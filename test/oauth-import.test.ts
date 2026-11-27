import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  InvalidArgumentError,
  NotConfiguredError,
  OAuthClientRolledBackError,
  OperationRolledBackError,
  createMemoryStore,
  type IdentkitStore,
  type ImportOAuthClientInput,
  type ImportOAuthGrantInput,
  type OAuthOptions,
} from "../src/index.js";
import { createOAuthTestClient, type RecordingAuditSink } from "../src/testing/index.js";
import { ISSUER, oauthSetup, RESOURCE } from "./oauth-helpers.js";

const DAY = 86_400_000;
const REFRESH = /^ikrt_[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;
const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");
const encode = (value: string) => encodeURIComponent(value).replace(/%20/g, "+");
const basic = (id: string, secret: string) => `Basic ${btoa(`${encode(id)}:${encode(secret)}`)}`;

/** Makes the audit sink throw once, on the next event of `type`. */
function failSinkOnce(audit: RecordingAuditSink, type: string) {
  const emit = audit.emit.bind(audit);
  audit.emit = (event) => {
    if (event.type !== type) return emit(event);
    audit.emit = emit;
    throw new Error("sink down");
  };
}

/** Legacy tokens of an earlier system: a table of token -> what its verifier returns. */
function legacySystem() {
  const access = new Map<string, { grantId: string; audience: string; expiresAt: Date }>();
  const refresh = new Map<string, { grantId: string; generation: number; expiresAt: Date }>();
  const verifyAccessToken = vi.fn(async (token: string) => access.get(token) ?? null);
  const verifyRefreshToken = vi.fn(async (token: string) => refresh.get(token) ?? null);
  return { access, refresh, verifyAccessToken, verifyRefreshToken };
}

function importSetup(oauth: Partial<OAuthOptions> = {}, store?: IdentkitStore) {
  const legacy = legacySystem();
  const setup = oauthSetup({
    oauth: {
      acceptLegacyClientSecrets: true,
      legacy: {
        verifyAccessToken: legacy.verifyAccessToken,
        verifyRefreshToken: legacy.verifyRefreshToken,
      },
      ...oauth,
    },
    ...(store ? { store } : {}),
  });
  return { ...setup, legacy };
}

const publicClient = (overrides: Partial<ImportOAuthClientInput> = {}): ImportOAuthClientInput => ({
  id: "legacy-client-1",
  name: "Legacy client",
  redirectUris: ["http://127.0.0.1/callback"],
  grantTypes: ["authorization_code", "refresh_token"],
  authMethod: "none",
  ...overrides,
});

/** A public client and a grant of an earlier system, imported, with its legacy tokens. */
async function importedGrant(
  t: ReturnType<typeof importSetup>,
  overrides: Partial<ImportOAuthGrantInput> = {},
) {
  const accountId = await t.account();
  const client = await t.ik.oauth.importClient(publicClient({ id: `c-${accountId}` }));
  if (client.status !== "imported") throw new Error(client.status);
  const now = t.clock.now().getTime();
  const refreshToken = `legacy-refresh-${accountId}-3`;
  const input: ImportOAuthGrantInput = {
    id: `g-${accountId}`,
    accountId,
    clientId: client.client.id,
    scopes: ["mcp:read"],
    resource: RESOURCE,
    createdAt: new Date(now - 10 * DAY),
    expiresAt: new Date(now + 80 * DAY),
    generation: 3,
    refreshedAt: new Date(now - DAY),
    refreshExpiresAt: new Date(now + 29 * DAY),
    refreshSha256: sha256Hex(refreshToken),
    ...overrides,
  };
  const result = await t.ik.oauth.importGrant(input);
  if (result.status !== "imported") throw new Error(result.status);
  t.legacy.refresh.set(refreshToken, {
    grantId: input.id,
    generation: input.generation,
    expiresAt: input.refreshExpiresAt,
  });
  const accessToken = `legacy-access-${accountId}`;
  t.legacy.access.set(accessToken, {
    grantId: input.id,
    audience: RESOURCE,
    expiresAt: new Date(now + 3_600_000),
  });
  return { accountId, clientId: client.client.id, grantId: input.id, refreshToken, accessToken };
}

const refreshForm = (clientId: string, refreshToken: string) =>
  new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: clientId,
  });

describe("oauth importClient", () => {
  it("imports a public client and answers already_imported or id_taken on a second import", async () => {
    const { ik, audit } = importSetup();
    const first = await ik.oauth.importClient(publicClient());
    expect(first).toMatchObject({
      status: "imported",
      client: { id: "legacy-client-1", source: "import", authMethod: "none", legacyDigest: false },
    });
    expect(await ik.oauth.importClient(publicClient())).toMatchObject({
      status: "already_imported",
    });
    expect(await ik.oauth.importClient(publicClient({ name: "Other" }))).toEqual({
      status: "id_taken",
    });
    expect(audit.ofType("oauth.client_imported")).toEqual([
      expect.objectContaining({ clientId: "legacy-client-1", method: "none", reason: "none" }),
    ]);
  });

  it("stores a plaintext secret keyed and authenticates with it", async () => {
    const { ik, audit } = importSetup();
    const input = publicClient({ authMethod: "client_secret_basic", secret: "s3cret value" });
    expect((await ik.oauth.importClient(input)).status).toBe("imported");
    expect(await ik.oauth.importClient(input)).toMatchObject({ status: "already_imported" });
    expect(await ik.oauth.importClient({ ...input, secret: "another secret" })).toEqual({
      status: "id_taken",
    });
    const form = new URLSearchParams({ grant_type: "refresh_token", refresh_token: "x" });
    const ok = await ik.oauth.token({ form, authorization: basic(input.id, "s3cret value") });
    expect(ok.body).toMatchObject({ error: "invalid_grant" });
    const bad = await ik.oauth.token({ form, authorization: basic(input.id, "wrong") });
    expect(bad.httpStatus).toBe(401);
    expect(audit.ofType("oauth.client_imported")[0]).toMatchObject({
      method: "client_secret_basic",
      reason: "hmac-sha256",
    });
  });

  it("refuses malformed input", async () => {
    const { ik, clock } = importSetup();
    const invalid: Partial<ImportOAuthClientInput>[] = [
      { id: "" },
      { id: "has space" },
      { id: "x".repeat(129) },
      { redirectUris: [] },
      { redirectUris: ["https://example.com#x"] },
      { redirectUris: ["http://127.0.0.1/callback", "http://127.0.0.1/callback"] },
      { grantTypes: ["refresh_token"] },
      { grantTypes: ["authorization_code", "client_credentials"] },
      { authMethod: "private_key_jwt" as never },
      { secret: "a public client has none" },
      { authMethod: "client_secret_post" },
      { authMethod: "client_secret_post", secret: "a", secretSha256: sha256Hex("a") },
      { authMethod: "client_secret_post", secret: "x".repeat(513) },
      { authMethod: "client_secret_post", secretSha256: "abc" },
      { createdAt: new Date(clock.now().getTime() + 1) },
      { lastUsedAt: new Date(clock.now().getTime() + 1) },
      {
        createdAt: new Date(clock.now().getTime() - 2000),
        lastUsedAt: new Date(clock.now().getTime() - 2001),
      },
    ];
    for (const overrides of invalid) {
      await expect(
        ik.oauth.importClient(publicClient(overrides)),
        JSON.stringify(overrides),
      ).rejects.toBeInstanceOf(InvalidArgumentError);
    }
    expect(await ik.oauth.getClient("legacy-client-1")).toBeNull();
  });

  it("needs acceptLegacyClientSecrets for a SHA-256 secret", async () => {
    const { ik } = importSetup({ acceptLegacyClientSecrets: false });
    await expect(
      ik.oauth.importClient(
        publicClient({ authMethod: "client_secret_post", secretSha256: sha256Hex("secret") }),
      ),
    ).rejects.toBeInstanceOf(NotConfiguredError);
  });

  it("rolls the client back when the sink refuses its event", async () => {
    const { ik, audit } = importSetup();
    failSinkOnce(audit, "oauth.client_imported");
    const error = await ik.oauth.importClient(publicClient()).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(OAuthClientRolledBackError);
    expect(error).toMatchObject({ clientId: "legacy-client-1" });
    expect(await ik.oauth.getClient("legacy-client-1")).toBeNull();
  });
});

const legacyInput = () =>
  publicClient({ authMethod: "client_secret_post", secretSha256: sha256Hex("old secret") });
/** A refresh with a junk token: an authenticated client gets invalid_grant, others 401. */
const form = (clientId: string, secret: string) =>
  new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: "x",
    client_id: clientId,
    client_secret: secret,
  });

describe("oauth legacy client secrets", () => {
  it("authenticates a SHA-256 secret and upgrades it to the keyed digest on first use", async () => {
    const { ik, store } = importSetup();
    const input = legacyInput();
    expect((await ik.oauth.importClient(input)).status).toBe("imported");
    expect((await ik.oauth.getClient(input.id))?.legacyDigest).toBe(true);
    const wrong = await ik.oauth.token({ form: form(input.id, "wrong"), authorization: null });
    expect(wrong.httpStatus).toBe(401);
    expect((await ik.oauth.getClient(input.id))?.legacyDigest).toBe(true);
    const ok = await ik.oauth.token({ form: form(input.id, "old secret"), authorization: null });
    expect(ok.body).toMatchObject({ error: "invalid_grant" });
    const stored = await store.oauth?.findClient(input.id);
    expect(stored?.secretDigestAlgorithm).toBe("hmac-sha256");
    expect(stored?.secretDigest).not.toBe(sha256Hex("old secret"));
    // The keyed digest authenticates from now on; the old SHA-256 digest is gone.
    const again = await ik.oauth.token({ form: form(input.id, "old secret"), authorization: null });
    expect(again.body).toMatchObject({ error: "invalid_grant" });
    // After the upgrade, a re-import by SHA-256 cannot prove the same secret; the plaintext can.
    expect(await ik.oauth.importClient(input)).toEqual({ status: "id_taken" });
    const { secretSha256: _, ...withoutDigest } = input;
    expect(await ik.oauth.importClient({ ...withoutDigest, secret: "old secret" })).toMatchObject({
      status: "already_imported",
    });
  });

  it("refuses a SHA-256 secret when acceptLegacyClientSecrets is off", async () => {
    const first = importSetup();
    await first.ik.oauth.importClient(legacyInput());
    const off = importSetup({ acceptLegacyClientSecrets: false }, first.store);
    const result = await off.ik.oauth.token({
      form: form("legacy-client-1", "old secret"),
      authorization: null,
    });
    expect(result.httpStatus).toBe(401);
    expect((await first.store.oauth?.findClient("legacy-client-1"))?.secretDigestAlgorithm).toBe(
      "sha256",
    );
  });

  it("keeps the authentication when the upgrade write fails, reports it, and upgrades later", async () => {
    const inner = createMemoryStore();
    const oauth = inner.oauth;
    if (!oauth) throw new Error("the memory store has oauth");
    let failUpgrade = true;
    const store: IdentkitStore = {
      ...inner,
      oauth: {
        ...oauth,
        upgradeClientSecret: async (...args) => {
          if (failUpgrade) throw new Error("db blip");
          return oauth.upgradeClientSecret(...args);
        },
      },
    };
    const reports: unknown[] = [];
    const { ik } = importSetup(
      { onStoreError: (error, write) => void reports.push({ error, write }) },
      store,
    );
    await ik.oauth.importClient(legacyInput());
    const ok = await ik.oauth.token({
      form: form("legacy-client-1", "old secret"),
      authorization: null,
    });
    expect(ok.body).toMatchObject({ error: "invalid_grant" });
    expect(reports).toEqual([
      {
        error: new Error("db blip"),
        write: { kind: "client_secret_upgrade", clientId: "legacy-client-1" },
      },
    ]);
    failUpgrade = false;
    await ik.oauth.token({ form: form("legacy-client-1", "old secret"), authorization: null });
    expect((await inner.oauth?.findClient("legacy-client-1"))?.secretDigestAlgorithm).toBe(
      "hmac-sha256",
    );
  });

  it("upgrades with a compare-and-set: two parallel first uses both authenticate", async () => {
    const { ik, store } = importSetup();
    await ik.oauth.importClient(legacyInput());
    const results = await Promise.all(
      [1, 2].map(() =>
        ik.oauth.token({ form: form("legacy-client-1", "old secret"), authorization: null }),
      ),
    );
    expect(results.map((r) => r.httpStatus)).toEqual([400, 400]);
    expect((await store.oauth?.findClient("legacy-client-1"))?.secretDigestAlgorithm).toBe(
      "hmac-sha256",
    );
  });
});

describe("oauth importGrant", () => {
  it("imports a grant and answers every other state without a change", async () => {
    const t = importSetup({ maxGrantsPerAccount: 1 });
    const { accountId, clientId, grantId } = await importedGrant(t);
    expect(t.audit.ofType("oauth.grant_imported")).toEqual([
      expect.objectContaining({
        accountId,
        clientId,
        grantId,
        scopes: ["mcp:read"],
        method: "sha256",
      }),
    ]);
    expect(await t.ik.oauth.listGrants(accountId)).toEqual([
      expect.objectContaining({ id: grantId, source: "import", resource: RESOURCE }),
    ]);
    const now = t.clock.now().getTime();
    const base: ImportOAuthGrantInput = {
      id: grantId,
      accountId,
      clientId,
      scopes: ["mcp:read"],
      resource: RESOURCE,
      createdAt: new Date(now - DAY),
      expiresAt: new Date(now + DAY),
      generation: 1,
      refreshExpiresAt: new Date(now + DAY),
      refreshSha256: sha256Hex("other"),
    };
    expect(await t.ik.oauth.importGrant(base)).toEqual({ status: "already_imported" });
    expect(await t.ik.oauth.importGrant({ ...base, scopes: ["mcp:read", "mcp:events"] })).toEqual({
      status: "id_taken",
    });
    expect(await t.ik.oauth.importGrant({ ...base, id: "g-other" })).toEqual({
      status: "account_client_taken",
    });
    const other = await t.ik.oauth.importClient(publicClient({ id: "c-other" }));
    if (other.status !== "imported") throw new Error(other.status);
    expect(await t.ik.oauth.importGrant({ ...base, id: "g-other", clientId: "c-other" })).toEqual({
      status: "limit_reached",
    });
    expect(await t.ik.oauth.importGrant({ ...base, id: "g-x", clientId: "missing" })).toEqual({
      status: "no_client",
    });
    expect(await t.ik.oauth.importGrant({ ...base, id: "g-x", accountId: "missing" })).toEqual({
      status: "no_account",
    });
    const fresh = await t.account();
    expect(
      await t.ik.oauth.importGrant({
        ...base,
        id: "g-x",
        accountId: fresh,
        clientId: "c-other",
        createdAt: new Date(now - 3 * DAY),
        expiresAt: new Date(now),
        refreshExpiresAt: new Date(now),
      }),
    ).toEqual({ status: "expired" });
    await t.ik.accounts.disable(fresh);
    expect(
      await t.ik.oauth.importGrant({ ...base, id: "g-x", accountId: fresh, clientId: "c-other" }),
    ).toEqual({ status: "account_disabled" });
    expect(t.audit.ofType("oauth.grant_imported")).toHaveLength(1);
  });

  it("refuses malformed input", async () => {
    const t = importSetup();
    const accountId = await t.account();
    await t.ik.oauth.importClient(publicClient());
    const now = t.clock.now().getTime();
    const base: ImportOAuthGrantInput = {
      id: "g-1",
      accountId,
      clientId: "legacy-client-1",
      scopes: ["mcp:read"],
      resource: RESOURCE,
      createdAt: new Date(now - DAY),
      expiresAt: new Date(now + DAY),
      generation: 1,
      refreshExpiresAt: new Date(now + DAY),
      refreshSha256: sha256Hex("t"),
    };
    const invalid: Partial<ImportOAuthGrantInput>[] = [
      { id: "has space" },
      { scopes: [] },
      { scopes: ["admin"] },
      { scopes: ["mcp:read", "mcp:read"] },
      { resource: "https://other.example" },
      { generation: 0 },
      { generation: 1.5 },
      { createdAt: new Date(now + DAY) },
      { expiresAt: new Date(now - 2 * DAY) },
      { refreshExpiresAt: new Date(now + 2 * DAY) },
      { refreshedAt: new Date(now - 2 * DAY) },
      { refreshedAt: new Date(now + 1000) },
      { refreshSha256: "not hex" },
      { expiresAt: new Date(Number.NaN) },
    ];
    for (const overrides of invalid) {
      await expect(
        t.ik.oauth.importGrant({ ...base, ...overrides }),
        JSON.stringify(overrides),
      ).rejects.toBeInstanceOf(InvalidArgumentError);
    }
    expect(await t.ik.oauth.listGrants(accountId)).toEqual([]);
  });

  it("rolls the grant back when the sink refuses its event", async () => {
    const t = importSetup();
    const accountId = await t.account();
    await t.ik.oauth.importClient(publicClient());
    failSinkOnce(t.audit, "oauth.grant_imported");
    const now = t.clock.now().getTime();
    const error = await t.ik.oauth
      .importGrant({
        id: "g-1",
        accountId,
        clientId: "legacy-client-1",
        scopes: ["mcp:read"],
        resource: RESOURCE,
        createdAt: new Date(now - DAY),
        expiresAt: new Date(now + DAY),
        generation: 1,
        refreshExpiresAt: new Date(now + DAY),
        refreshSha256: sha256Hex("t"),
      })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(OperationRolledBackError);
    expect(error).toMatchObject({ accountId, hookFailed: false });
    expect(await t.ik.oauth.listGrants(accountId)).toEqual([]);
  });
});

describe("oauth legacy access tokens", () => {
  it("validates a legacy token of an imported grant, with the grant's account and scopes", async () => {
    const t = importSetup();
    const g = await importedGrant(t);
    expect(await t.ik.oauth.validateAccessToken(g.accessToken)).toEqual({
      status: "valid",
      accountId: g.accountId,
      clientId: g.clientId,
      grantId: g.grantId,
      scopes: ["mcp:read"],
      resource: RESOURCE,
      expiresAt: new Date(t.clock.now().getTime() + 3_600_000),
    });
    expect(await t.ik.oauth.validateAccessToken(g.accessToken, { resource: ISSUER })).toMatchObject(
      { reason: "wrong_resource" },
    );
    expect(t.legacy.verifyAccessToken).toHaveBeenCalledWith(g.accessToken);
  });

  it("refuses what the grant, the account or the audience do not allow", async () => {
    const t = importSetup();
    const g = await importedGrant(t);
    const now = t.clock.now().getTime();
    const refusal = async (token: string) => t.ik.oauth.validateAccessToken(token);
    expect(await refusal("unknown-legacy")).toEqual({ status: "refused", reason: "unknown" });
    t.legacy.access.set("expired", {
      grantId: g.grantId,
      audience: RESOURCE,
      expiresAt: new Date(now),
    });
    expect(await refusal("expired")).toMatchObject({ reason: "expired" });
    t.legacy.access.set("no-grant", {
      grantId: "missing",
      audience: RESOURCE,
      expiresAt: new Date(now + 1000),
    });
    expect(await refusal("no-grant")).toMatchObject({ reason: "unknown" });
    t.legacy.access.set("other-aud", {
      grantId: g.grantId,
      audience: "https://other.example",
      expiresAt: new Date(now + 1000),
    });
    expect(await refusal("other-aud")).toMatchObject({ reason: "wrong_resource" });
    // A legacy token never reaches a grant that identkit created.
    const client = await createOAuthTestClient(t.ik.oauth);
    const own = await t.account();
    await client.connect(own);
    const [created] = await t.ik.oauth.listGrants(own);
    t.legacy.access.set("names-created", {
      grantId: created?.id ?? "",
      audience: RESOURCE,
      expiresAt: new Date(now + 1000),
    });
    expect(await refusal("names-created")).toMatchObject({ reason: "unknown" });
    await t.ik.accounts.disable(g.accountId);
    // accounts.disable ends the imported grant too.
    expect(await refusal(g.accessToken)).toMatchObject({ reason: "unknown" });
  });

  it("fails closed when the verifier throws or returns another shape", async () => {
    const t = importSetup();
    t.legacy.verifyAccessToken.mockRejectedValueOnce(new Error("key fetch failed"));
    await expect(t.ik.oauth.validateAccessToken("legacy-x")).rejects.toThrow("key fetch failed");
    for (const shape of [
      undefined,
      {},
      { grantId: "g", audience: RESOURCE, expiresAt: "soon" },
      true,
    ]) {
      t.legacy.verifyAccessToken.mockResolvedValueOnce(shape as never);
      await expect(
        t.ik.oauth.validateAccessToken("legacy-x"),
        JSON.stringify(shape),
      ).rejects.toThrow(/^oauth\.legacy\.verifyAccessToken must return/);
    }
  });
});

describe("oauth legacy refresh tokens", () => {
  it("rotates the current legacy token into an identkit token; the grant gets its ref", async () => {
    const t = importSetup();
    const g = await importedGrant(t);
    const result = await t.ik.oauth.token({
      form: refreshForm(g.clientId, g.refreshToken),
      authorization: null,
    });
    expect(result.httpStatus).toBe(200);
    const refreshToken = String(result.body?.["refresh_token"]);
    expect(refreshToken).toMatch(REFRESH);
    expect(
      (await t.ik.oauth.validateAccessToken(String(result.body?.["access_token"]))).status,
    ).toBe("valid");
    const lookup = await t.store.oauth?.findGrant(g.grantId);
    expect(lookup?.grant).toMatchObject({
      generation: 4,
      refreshDigestAlgorithm: "hmac-sha256",
      previousRefreshDigest: sha256Hex(g.refreshToken),
    });
    expect(lookup?.grant.refreshRefDigest).not.toBeNull();
    // The new identkit token refreshes as any other.
    const next = await t.ik.oauth.token({
      form: refreshForm(g.clientId, refreshToken),
      authorization: null,
    });
    expect(next.httpStatus).toBe(200);
    expect(t.audit.ofType("oauth.token_refreshed")).toHaveLength(2);
  });

  it("grace for the legacy token just rotated; after the grace, or an older generation, the grant ends", async () => {
    const t = importSetup();
    const g = await importedGrant(t);
    expect(
      (
        await t.ik.oauth.token({
          form: refreshForm(g.clientId, g.refreshToken),
          authorization: null,
        })
      ).httpStatus,
    ).toBe(200);
    t.clock.advanceSeconds(10);
    const raced = await t.ik.oauth.token({
      form: refreshForm(g.clientId, g.refreshToken),
      authorization: null,
    });
    expect(raced.body).toMatchObject({ error: "invalid_grant" });
    expect(await t.ik.oauth.listGrants(g.accountId)).toHaveLength(1);
    t.clock.advanceSeconds(30);
    await t.ik.oauth.token({ form: refreshForm(g.clientId, g.refreshToken), authorization: null });
    expect(await t.ik.oauth.listGrants(g.accountId)).toEqual([]);
    expect(t.audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual(["refresh_reuse"]);

    const h = await importedGrant(t);
    t.legacy.refresh.set("older", {
      grantId: h.grantId,
      generation: 1,
      expiresAt: new Date(t.clock.now().getTime() + DAY),
    });
    await t.ik.oauth.token({ form: refreshForm(h.clientId, "older"), authorization: null });
    expect(await t.ik.oauth.listGrants(h.accountId)).toEqual([]);
  });

  it("a legacy token one generation below, within the grace of the import's last rotation, keeps the grant", async () => {
    const t = importSetup();
    // The import was written right after the earlier system rotated (refreshedAt now).
    const h = await importedGrant(t, { refreshedAt: t.clock.now() });
    t.legacy.refresh.set("gen-2", {
      grantId: h.grantId,
      generation: 2,
      expiresAt: new Date(t.clock.now().getTime() + DAY),
    });
    const raced = await t.ik.oauth.token({
      form: refreshForm(h.clientId, "gen-2"),
      authorization: null,
    });
    expect(raced.body).toMatchObject({ error: "invalid_grant" });
    expect(await t.ik.oauth.listGrants(h.accountId)).toHaveLength(1);
  });

  it("fails closed when the refresh verifier throws or returns another shape", async () => {
    const t = importSetup();
    const g = await importedGrant(t);
    const call = () =>
      t.ik.oauth.token({ form: refreshForm(g.clientId, g.refreshToken), authorization: null });
    t.legacy.verifyRefreshToken.mockRejectedValueOnce(new Error("key fetch failed"));
    await expect(call()).rejects.toThrow("key fetch failed");
    const shapes = [
      undefined,
      { grantId: g.grantId, generation: 0, expiresAt: new Date() },
      { grantId: g.grantId, generation: "3", expiresAt: new Date() },
      { grantId: "", generation: 3, expiresAt: new Date() },
      { grantId: g.grantId, generation: 3, expiresAt: new Date(Number.NaN) },
    ];
    for (const shape of shapes) {
      t.legacy.verifyRefreshToken.mockResolvedValueOnce(shape as never);
      await expect(call(), JSON.stringify(shape)).rejects.toThrow(
        /^oauth\.legacy\.verifyRefreshToken must return/,
      );
    }
    expect(await t.ik.oauth.listGrants(g.accountId)).toHaveLength(1);
  });

  it("does not take a token as current when the verifier's generation disagrees with the grant", async () => {
    const t = importSetup();
    const g = await importedGrant(t);
    t.legacy.refresh.set(g.refreshToken, {
      grantId: g.grantId,
      generation: 4,
      expiresAt: new Date(t.clock.now().getTime() + DAY),
    });
    const result = await t.ik.oauth.token({
      form: refreshForm(g.clientId, g.refreshToken),
      authorization: null,
    });
    expect(result.body).toMatchObject({ error: "invalid_grant" });
    expect(t.audit.ofType("oauth.token_refreshed")).toEqual([]);
  });

  it("ends the grant when the verifier says the legacy token expired", async () => {
    const t = importSetup();
    const g = await importedGrant(t);
    t.legacy.refresh.set(g.refreshToken, {
      grantId: g.grantId,
      generation: 3,
      expiresAt: t.clock.now(),
    });
    const result = await t.ik.oauth.token({
      form: refreshForm(g.clientId, g.refreshToken),
      authorization: null,
    });
    expect(result.body).toMatchObject({ error: "invalid_grant" });
    expect(t.audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual(["expired"]);
  });

  it("revokes the grant of a legacy refresh or access token of the calling client", async () => {
    const t = importSetup();
    const g = await importedGrant(t);
    const h = await importedGrant(t);
    const revoke = (clientId: string, token: string) =>
      t.ik.oauth.revoke({
        form: new URLSearchParams({ token, client_id: clientId }),
        authorization: null,
      });
    // Another client's token ends nothing.
    expect((await revoke(h.clientId, g.refreshToken)).httpStatus).toBe(200);
    expect(await t.ik.oauth.listGrants(g.accountId)).toHaveLength(1);
    expect((await revoke(g.clientId, g.refreshToken)).httpStatus).toBe(200);
    expect(await t.ik.oauth.listGrants(g.accountId)).toEqual([]);
    expect((await revoke(h.clientId, h.accessToken)).httpStatus).toBe(200);
    expect(await t.ik.oauth.listGrants(h.accountId)).toEqual([]);
    expect(t.audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual([
      "revoked_by_client",
      "revoked_by_client",
    ]);
  });
});
