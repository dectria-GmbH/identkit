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
  const access = new Map<
    string,
    { grantId: string; audience: string; expiresAt: Date; scopes?: string[] }
  >();
  const refresh = new Map<string, { grantId: string; generation: number; expiresAt: Date }>();
  const verifyAccessToken = vi.fn(async (token: string) => access.get(token) ?? null);
  const verifyRefreshToken = vi.fn(async (token: string) => refresh.get(token) ?? null);
  return { access, refresh, verifyAccessToken, verifyRefreshToken };
}

function importSetup(
  oauth: Partial<OAuthOptions> = {},
  store?: IdentkitStore,
  apiTokens?: { prefix: string; allowedScopes: string[] },
) {
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
    ...(apiTokens ? { apiTokens } : {}),
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

type ImportedGrant = Awaited<ReturnType<typeof importedGrant>>;

/** A public client and a grant of an earlier system, imported, with its legacy tokens. */
async function importedGrant(
  t: ReturnType<typeof importSetup>,
  overrides: Partial<ImportOAuthGrantInput> = {},
) {
  const accountId = await t.account();
  const clientInput = publicClient({ id: `c-${accountId}` });
  const client = await t.ik.oauth.importClient(clientInput);
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
  return {
    accountId,
    clientId: client.client.id,
    grantId: input.id,
    refreshToken,
    accessToken,
    input,
    clientInput,
  };
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

describe("oauth import after an end", () => {
  /**
   * Ends the imported grant one way, then runs the same import again: it answers `revoked`, and
   * the earlier legacy refresh token stays dead.
   */
  const ends: [
    string,
    (t: ReturnType<typeof importSetup>, g: ImportedGrant) => Promise<unknown>,
  ][] = [
    [
      "revokeGrant",
      (t, g) => t.ik.oauth.revokeGrant({ accountId: g.accountId, grantId: g.grantId }),
    ],
    ["revokeAll", (t, g) => t.ik.oauth.revokeAll(g.accountId)],
    [
      "revocation by the client",
      (t, g) =>
        t.ik.oauth.revoke({
          form: new URLSearchParams({ token: g.refreshToken, client_id: g.clientId }),
          authorization: null,
        }),
    ],
    [
      "refresh token reuse",
      async (t, g) => {
        t.legacy.refresh.set("older", {
          grantId: g.grantId,
          generation: 1,
          expiresAt: new Date(t.clock.now().getTime() + DAY),
        });
        await t.ik.oauth.token({ form: refreshForm(g.clientId, "older"), authorization: null });
      },
    ],
    [
      "expired legacy refresh token",
      async (t, g) => {
        t.legacy.refresh.set(g.refreshToken, {
          grantId: g.grantId,
          generation: g.input.generation,
          expiresAt: t.clock.now(),
        });
        await t.ik.oauth.token({
          form: refreshForm(g.clientId, g.refreshToken),
          authorization: null,
        });
      },
    ],
    [
      "account disable, then enabled again in the store",
      async (t, g) => {
        await t.ik.accounts.disable(g.accountId);
        await t.store.accounts.setStatus(g.accountId, "active");
      },
    ],
  ];
  for (const [name, end] of ends) {
    it(`a re-import after ${name} answers revoked`, async () => {
      const t = importSetup();
      const g = await importedGrant(t);
      await end(t, g);
      expect(await t.ik.oauth.listGrants(g.accountId)).toEqual([]);
      // Restore what the legacy verifier said at the import, as a re-run would find it.
      t.legacy.refresh.set(g.refreshToken, {
        grantId: g.grantId,
        generation: g.input.generation,
        expiresAt: g.input.refreshExpiresAt,
      });
      expect(await t.ik.oauth.importGrant(g.input)).toEqual({ status: "revoked" });
      expect(await t.ik.oauth.listGrants(g.accountId)).toEqual([]);
      const refreshed = await t.ik.oauth.token({
        form: refreshForm(g.clientId, g.refreshToken),
        authorization: null,
      });
      expect(refreshed.body).toMatchObject({ error: "invalid_grant" });
      expect(t.audit.ofType("oauth.grant_imported")).toHaveLength(1);
    });
  }

  it("a re-import after deleteClient answers revoked for the client and its grant", async () => {
    const t = importSetup();
    const g = await importedGrant(t);
    expect(await t.ik.oauth.deleteClient(g.clientId)).toBe(true);
    expect(await t.ik.oauth.importClient(g.clientInput)).toEqual({ status: "revoked" });
    expect(await t.ik.oauth.getClient(g.clientId)).toBeNull();
    expect(await t.ik.oauth.importGrant(g.input)).toEqual({ status: "revoked" });
    expect(t.audit.ofType("oauth.client_imported")).toHaveLength(1);
  });

  it("a re-import after purge answers revoked for the client", async () => {
    const t = importSetup();
    const accountId = await t.account();
    const input = publicClient({ id: `idle-${accountId}` });
    expect((await t.ik.oauth.importClient(input)).status).toBe("imported");
    // Never used: purged once it is older than unusedDays.
    t.clock.advanceSeconds(400 * 86_400);
    expect((await t.ik.oauth.purge()).clients).toBe(1);
    expect(await t.ik.oauth.importClient(input)).toEqual({ status: "revoked" });
  });

  it("a rolled-back import leaves no tombstone: the retry imports", async () => {
    const t = importSetup();
    const accountId = await t.account();
    const clientInput = publicClient({ id: `retry-${accountId}` });
    failSinkOnce(t.audit, "oauth.client_imported");
    await expect(t.ik.oauth.importClient(clientInput)).rejects.toBeInstanceOf(
      OAuthClientRolledBackError,
    );
    expect((await t.ik.oauth.importClient(clientInput)).status).toBe("imported");
    const now = t.clock.now().getTime();
    const grantInput: ImportOAuthGrantInput = {
      id: `retry-g-${accountId}`,
      accountId,
      clientId: clientInput.id,
      scopes: ["mcp:read"],
      resource: RESOURCE,
      createdAt: new Date(now - DAY),
      expiresAt: new Date(now + DAY),
      generation: 1,
      refreshExpiresAt: new Date(now + DAY),
      refreshSha256: sha256Hex("t"),
    };
    failSinkOnce(t.audit, "oauth.grant_imported");
    await expect(t.ik.oauth.importGrant(grantInput)).rejects.toBeInstanceOf(
      OperationRolledBackError,
    );
    expect(await t.ik.oauth.importGrant(grantInput)).toEqual({ status: "imported" });
  });

  it("a client rollback ends the grant that a concurrent import attached to it", async () => {
    const t = importSetup();
    const accountId = await t.account();
    const clientInput = publicClient({ id: `attached-${accountId}` });
    const now = t.clock.now().getTime();
    const grantInput: ImportOAuthGrantInput = {
      id: `attached-g-${accountId}`,
      accountId,
      clientId: clientInput.id,
      scopes: ["mcp:read"],
      resource: RESOURCE,
      createdAt: new Date(now - DAY),
      expiresAt: new Date(now + DAY),
      generation: 1,
      refreshExpiresAt: new Date(now + DAY),
      refreshSha256: sha256Hex("attached"),
    };
    // The sink is slow on the client's event: the grant import commits, then the sink refuses.
    const emit = t.audit.emit.bind(t.audit);
    t.audit.emit = async (event) => {
      if (event.type !== "oauth.client_imported") return emit(event);
      t.audit.emit = emit;
      expect(await t.ik.oauth.importGrant(grantInput)).toEqual({ status: "imported" });
      throw new Error("sink down");
    };
    await expect(t.ik.oauth.importClient(clientInput)).rejects.toBeInstanceOf(
      OAuthClientRolledBackError,
    );
    expect(await t.ik.oauth.listGrants(accountId)).toEqual([]);
    // The grant passed its own audit record, so its end is recorded too.
    expect(t.audit.ofType("oauth.grant_imported")).toHaveLength(1);
    const ended = t.audit.ofType("oauth.grant_ended");
    expect(ended).toHaveLength(1);
    expect(ended[0]).toMatchObject({
      accountId,
      clientId: clientInput.id,
      grantId: grantInput.id,
      reason: "client_deleted",
    });
    // The client import did not happen and may run again; the grant stays ended.
    expect((await t.ik.oauth.importClient(clientInput)).status).toBe("imported");
    expect(await t.ik.oauth.importGrant(grantInput)).toEqual({ status: "revoked" });
  });

  it("an end that races with the import's store write still answers revoked", async () => {
    // The store's import runs after a concurrent end wrote the tombstone: the store refuses.
    const inner = createMemoryStore();
    const oauth = inner.oauth;
    if (!oauth) throw new Error("no oauth");
    let beforeImport: (() => Promise<void>) | null = null;
    const store: IdentkitStore = {
      ...inner,
      oauth: {
        ...oauth,
        importGrant: async (grant, limit) => {
          const hook = beforeImport;
          beforeImport = null;
          await hook?.();
          return oauth.importGrant(grant, limit);
        },
      },
    };
    const t = importSetup({}, store);
    const g = await importedGrant(t);
    // Frees the account's slot of this client for the second grant id.
    await t.ik.oauth.revokeGrant({ accountId: g.accountId, grantId: g.grantId });
    // A second grant id, imported and ended by another call after the import's own reads found
    // nothing, right before its store write.
    const fresh: ImportOAuthGrantInput = { ...g.input, id: `${g.input.id}-2` };
    beforeImport = async () => {
      await oauth.importGrant(
        {
          id: fresh.id,
          accountId: fresh.accountId,
          clientId: fresh.clientId,
          scopes: fresh.scopes,
          resource: fresh.resource,
          createdAt: fresh.createdAt,
          expiresAt: fresh.expiresAt,
          generation: fresh.generation,
          refreshRefDigest: null,
          refreshDigest: fresh.refreshSha256,
          refreshDigestAlgorithm: "sha256",
          previousRefreshDigest: null,
          refreshedAt: null,
          refreshExpiresAt: fresh.refreshExpiresAt,
          codeDigest: null,
          source: "import",
        },
        { maxOtherGrants: 10, at: t.clock.now() },
      );
      await oauth.deleteGrant(fresh.id, { accountId: fresh.accountId }, t.clock.now());
    };
    expect(await t.ik.oauth.importGrant(fresh)).toEqual({ status: "revoked" });
    expect(await t.ik.oauth.listGrants(g.accountId)).toEqual([]);
  });

  it("a client import that races with a concurrent import and delete answers revoked", async () => {
    // Another call imports the client and deletes it between this call's read and its insert.
    const inner = createMemoryStore();
    const oauth = inner.oauth;
    if (!oauth) throw new Error("no oauth");
    let beforeInsert: (() => Promise<void>) | null = null;
    const store: IdentkitStore = {
      ...inner,
      oauth: {
        ...oauth,
        insertClient: async (client) => {
          const hook = beforeInsert;
          beforeInsert = null;
          if (!hook) return oauth.insertClient(client);
          await hook();
          // The insert of the other call won; this one met its row.
          return "id_taken";
        },
      },
    };
    const t = importSetup({}, store);
    const input = publicClient({ id: "raced-client" });
    beforeInsert = async () => {
      expect((await t.ik.oauth.importClient(input)).status).toBe("imported");
      expect(await t.ik.oauth.deleteClient(input.id)).toBe(true);
    };
    expect(await t.ik.oauth.importClient(input)).toEqual({ status: "revoked" });
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

  it("refuses an audience other than the grant's resource, also a configured one", async () => {
    const t = importSetup();
    const g = await importedGrant(t);
    // ISSUER is the second configured resource; the grant was imported for RESOURCE.
    t.legacy.access.set("second-resource", {
      grantId: g.grantId,
      audience: ISSUER,
      expiresAt: new Date(t.clock.now().getTime() + 1000),
    });
    expect(await t.ik.oauth.validateAccessToken("second-resource")).toEqual({
      status: "refused",
      reason: "wrong_resource",
    });
    expect(await t.ik.oauth.validateAccessToken("second-resource", { resource: ISSUER })).toEqual({
      status: "refused",
      reason: "wrong_resource",
    });
    // The control: the grant's own resource passes.
    expect(
      (await t.ik.oauth.validateAccessToken(g.accessToken, { resource: RESOURCE })).status,
    ).toBe("valid");
  });

  it("never shows a verifier a token with the API token prefix", async () => {
    const t = importSetup({}, undefined, { prefix: "pat_", allowedScopes: ["read"] });
    const g = await importedGrant(t);
    const apiToken = `pat_${"A".repeat(43)}`;
    expect(await t.ik.oauth.validateAccessToken(apiToken)).toEqual({
      status: "refused",
      reason: "malformed",
    });
    await t.ik.oauth.revoke({
      form: new URLSearchParams({ token: apiToken, client_id: g.clientId }),
      authorization: null,
    });
    const refreshed = await t.ik.oauth.token({
      form: refreshForm(g.clientId, `pat_${"B".repeat(43)}`),
      authorization: null,
    });
    expect(refreshed.body).toMatchObject({ error: "invalid_grant" });
    expect(t.legacy.verifyAccessToken).not.toHaveBeenCalled();
    expect(t.legacy.verifyRefreshToken).not.toHaveBeenCalled();
    // The control: a token without any identkit prefix reaches the verifier.
    await t.ik.oauth.validateAccessToken("legacy-unknown");
    expect(t.legacy.verifyAccessToken).toHaveBeenCalledWith("legacy-unknown");
  });

  it("narrows the scopes to those the legacy token names, never wider", async () => {
    const t = importSetup();
    const g = await importedGrant(t, { scopes: ["mcp:read", "mcp:events"] });
    const expiresAt = new Date(t.clock.now().getTime() + 1000);
    const validate = async (scopes: string[]) => {
      t.legacy.access.set("narrowed", {
        grantId: g.grantId,
        audience: RESOURCE,
        expiresAt,
        scopes,
      });
      return t.ik.oauth.validateAccessToken("narrowed");
    };
    expect(await validate(["mcp:events"])).toMatchObject({
      status: "valid",
      scopes: ["mcp:events"],
    });
    // A scope beyond the grant is dropped.
    expect(await validate(["mcp:read", "admin"])).toMatchObject({
      status: "valid",
      scopes: ["mcp:read"],
    });
    expect(await validate(["admin"])).toEqual({ status: "refused", reason: "no_allowed_scope" });
    expect(await validate([])).toEqual({ status: "refused", reason: "no_allowed_scope" });
    // Without scopes the token carries the grant's.
    expect(await t.ik.oauth.validateAccessToken(g.accessToken)).toMatchObject({
      scopes: ["mcp:read", "mcp:events"],
    });
  });

  it("fails closed when the verifier throws or returns another shape", async () => {
    const t = importSetup();
    t.legacy.verifyAccessToken.mockRejectedValueOnce(new Error("key fetch failed"));
    await expect(t.ik.oauth.validateAccessToken("legacy-x")).rejects.toThrow("key fetch failed");
    for (const shape of [
      undefined,
      {},
      { grantId: "g", audience: RESOURCE, expiresAt: "soon" },
      { grantId: "g", audience: RESOURCE, expiresAt: new Date(), scopes: "mcp:read" },
      { grantId: "g", audience: RESOURCE, expiresAt: new Date(), scopes: [1] },
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

  it("ends the grant for a token one generation below whose digest is not the previous one", async () => {
    const t = importSetup();
    const g = await importedGrant(t);
    // A legacy rotation: the grant is at generation 4 now, its previous digest the legacy token's.
    const rotated = await t.ik.oauth.token({
      form: refreshForm(g.clientId, g.refreshToken),
      authorization: null,
    });
    expect(rotated.httpStatus).toBe(200);
    t.clock.advanceSeconds(5);
    // Within the grace, generation 3 as the previous token, but another token: a copy of an
    // earlier generation 3 token cannot be the one just rotated.
    t.legacy.refresh.set("other-gen-3", {
      grantId: g.grantId,
      generation: 3,
      expiresAt: new Date(t.clock.now().getTime() + DAY),
    });
    const result = await t.ik.oauth.token({
      form: refreshForm(g.clientId, "other-gen-3"),
      authorization: null,
    });
    expect(result.body).toMatchObject({ error: "invalid_grant" });
    expect(await t.ik.oauth.listGrants(g.accountId)).toEqual([]);
    expect(t.audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual(["refresh_reuse"]);
    // The control: the token just rotated, within the grace, keeps the grant.
    const h = await importedGrant(t);
    await t.ik.oauth.token({ form: refreshForm(h.clientId, h.refreshToken), authorization: null });
    t.clock.advanceSeconds(5);
    const raced = await t.ik.oauth.token({
      form: refreshForm(h.clientId, h.refreshToken),
      authorization: null,
    });
    expect(raced.body).toMatchObject({ error: "invalid_grant" });
    expect(await t.ik.oauth.listGrants(h.accountId)).toHaveLength(1);
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
