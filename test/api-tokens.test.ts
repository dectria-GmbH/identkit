import { createHash, createHmac, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createHmacHasher,
  createIdentkit,
  createMemoryStore,
  InvalidArgumentError,
  NotConfiguredError,
  OperationRolledBackError,
  parseBearerToken,
  type ApiTokenOptions,
  type AuditEvent,
  type IdentkitStore,
} from "../src/index.js";
import {
  createFakeClock,
  createRecordingAuditSink,
  createRecordingMailSender,
  createTestSealer,
} from "../src/testing/index.js";
import { emailFirstPolicy, setup, testConfig } from "./helpers.js";

const DAY = 86_400;
const TOKEN = /^pat_[A-Za-z0-9_-]{43}$/;
const baseOptions: ApiTokenOptions = {
  prefix: "pat_",
  allowedScopes: ["read:items", "write:items", "admin"],
};

interface TokenSetupOptions {
  apiTokens?: ApiTokenOptions;
  store?: IdentkitStore;
  hashKey?: Uint8Array;
  onAllSessionsRevoked?: () => void;
}

/** identkit with API tokens over a memory store, with a known hash key. */
function tokenSetup(options: TokenSetupOptions = {}) {
  const store = options.store ?? createMemoryStore();
  const hashKey = options.hashKey ?? new Uint8Array(randomBytes(32));
  const clock = createFakeClock();
  const audit = createRecordingAuditSink();
  const mail = createRecordingMailSender();
  const build = (apiTokens: ApiTokenOptions | undefined) =>
    createIdentkit({
      config: testConfig,
      policy: emailFirstPolicy,
      isPrivilegedAccount: () => false,
      store,
      hasher: createHmacHasher(new Uint8Array(hashKey)),
      sealer: createTestSealer(),
      mail,
      audit,
      clock,
      ...(apiTokens ? { apiTokens } : {}),
      ...(options.onAllSessionsRevoked
        ? { onAllSessionsRevoked: options.onAllSessionsRevoked }
        : {}),
    });
  const ik = build(options.apiTokens ?? baseOptions);
  async function account(email = `p-${Math.random().toString(36).slice(2)}@example.org`) {
    const created = await ik.accounts.create({ email });
    if (created.status !== "created") throw new Error(created.status);
    return created.account.id;
  }
  async function token(
    accountId: string,
    input: { scopes?: string[]; expiresInDays?: number; name?: string } = {},
  ) {
    const created = await ik.apiTokens.create({
      accountId,
      name: input.name ?? "ci",
      scopes: input.scopes ?? ["read:items"],
      expiresInDays: input.expiresInDays ?? 30,
    });
    if (created.status !== "created") throw new Error(created.status);
    return created;
  }
  const keyed = (value: string) =>
    createHmac("sha256", hashKey).update(`api-token\u0000${value}`).digest("hex");
  return { ik, build, store, clock, audit, hashKey, account, token, keyed, legacy };
}

/** Makes the audit sink throw on the next `times` events of `type`. */
function failSink(
  audit: ReturnType<typeof createRecordingAuditSink>,
  type: AuditEvent["type"],
  times = 1,
) {
  const emit = audit.emit.bind(audit);
  let left = times;
  audit.emit = (event) => {
    if (event.type !== type || left === 0) return emit(event);
    left -= 1;
    throw new Error("sink down");
  };
}

/** The legacy digest of a token: unkeyed SHA-256 hex. */
const legacy = (value: string) => createHash("sha256").update(value).digest("hex");

/** A token in the configured format that identkit never issued. */
const randomShaped = () => `pat_${randomBytes(32).toString("base64url")}`;

describe("api tokens", () => {
  it("rule: create returns the plaintext once; the store holds only its keyed HMAC", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    const created = await t.ik.apiTokens.create({
      accountId,
      name: "deploy",
      scopes: ["write:items", "read:items"],
      expiresInDays: 7,
    });
    if (created.status !== "created") throw new Error(created.status);
    expect(created.token).toMatch(TOKEN);
    expect(created.apiToken).toEqual({
      id: created.apiToken.id,
      accountId,
      name: "deploy",
      scopes: ["write:items", "read:items"],
      createdAt: t.clock.now(),
      expiresAt: new Date(t.clock.now().getTime() + 7 * DAY * 1000),
      lastUsedAt: null,
      source: "created",
      legacyDigest: false,
    });
    const [lookup] = (await t.store.apiTokens?.findByDigests([t.keyed(created.token)])) ?? [];
    expect(lookup?.record.digestAlgorithm).toBe("hmac-sha256");
    expect(lookup?.record.id).toBe(created.apiToken.id);
    expect(JSON.stringify(lookup)).not.toContain(created.token);
    expect(JSON.stringify(lookup)).not.toContain(created.token.slice(4));
    // Two tokens never share a body.
    const second = await t.token(accountId);
    expect(second.token).not.toBe(created.token);
  });

  it("rule: verify returns the account, token id and scopes; writes lastUsedAt once per interval", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    const { token, apiToken } = await t.token(accountId, { scopes: ["write:items", "admin"] });
    expect(await t.ik.apiTokens.verify(token)).toEqual({
      status: "valid",
      accountId,
      tokenId: apiToken.id,
      scopes: ["write:items", "admin"],
      expiresAt: apiToken.expiresAt,
    });
    expect(t.audit.ofType("api_token.used")).toHaveLength(1);
    const firstUse = t.clock.now();
    t.clock.advanceSeconds(3599);
    expect((await t.ik.apiTokens.verify(token)).status).toBe("valid");
    expect(t.audit.ofType("api_token.used")).toHaveLength(1);
    expect((await t.ik.apiTokens.list(accountId))[0]?.lastUsedAt).toEqual(firstUse);
    t.clock.advanceSeconds(1);
    // Concurrent verifies when the interval is over: one write, one event.
    const results = await Promise.all(
      Array.from({ length: 5 }, () => t.ik.apiTokens.verify(token)),
    );
    expect(results.every((r) => r.status === "valid")).toBe(true);
    expect(t.audit.ofType("api_token.used")).toHaveLength(2);
    expect(t.audit.ofType("api_token.used")[1]).toEqual({
      type: "api_token.used",
      at: t.clock.now(),
      accountId,
      tokenId: apiToken.id,
    });
    expect((await t.ik.apiTokens.list(accountId))[0]?.lastUsedAt).toEqual(t.clock.now());
  });

  it("rule: lastUsedIntervalSeconds 0 writes on every verify", async () => {
    const t = tokenSetup({ apiTokens: { ...baseOptions, lastUsedIntervalSeconds: 0 } });
    const { token } = await t.token(await t.account());
    await t.ik.apiTokens.verify(token);
    await t.ik.apiTokens.verify(token);
    expect(t.audit.ofType("api_token.used")).toHaveLength(2);
  });

  it("rule: malformed tokens are refused before any digest or read", async () => {
    const t = tokenSetup();
    const { token } = await t.token(await t.account());
    const inner = t.store.apiTokens;
    if (!inner) throw new Error("no apiTokens");
    let reads = 0;
    const counting: IdentkitStore = {
      ...t.store,
      apiTokens: {
        ...inner,
        findByDigests: (digests) => {
          reads += 1;
          return inner.findByDigests(digests);
        },
      },
    };
    const c = tokenSetup({ store: counting, hashKey: t.hashKey });
    const body = token.slice(4);
    const malformed: unknown[] = [
      "",
      "pat_",
      body,
      `PAT_${body}`,
      `pat-${body}`,
      `ghp_${body}`,
      `${token}A`,
      token.slice(0, -1),
      `${token.slice(0, -1)}=`,
      `${token.slice(0, -1)}/`,
      ` ${token}`,
      `${token}\n`,
      `pat_${"A".repeat(42)}é`,
      null,
      undefined,
      42,
      { token },
      [token],
    ];
    for (const value of malformed) {
      expect(await c.ik.apiTokens.verify(value as string), String(value)).toEqual({
        status: "refused",
        reason: "malformed",
      });
    }
    expect(reads).toBe(0);
    expect((await c.ik.apiTokens.verify(token)).status).toBe("valid");
    expect(reads).toBe(1);
    expect(await c.ik.apiTokens.verify(randomShaped())).toEqual({
      status: "refused",
      reason: "unknown",
    });
  });

  it("rule: expired and revoked tokens never verify", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    const week = await t.token(accountId, { expiresInDays: 7 });
    const month = await t.token(accountId, { expiresInDays: 30 });
    t.clock.advanceSeconds(7 * DAY - 1);
    expect((await t.ik.apiTokens.verify(week.token)).status).toBe("valid");
    t.clock.advanceSeconds(1);
    expect(await t.ik.apiTokens.verify(week.token)).toEqual({
      status: "refused",
      reason: "expired",
    });
    expect(await t.ik.apiTokens.revoke({ accountId, tokenId: month.apiToken.id })).toBe(true);
    expect(await t.ik.apiTokens.verify(month.token)).toEqual({
      status: "refused",
      reason: "revoked",
    });
    // An expired token is still listed until it is revoked.
    expect((await t.ik.apiTokens.list(accountId)).map((v) => v.id)).toEqual([week.apiToken.id]);
  });

  it("rule: a token of a disabled account never verifies, also when it was not revoked", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    const { token } = await t.token(accountId);
    // As if the account were disabled outside identkit, or while the token was being created.
    await t.store.accounts.setStatus(accountId, "disabled");
    expect(await t.ik.apiTokens.verify(token)).toEqual({
      status: "refused",
      reason: "account_disabled",
    });
    expect(t.audit.ofType("api_token.used")).toHaveLength(0);
    expect(
      await t.ik.apiTokens.create({
        accountId,
        name: "x",
        scopes: ["admin"],
        expiresInDays: 7,
      }),
    ).toEqual({ status: "account_disabled" });
    expect(
      await t.ik.apiTokens.create({
        accountId: "no-such-account",
        name: "x",
        scopes: ["admin"],
        expiresInDays: 7,
      }),
    ).toEqual({ status: "no_account" });
  });

  it("rule: accounts.disable revokes every token of the account, with an event each", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    const other = await t.account();
    const a = await t.token(accountId);
    const b = await t.token(accountId);
    const kept = await t.token(other);
    await t.ik.accounts.disable(accountId);
    expect(await t.ik.apiTokens.verify(a.token)).toEqual({ status: "refused", reason: "revoked" });
    expect(await t.ik.apiTokens.verify(b.token)).toEqual({ status: "refused", reason: "revoked" });
    expect((await t.ik.apiTokens.verify(kept.token)).status).toBe("valid");
    expect(await t.ik.apiTokens.list(accountId)).toEqual([]);
    expect(
      t.audit
        .ofType("api_token.revoked")
        .map((e) => `${e.accountId} ${e.tokenId} ${e.reason}`)
        .toSorted((x, y) => x.localeCompare(y)),
    ).toEqual(
      [
        `${accountId} ${a.apiToken.id} account_disabled`,
        `${accountId} ${b.apiToken.id} account_disabled`,
      ].toSorted((x, y) => x.localeCompare(y)),
    );
    expect(t.audit.ofType("account.disabled")).toHaveLength(1);
    // A retry records nothing twice.
    await t.ik.accounts.disable(accountId);
    expect(t.audit.ofType("api_token.revoked")).toHaveLength(2);
  });

  it("rule: accounts.disable offers every event and runs the hook when the sink refuses a token event", async () => {
    let hookRuns = 0;
    const t = tokenSetup({ onAllSessionsRevoked: () => void (hookRuns += 1) });
    const accountId = await t.account();
    await t.token(accountId);
    await t.token(accountId);
    failSink(t.audit, "api_token.revoked");
    await expect(t.ik.accounts.disable(accountId)).rejects.toThrow("sink down");
    expect(hookRuns).toBe(1);
    expect(t.audit.ofType("account.disabled")).toHaveLength(1);
    expect(t.audit.ofType("api_token.revoked")).toHaveLength(1);
    expect(await t.ik.apiTokens.list(accountId)).toEqual([]);
  });

  it("rule: sessions and tokens are separate; revokeAll for tokens does not run the session hook", async () => {
    let hookRuns = 0;
    const t = tokenSetup({ onAllSessionsRevoked: () => void (hookRuns += 1) });
    const accountId = await t.account();
    const { token } = await t.token(accountId);
    await t.ik.sessions.revokeAll(accountId);
    expect(hookRuns).toBe(1);
    expect((await t.ik.apiTokens.verify(token)).status).toBe("valid");
    expect(await t.ik.apiTokens.revokeAll(accountId)).toBe(1);
    expect(hookRuns).toBe(1);
    expect((await t.ik.apiTokens.verify(token)).status).toBe("refused");
  });

  it("rule: revoke is scoped to the account and recorded once; revokeAll is idempotent", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    const other = await t.account();
    const a = await t.token(accountId);
    await t.token(accountId);
    await t.token(other);
    expect(await t.ik.apiTokens.revoke({ accountId: other, tokenId: a.apiToken.id })).toBe(false);
    expect((await t.ik.apiTokens.verify(a.token)).status).toBe("valid");
    expect(await t.ik.apiTokens.revoke({ accountId, tokenId: a.apiToken.id })).toBe(true);
    expect(await t.ik.apiTokens.revoke({ accountId, tokenId: a.apiToken.id })).toBe(false);
    expect(t.audit.ofType("api_token.revoked")).toEqual([
      {
        type: "api_token.revoked",
        at: t.clock.now(),
        accountId,
        tokenId: a.apiToken.id,
        reason: "revoked",
      },
    ]);
    expect(await t.ik.apiTokens.revokeAll(accountId)).toBe(1);
    expect(await t.ik.apiTokens.revokeAll(accountId)).toBe(0);
    expect(t.audit.ofType("api_token.revoked").map((e) => e.reason)).toEqual([
      "revoked",
      "revoked_all",
    ]);
    expect(await t.ik.apiTokens.list(other)).toHaveLength(1);
  });

  it("rule: revokeAll offers every event when the sink refuses one, then throws", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    await t.token(accountId);
    await t.token(accountId);
    await t.token(accountId);
    failSink(t.audit, "api_token.revoked");
    await expect(t.ik.apiTokens.revokeAll(accountId)).rejects.toThrow("sink down");
    expect(t.audit.ofType("api_token.revoked")).toHaveLength(2);
    expect(await t.ik.apiTokens.list(accountId)).toEqual([]);
  });

  it("rule: the active-token cap holds under parallel creates; revoked and expired do not count", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    const results = await Promise.all(
      Array.from({ length: 12 }, () =>
        t.ik.apiTokens.create({ accountId, name: "x", scopes: ["admin"], expiresInDays: 7 }),
      ),
    );
    expect(results.filter((r) => r.status === "created")).toHaveLength(5);
    expect(results.filter((r) => r.status === "limit_reached")).toHaveLength(7);
    expect(await t.ik.apiTokens.list(accountId)).toHaveLength(5);
    expect(t.audit.ofType("api_token.created")).toHaveLength(5);
    const [first] = await t.ik.apiTokens.list(accountId);
    if (!first) throw new Error("no token");
    await t.ik.apiTokens.revoke({ accountId, tokenId: first.id });
    expect((await t.token(accountId, { expiresInDays: 30 })).token).toMatch(TOKEN);
    expect(
      (await t.ik.apiTokens.create({ accountId, name: "x", scopes: ["admin"], expiresInDays: 7 }))
        .status,
    ).toBe("limit_reached");
    // The four 7-day tokens expire; the 30-day one still counts.
    t.clock.advanceSeconds(7 * DAY);
    const later = await Promise.all(
      Array.from({ length: 6 }, () =>
        t.ik.apiTokens.create({ accountId, name: "x", scopes: ["admin"], expiresInDays: 7 }),
      ),
    );
    expect(later.filter((r) => r.status === "created")).toHaveLength(4);
  });

  it("rule: maxActiveTokensPerAccount and allowedExpiryDays are configurable", async () => {
    const t = tokenSetup({
      apiTokens: { ...baseOptions, maxActiveTokensPerAccount: 1, allowedExpiryDays: [1, 365] },
    });
    const accountId = await t.account();
    await t.token(accountId, { expiresInDays: 365 });
    expect(
      (await t.ik.apiTokens.create({ accountId, name: "x", scopes: ["admin"], expiresInDays: 1 }))
        .status,
    ).toBe("limit_reached");
    await expect(
      t.ik.apiTokens.create({ accountId, name: "x", scopes: ["admin"], expiresInDays: 30 }),
    ).rejects.toBeInstanceOf(InvalidArgumentError);
  });

  it("rule: create refuses invalid names, scopes, expiries and ids", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    const valid = { accountId, name: "ok", scopes: ["admin"], expiresInDays: 7 };
    const invalid: unknown[] = [
      { ...valid, name: "" },
      { ...valid, name: "x".repeat(65) },
      { ...valid, name: "line\nbreak" },
      { ...valid, name: "tab\there" },
      { ...valid, name: "sep x" },
      { ...valid, name: "a\u202Eb" },
      { ...valid, name: "a\u2066b" },
      { ...valid, name: "zero\u200Bwidth" },
      { ...valid, name: "bom\uFEFF" },
      { ...valid, name: "lone\uD800" },
      { ...valid, name: 7 },
      { ...valid, scopes: [] },
      { ...valid, scopes: ["admin", "admin"] },
      { ...valid, scopes: ["unknown"] },
      { ...valid, scopes: ["admin", 1] },
      { ...valid, scopes: "admin" },
      { ...valid, expiresInDays: 8 },
      { ...valid, expiresInDays: "7" },
      { ...valid, expiresInDays: undefined },
      { ...valid, accountId: "" },
      { ...valid, accountId: 1 },
      null,
    ];
    for (const input of invalid) {
      await expect(
        t.ik.apiTokens.create(input as Parameters<typeof t.ik.apiTokens.create>[0]),
        JSON.stringify(input),
      ).rejects.toBeInstanceOf(InvalidArgumentError);
    }
    // 64 characters, also outside ASCII, are fine.
    expect((await t.token(accountId, { name: "ä".repeat(64) })).apiToken.name).toBe("ä".repeat(64));
    expect(await t.ik.apiTokens.list(accountId)).toHaveLength(1);
  });

  it("rule: verify returns only scopes the operator still allows, and refuses a token with none", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    const both = await t.token(accountId, { scopes: ["admin", "read:items"] });
    t.clock.advanceSeconds(1);
    const adminOnly = await t.token(accountId, { scopes: ["admin"] });
    const narrowed = t.build({ ...baseOptions, allowedScopes: ["read:items"] });
    expect(await narrowed.apiTokens.verify(both.token)).toMatchObject({
      status: "valid",
      scopes: ["read:items"],
    });
    expect(await narrowed.apiTokens.verify(adminOnly.token)).toEqual({
      status: "refused",
      reason: "no_allowed_scope",
    });
    // The stored scopes stay as given.
    expect((await narrowed.apiTokens.list(accountId)).map((v) => v.scopes)).toEqual([
      ["admin", "read:items"],
      ["admin"],
    ]);
  });

  it("rule: the digest found by the read is compared again; a row with another digest never verifies", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    const { token } = await t.token(accountId);
    const inner = t.store.apiTokens;
    if (!inner) throw new Error("no apiTokens");
    // A broken store that returns every token of the account, whatever the digest.
    const loose: IdentkitStore = {
      ...t.store,
      apiTokens: {
        ...inner,
        findByDigests: async () => {
          const [record] = await inner.listByAccount(accountId);
          return record ? [{ record, accountStatus: "active" }] : [];
        },
      },
    };
    const l = tokenSetup({ store: loose, hashKey: t.hashKey });
    expect((await l.ik.apiTokens.verify(token)).status).toBe("valid");
    expect(await l.ik.apiTokens.verify(randomShaped())).toEqual({
      status: "refused",
      reason: "unknown",
    });
  });

  it("rule: import of a plaintext token stores its keyed HMAC and is idempotent", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    const other = await t.account();
    const token = randomShaped();
    const expiresAt = new Date(t.clock.now().getTime() + 10 * DAY * 1000);
    const createdAt = new Date(t.clock.now().getTime() - 20 * DAY * 1000);
    const input = { accountId, name: "legacy", scopes: ["read:items"], expiresAt, token };
    const imported = await t.ik.apiTokens.import({ ...input, createdAt });
    if (imported.status !== "imported") throw new Error(imported.status);
    expect(imported.apiToken).toMatchObject({
      accountId,
      source: "import",
      legacyDigest: false,
      createdAt,
      expiresAt,
      lastUsedAt: null,
    });
    const [lookup] = (await t.store.apiTokens?.findByDigests([t.keyed(token)])) ?? [];
    expect(lookup?.record.digestAlgorithm).toBe("hmac-sha256");
    expect(await t.ik.apiTokens.verify(token)).toMatchObject({
      status: "valid",
      accountId,
      tokenId: imported.apiToken.id,
    });
    expect(await t.ik.apiTokens.import(input)).toMatchObject({ status: "already_imported" });
    expect(await t.ik.apiTokens.import({ ...input, accountId: other })).toEqual({
      status: "digest_taken",
    });
    expect(t.audit.ofType("api_token.imported")).toEqual([
      {
        type: "api_token.imported",
        at: t.clock.now(),
        accountId,
        tokenId: imported.apiToken.id,
        scopes: ["read:items"],
        method: "hmac-sha256",
      },
    ]);
    await t.ik.apiTokens.revoke({ accountId, tokenId: imported.apiToken.id });
    expect(await t.ik.apiTokens.import(input)).toEqual({ status: "revoked" });
    expect(await t.ik.apiTokens.verify(token)).toEqual({ status: "refused", reason: "revoked" });
  });

  it("rule: import refuses bad input, expired tokens, longer expiries and a full account", async () => {
    const t = tokenSetup({ apiTokens: { ...baseOptions, maxActiveTokensPerAccount: 1 } });
    const accountId = await t.account();
    const now = t.clock.now().getTime();
    const base = {
      accountId,
      name: "legacy",
      scopes: ["read:items"],
      expiresAt: new Date(now + DAY * 1000),
    };
    const invalid: unknown[] = [
      base,
      { ...base, token: randomShaped(), sha256Digest: "a".repeat(64) },
      { ...base, token: "not-a-token" },
      { ...base, token: randomShaped(), expiresAt: new Date(now + 91 * DAY * 1000) },
      { ...base, token: randomShaped(), expiresAt: new Date(Number.NaN) },
      { ...base, token: randomShaped(), expiresAt: "2030-02-01" },
      { ...base, token: randomShaped(), createdAt: new Date(Number.NaN) },
      { ...base, token: randomShaped(), scopes: ["other"] },
    ];
    for (const input of invalid) {
      await expect(
        t.ik.apiTokens.import(input as Parameters<typeof t.ik.apiTokens.import>[0]),
        JSON.stringify(input),
      ).rejects.toBeInstanceOf(InvalidArgumentError);
    }
    expect(
      await t.ik.apiTokens.import({
        ...base,
        token: randomShaped(),
        expiresAt: new Date(now),
      }),
    ).toEqual({ status: "expired" });
    expect((await t.ik.apiTokens.import({ ...base, token: randomShaped() })).status).toBe(
      "imported",
    );
    expect(await t.ik.apiTokens.import({ ...base, token: randomShaped() })).toEqual({
      status: "limit_reached",
    });
    expect(
      await t.ik.apiTokens.import({ ...base, accountId: "missing", token: randomShaped() }),
    ).toEqual({ status: "no_account" });
  });

  it("rule: a legacy SHA-256 digest needs acceptLegacyDigests, verifies only as SHA-256, and turns off", async () => {
    const off = tokenSetup();
    const offAccount = await off.account();
    const token = randomShaped();
    const expiresAt = new Date(off.clock.now().getTime() + 30 * DAY * 1000);
    await expect(
      off.ik.apiTokens.import({
        accountId: offAccount,
        name: "legacy",
        scopes: ["read:items"],
        expiresAt,
        sha256Digest: off.legacy(token),
      }),
    ).rejects.toBeInstanceOf(NotConfiguredError);

    const t = tokenSetup({ apiTokens: { ...baseOptions, acceptLegacyDigests: true } });
    const accountId = await t.account();
    const imported = await t.ik.apiTokens.import({
      accountId,
      name: "legacy",
      scopes: ["read:items"],
      expiresAt,
      sha256Digest: t.legacy(token).toUpperCase(),
      lastUsedAt: new Date(t.clock.now().getTime() - DAY * 1000),
    });
    if (imported.status !== "imported") throw new Error(imported.status);
    expect(imported.apiToken.legacyDigest).toBe(true);
    const [lookup] = (await t.store.apiTokens?.findByDigests([t.legacy(token)])) ?? [];
    expect(lookup?.record).toMatchObject({ digestAlgorithm: "sha256", digest: t.legacy(token) });
    expect(await t.ik.apiTokens.verify(token)).toMatchObject({
      status: "valid",
      tokenId: imported.apiToken.id,
    });
    expect(t.audit.ofType("api_token.imported")[0]?.method).toBe("sha256");

    // A row is matched only by the digest of its own algorithm: a SHA-256 row that holds the
    // keyed HMAC of a token does not verify that token.
    const other = randomShaped();
    await t.ik.apiTokens.import({
      accountId,
      name: "crossed",
      scopes: ["read:items"],
      expiresAt,
      sha256Digest: t.keyed(other),
    });
    expect(await t.ik.apiTokens.verify(other)).toEqual({ status: "refused", reason: "unknown" });

    // Turning the option off stops every legacy token at once.
    const strict = t.build({ ...baseOptions, acceptLegacyDigests: false });
    expect(await strict.apiTokens.verify(token)).toEqual({ status: "refused", reason: "unknown" });
  });

  it("rule: create and import roll back when the sink refuses their event", async () => {
    const t = tokenSetup({ apiTokens: { ...baseOptions, maxActiveTokensPerAccount: 1 } });
    const accountId = await t.account();
    failSink(t.audit, "api_token.created");
    const error: unknown = await t.ik.apiTokens
      .create({ accountId, name: "x", scopes: ["admin"], expiresInDays: 7 })
      .then(
        () => null,
        (e: unknown) => e,
      );
    expect(error).toBeInstanceOf(OperationRolledBackError);
    expect(error).toMatchObject({ accountId, hookFailed: false, cause: new Error("sink down") });
    expect(await t.ik.apiTokens.list(accountId)).toEqual([]);
    // The rolled-back token holds no slot.
    await t.token(accountId);
    await t.ik.apiTokens.revokeAll(accountId);

    const token = randomShaped();
    const input = {
      accountId,
      name: "legacy",
      scopes: ["admin"],
      expiresAt: new Date(t.clock.now().getTime() + DAY * 1000),
      token,
    };
    failSink(t.audit, "api_token.imported");
    await expect(t.ik.apiTokens.import(input)).rejects.toBeInstanceOf(OperationRolledBackError);
    expect(await t.ik.apiTokens.verify(token)).toEqual({ status: "refused", reason: "unknown" });
    // A retry imports it.
    expect((await t.ik.apiTokens.import(input)).status).toBe("imported");
  });

  it("rule: a refused revoke event undoes no revocation", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    const { token, apiToken } = await t.token(accountId);
    failSink(t.audit, "api_token.revoked");
    await expect(t.ik.apiTokens.revoke({ accountId, tokenId: apiToken.id })).rejects.toThrow(
      "sink down",
    );
    expect(await t.ik.apiTokens.verify(token)).toEqual({ status: "refused", reason: "revoked" });
  });

  it("rule: no event, error or result after create holds the token or its digest", async () => {
    const t = tokenSetup({ apiTokens: { ...baseOptions, acceptLegacyDigests: true } });
    const accountId = await t.account();
    const { token, apiToken } = await t.token(accountId);
    const legacyToken = randomShaped();
    await t.ik.apiTokens.import({
      accountId,
      name: "legacy",
      scopes: ["read:items"],
      expiresAt: new Date(t.clock.now().getTime() + DAY * 1000),
      sha256Digest: t.legacy(legacyToken),
    });
    const results = [
      await t.ik.apiTokens.verify(token),
      await t.ik.apiTokens.verify(legacyToken),
      await t.ik.apiTokens.list(accountId),
      apiToken,
    ];
    await t.ik.apiTokens.revokeAll(accountId);
    await t.ik.accounts.disable(accountId);
    const secrets = [
      token,
      token.slice(4),
      t.keyed(token),
      t.legacy(token),
      legacyToken,
      t.legacy(legacyToken),
    ];
    const rendered = JSON.stringify({ events: t.audit.events, results });
    for (const secret of secrets) expect(rendered).not.toContain(secret);
    expect(t.audit.ofType("api_token.created")[0]).toEqual({
      type: "api_token.created",
      at: apiToken.createdAt,
      accountId,
      tokenId: apiToken.id,
      scopes: ["read:items"],
    });
  });

  it("rule: without the option every call throws NotConfiguredError; invalid options fail at createIdentkit", async () => {
    const t = tokenSetup();
    const bare = t.build(undefined);
    await expect(bare.apiTokens.verify(randomShaped())).rejects.toBeInstanceOf(NotConfiguredError);
    await expect(bare.apiTokens.list("a")).rejects.toBeInstanceOf(NotConfiguredError);
    await expect(bare.apiTokens.revokeAll("a")).rejects.toBeInstanceOf(NotConfiguredError);

    const invalid: unknown[] = [
      { ...baseOptions, prefix: "" },
      { ...baseOptions, prefix: "pat-" },
      { ...baseOptions, prefix: "_pat" },
      { ...baseOptions, prefix: "1pat" },
      { ...baseOptions, prefix: `p${"a".repeat(32)}` },
      { ...baseOptions, allowedScopes: [] },
      { ...baseOptions, allowedScopes: ["a b"] },
      { ...baseOptions, allowedScopes: ["a", "a"] },
      { ...baseOptions, allowedScopes: [""] },
      { ...baseOptions, allowedExpiryDays: [] },
      { ...baseOptions, allowedExpiryDays: [0] },
      { ...baseOptions, allowedExpiryDays: [7, 7] },
      { ...baseOptions, allowedExpiryDays: [1.5] },
      { ...baseOptions, maxActiveTokensPerAccount: 0 },
      { ...baseOptions, lastUsedIntervalSeconds: -1 },
      { ...baseOptions, acceptLegacyDigests: "yes" },
      { ...baseOptions, unknownOption: true },
      { allowedScopes: ["a"] },
    ];
    for (const options of invalid) {
      expect(() => t.build(options as ApiTokenOptions), JSON.stringify(options)).toThrow(
        InvalidArgumentError,
      );
    }
    const { apiTokens: _dropped, ...withoutTokens } = createMemoryStore();
    expect(() => tokenSetup({ store: withoutTokens })).toThrow(NotConfiguredError);
  });

  it("rule: a store without apiTokens still disables accounts", async () => {
    const { apiTokens: _dropped, ...withoutTokens } = createMemoryStore();
    const audit = createRecordingAuditSink();
    const ik = createIdentkit({
      config: testConfig,
      policy: emailFirstPolicy,
      isPrivilegedAccount: () => false,
      store: withoutTokens,
      hasher: createHmacHasher(new Uint8Array(randomBytes(32))),
      sealer: createTestSealer(),
      mail: createRecordingMailSender(),
      audit,
    });
    const created = await ik.accounts.create({ email: "plain@example.org" });
    if (created.status !== "created") throw new Error(created.status);
    await ik.accounts.disable(created.account.id);
    expect(audit.ofType("account.disabled")).toHaveLength(1);
  });

  it("parseBearerToken takes the token of a Bearer header", () => {
    const token = randomShaped();
    expect(parseBearerToken(`Bearer ${token}`)).toBe(token);
    expect(parseBearerToken(`bearer ${token}`)).toBe(token);
    expect(parseBearerToken(`BEARER   ${token}`)).toBe(token);
    expect(parseBearerToken(`  Bearer ${token}  `)).toBe(token);
    expect(parseBearerToken("Bearer abc==")).toBe("abc==");
    for (const value of [
      null,
      undefined,
      "",
      "Bearer",
      "Bearer ",
      `Basic ${token}`,
      `Bearer ${token} extra`,
      `Bearer\t${token}`,
      `Bearer ${token},`,
      token,
    ]) {
      expect(parseBearerToken(value), String(value)).toBeNull();
    }
  });
});

/** Import input without the token, valid for ten days from the fake clock's now. */
function importInput(t: ReturnType<typeof tokenSetup>, accountId: string) {
  return {
    accountId,
    name: "legacy",
    scopes: ["read:items"],
    expiresAt: new Date(t.clock.now().getTime() + 10 * DAY * 1000),
  };
}

describe("api tokens: one token stored twice", () => {
  const legacyOptions: ApiTokenOptions = { ...baseOptions, acceptLegacyDigests: true };

  it("rule: import with the plaintext finds a legacy row of the same token (same account)", async () => {
    const t = tokenSetup({ apiTokens: legacyOptions });
    const accountId = await t.account();
    const token = randomShaped();
    const base = importInput(t, accountId);
    const first = await t.ik.apiTokens.import({ ...base, sha256Digest: t.legacy(token) });
    if (first.status !== "imported") throw new Error(first.status);
    expect(await t.ik.apiTokens.import({ ...base, token })).toEqual({
      status: "already_imported",
      apiToken: first.apiToken,
    });
    expect(await t.ik.apiTokens.list(accountId)).toHaveLength(1);
    await t.ik.apiTokens.revoke({ accountId, tokenId: first.apiToken.id });
    // Probe P1 of the review: the keyed copy brought a revoked token back.
    expect(await t.ik.apiTokens.import({ ...base, token })).toEqual({ status: "revoked" });
    expect(await t.ik.apiTokens.verify(token)).toEqual({ status: "refused", reason: "revoked" });
    // Also after the operator turned legacy digests off: the revoked row still counts.
    const strict = t.build(baseOptions);
    expect(await strict.apiTokens.import({ ...base, token })).toEqual({ status: "revoked" });
    expect(await strict.apiTokens.verify(token)).toEqual({ status: "refused", reason: "unknown" });
  });

  it("rule: import with the plaintext finds a legacy row of the same token on another account", async () => {
    const t = tokenSetup({ apiTokens: legacyOptions });
    const a = await t.account();
    const b = await t.account();
    const token = randomShaped();
    const first = await t.ik.apiTokens.import({
      ...importInput(t, a),
      sha256Digest: t.legacy(token),
    });
    expect(first.status).toBe("imported");
    // Probe P1b of the review: the keyed copy on b made the token authenticate as a or b.
    expect(await t.ik.apiTokens.import({ ...importInput(t, b), token })).toEqual({
      status: "digest_taken",
    });
    expect(await t.ik.apiTokens.verify(token)).toMatchObject({ status: "valid", accountId: a });
  });

  it("rule: verify refuses a token that more than one row matches, in every state", async () => {
    const t = tokenSetup({ apiTokens: legacyOptions });
    const a = await t.account();
    const b = await t.account();
    const token = randomShaped();
    // Keyed first, legacy second: import cannot see the keyed row without the plaintext.
    const keyed = await t.ik.apiTokens.import({ ...importInput(t, b), token });
    const weak = await t.ik.apiTokens.import({
      ...importInput(t, a),
      sha256Digest: t.legacy(token),
    });
    if (keyed.status !== "imported" || weak.status !== "imported") throw new Error("setup");
    const ambiguous = { status: "refused", reason: "ambiguous" };
    expect(await t.ik.apiTokens.verify(token)).toEqual(ambiguous);
    expect(t.audit.ofType("api_token.used")).toEqual([]);
    // One copy revoked: still refused, whichever one.
    await t.ik.apiTokens.revoke({ accountId: b, tokenId: keyed.apiToken.id });
    expect(await t.ik.apiTokens.verify(token)).toEqual(ambiguous);
    // Without legacy digests, only the keyed row is read: it is revoked.
    expect(await t.build(baseOptions).apiTokens.verify(token)).toEqual({
      status: "refused",
      reason: "revoked",
    });

    // Same account, other order of states: the legacy copy revoked, the keyed copy live.
    const other = randomShaped();
    const k2 = await t.ik.apiTokens.import({ ...importInput(t, a), token: other });
    const l2 = await t.ik.apiTokens.import({
      ...importInput(t, a),
      sha256Digest: t.legacy(other),
    });
    if (k2.status !== "imported" || l2.status !== "imported") throw new Error("setup");
    await t.ik.apiTokens.revoke({ accountId: a, tokenId: l2.apiToken.id });
    expect(await t.ik.apiTokens.verify(other)).toEqual(ambiguous);
  });
});

describe("api tokens: api_token.used is best effort", () => {
  it("rule: a refused api_token.used does not fail verify; onAuditError gets the error once", async () => {
    const calls: { error: unknown; event: AuditEvent }[] = [];
    const t = tokenSetup({
      apiTokens: {
        ...baseOptions,
        onAuditError: (error, event) => void calls.push({ error, event }),
      },
    });
    const accountId = await t.account();
    const { token, apiToken } = await t.token(accountId);
    failSink(t.audit, "api_token.used");
    expect(await t.ik.apiTokens.verify(token)).toMatchObject({ status: "valid", accountId });
    expect(calls).toEqual([
      {
        error: new Error("sink down"),
        event: { type: "api_token.used", at: t.clock.now(), accountId, tokenId: apiToken.id },
      },
    ]);
    // lastUsedAt is written, so the next verify in the interval writes and emits nothing.
    expect((await t.ik.apiTokens.list(accountId))[0]?.lastUsedAt).toEqual(t.clock.now());
    expect((await t.ik.apiTokens.verify(token)).status).toBe("valid");
    expect(calls).toHaveLength(1);
    expect(t.audit.ofType("api_token.used")).toEqual([]);
  });

  it("rule: without onAuditError, or with one that throws, verify still returns valid", async () => {
    const plain = tokenSetup({ apiTokens: { ...baseOptions, lastUsedIntervalSeconds: 0 } });
    const { token } = await plain.token(await plain.account());
    failSink(plain.audit, "api_token.used", 3);
    for (let i = 0; i < 3; i += 1) {
      expect((await plain.ik.apiTokens.verify(token)).status).toBe("valid");
    }

    const throwing = tokenSetup({
      apiTokens: {
        ...baseOptions,
        onAuditError: () => Promise.reject(new Error("handler down")),
      },
    });
    const second = await throwing.token(await throwing.account());
    failSink(throwing.audit, "api_token.used");
    expect((await throwing.ik.apiTokens.verify(second.token)).status).toBe("valid");
  });

  it("rule: onAuditError must be a function", () => {
    expect(() =>
      tokenSetup({ apiTokens: { ...baseOptions, onAuditError: "log" as unknown as () => void } }),
    ).toThrow(InvalidArgumentError);
  });
});

describe("api tokens: accounts.disable without a working token store", () => {
  it("rule: sessions are revoked and the hook runs when the token revocation throws", async () => {
    const memory = createMemoryStore();
    const tokens = memory.apiTokens;
    if (!tokens) throw new Error("memory store has apiTokens");
    const store: IdentkitStore = {
      ...memory,
      apiTokens: {
        ...tokens,
        revokeAllForAccount: () => Promise.reject(new Error("no such table: identkit_api_tokens")),
      },
    };
    const hookEvents: { accountId: string; revokedSessionIds: string[] }[] = [];
    const t = setup({ store, onAllSessionsRevoked: (event) => void hookEvents.push(event) });
    const session = await t.signIn("disable@example.org");
    const accountId = session.account.id;
    await expect(t.ik.accounts.disable(accountId)).rejects.toThrow(
      "no such table: identkit_api_tokens",
    );
    expect(hookEvents).toHaveLength(1);
    expect(hookEvents[0]).toMatchObject({ accountId, revokedSessionIds: [session.session.id] });
    expect(t.audit.ofType("session.revoked")).toHaveLength(1);
    expect(t.audit.ofType("account.disabled")).toHaveLength(1);
    expect((await t.ik.accounts.get(accountId))?.status).toBe("disabled");
  });
});

describe("api tokens: import dates", () => {
  it("rule: import refuses createdAt or lastUsedAt in the future and lastUsedAt before createdAt", async () => {
    const t = tokenSetup();
    const accountId = await t.account();
    const now = t.clock.now().getTime();
    const base = {
      accountId,
      name: "legacy",
      scopes: ["read:items"],
      expiresAt: new Date(now + 10 * DAY * 1000),
    };
    const invalid = [
      { createdAt: new Date(now + 1) },
      { lastUsedAt: new Date(now + 1) },
      { lastUsedAt: new Date(now + 365 * DAY * 1000) },
      { createdAt: new Date(now - 2000), lastUsedAt: new Date(now - 2001) },
    ];
    for (const dates of invalid) {
      await expect(
        t.ik.apiTokens.import({ ...base, ...dates, token: randomShaped() }),
        JSON.stringify(dates),
      ).rejects.toBeInstanceOf(InvalidArgumentError);
    }
    expect(await t.ik.apiTokens.list(accountId)).toEqual([]);
    // The edges are fine: both at now, or lastUsedAt equal to createdAt.
    const edge = await t.ik.apiTokens.import({
      ...base,
      createdAt: new Date(now),
      lastUsedAt: new Date(now),
      token: randomShaped(),
    });
    expect(edge.status).toBe("imported");
    // Without createdAt (default now), a past lastUsedAt is a date of the source system.
    const noCreatedAt = await t.ik.apiTokens.import({
      ...base,
      lastUsedAt: new Date(now - DAY * 1000),
      token: randomShaped(),
    });
    expect(noCreatedAt.status).toBe("imported");
  });
});
