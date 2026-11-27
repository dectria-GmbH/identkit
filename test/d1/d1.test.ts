/**
 * D1 store tests against a local D1 database (miniflare). They need no account and no
 * network: pnpm test:d1
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { addSeconds } from "../../src/clock.js";
import {
  createD1Store,
  D1_DEFAULT_THROTTLE_RETRIES,
  D1_MIGRATIONS,
  D1ThrottleContentionError,
  migrateIdentkitD1,
  type D1DatabaseLike,
} from "../../src/d1/index.js";
import type { IdentkitStore, SessionRecord } from "../../src/storage/types.js";
import { hashPayload } from "../../src/index.js";
import { mfaPolicy, setup } from "../helpers.js";
import { runStoreContract } from "../store-contract.js";
import { runStoreFlows } from "../store-flows.js";
import { oauthRowsAfterAccountDelete } from "../oauth-helpers.js";
import { startLocalD1 } from "./local-d1.js";
import { recordingD1 } from "./recording-d1.js";

/**
 * D1 limit on queries per Worker invocation, Workers Free plan. Source:
 * https://developers.cloudflare.com/d1/platform/limits/ (read 2026-11-27: "1000 (Workers Paid)
 * / 50 (Free)"; a `batch()` counts as one query).
 */
const FREE_QUERIES_PER_INVOCATION = 50;

const T0 = new Date("2030-01-01T00:00:00.000Z");

let local: Awaited<ReturnType<typeof startLocalD1>> | undefined;
let store: IdentkitStore | undefined;

function requireDb(): D1DatabaseLike {
  if (!local) throw new Error("database not initialised");
  return local.db;
}

function requireStore(): IdentkitStore {
  if (!store) throw new Error("store not initialised");
  return store;
}

function requireLocal(): NonNullable<typeof local> {
  if (!local) throw new Error("database not initialised");
  return local;
}

const accountAt = (id: string) => ({
  id,
  email: `${id}@example.org`,
  webauthnUserId: `${id}-wu`,
  status: "active" as const,
  createdAt: T0,
  personKeyDigest: null,
  assuranceLevel: null,
  identityVerifiedAt: null,
});

const sessionAt = (id: string, accountId: string): SessionRecord => ({
  id,
  accountId,
  tokenDigest: `${id}-digest`,
  state: "complete",
  authMethods: ["email_otp"],
  createdAt: T0,
  lastSeenAt: T0,
  absoluteExpiresAt: addSeconds(T0, 3600),
  stepUp: null,
  revokedAt: null,
  revokeReason: null,
});

async function names(db: D1DatabaseLike): Promise<string[]> {
  const { results } = await db
    .prepare("SELECT name FROM sqlite_master WHERE type IN ('table', 'index') ORDER BY name")
    .all();
  return results.map((r) => String(r["name"]));
}

// Each statement is a round trip into workerd; on a loaded machine the default 5 s is short.
describe("d1", { timeout: 30_000 }, () => {
  let before: string[] = [];

  beforeAll(async () => {
    local = await startLocalD1();
    const db = requireDb();
    // Tables of the application that shares the database. identkit must leave them alone.
    await db.batch([
      db.prepare("CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE)"),
      db.prepare("CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL)"),
      db.prepare("CREATE TABLE api_tokens (id TEXT PRIMARY KEY)"),
      db.prepare("INSERT INTO users (id, email) VALUES ('u1', 'app@example.org')"),
    ]);
    before = await names(db);
    expect(await migrateIdentkitD1(db)).toEqual(D1_MIGRATIONS.map((m) => m.name));
    expect(await migrateIdentkitD1(db)).toEqual([]);
    store = createD1Store(db);
  }, 60_000);

  afterAll(async () => {
    await local?.stop();
  });

  runStoreContract("d1", () => requireStore());
  runStoreFlows("d1", requireStore);

  it("oauth row 28: deleting an account row removes its grants, access tokens and codes", async () => {
    const db = requireDb();
    const result = await oauthRowsAfterAccountDelete(
      requireStore(),
      async (accountId) => {
        await db.prepare("DELETE FROM identkit_accounts WHERE id = ?1").bind(accountId).run();
      },
      async (table, column, value) => {
        const row = await db
          .prepare(`SELECT count(*) AS n FROM ${table} WHERE ${column} = ?1`)
          .bind(value)
          .first();
        return Number(row?.["n"]);
      },
    );
    // The control: the rows exist before the delete.
    expect(result.before).toEqual({ grants: 1, accessTokens: 1, codes: 1 });
    expect(result.after).toEqual({ grants: 0, accessTokens: 0, codes: 0 });
    // The client belongs to no account and stays.
    expect(result.client).not.toBeNull();
  });

  it("migrations: every new table and index starts with identkit_; other tables stay", async () => {
    const db = requireDb();
    const added = (await names(db)).filter((name) => !before.includes(name));
    expect(added.length).toBeGreaterThan(10);
    // SQLite names the index of a UNIQUE column after its table.
    const foreign = added.filter(
      (name) => !name.startsWith("identkit_") && !name.startsWith("sqlite_autoindex_identkit_"),
    );
    expect(foreign).toEqual([]);
    expect(await db.prepare("SELECT email FROM users WHERE id = 'u1'").first()).toEqual({
      email: "app@example.org",
    });
  });

  it("migrations: concurrent runs apply each migration once", async () => {
    const { db, stop } = await startLocalD1();
    try {
      const runs = await Promise.all(Array.from({ length: 4 }, () => migrateIdentkitD1(db)));
      expect(runs.flat().toSorted()).toEqual(D1_MIGRATIONS.map((m) => m.name));
      const { results } = await db.prepare("SELECT name FROM identkit_migrations").all();
      expect(results).toHaveLength(D1_MIGRATIONS.length);
    } finally {
      await stop();
    }
  }, 60_000);

  it("migrations: a failing migration rolls back, also its record", async () => {
    const { db, stop } = await startLocalD1();
    try {
      const broken = [
        ...D1_MIGRATIONS,
        { name: "9999_broken.sql", sql: "CREATE TABLE identkit_x (a TEXT);\nNOT SQL;\n" },
      ];
      await expect(migrateIdentkitD1(db, { migrations: broken })).rejects.toThrow();
      expect(
        await db.prepare("SELECT name FROM sqlite_master WHERE name = 'identkit_x'").first(),
      ).toBeNull();
      expect(
        await db
          .prepare("SELECT name FROM identkit_migrations WHERE name = '9999_broken.sql'")
          .first(),
      ).toBeNull();
    } finally {
      await stop();
    }
  }, 60_000);

  it("migrations: an applied migration whose SQL changed is refused", async () => {
    const { db, stop } = await startLocalD1();
    try {
      const first = { name: "0001_a.sql", sql: "CREATE TABLE identkit_a (id TEXT NOT NULL);\n" };
      expect(await migrateIdentkitD1(db, { migrations: [first] })).toEqual(["0001_a.sql"]);
      expect(await migrateIdentkitD1(db, { migrations: [first] })).toEqual([]);
      const changed = { ...first, sql: "CREATE TABLE identkit_a (id TEXT);\n" };
      await expect(migrateIdentkitD1(db, { migrations: [changed] })).rejects.toThrow(
        /0001_a\.sql differs from the applied one/,
      );
    } finally {
      await stop();
    }
  }, 60_000);

  it("migrations: two statements on one line are refused before anything runs", async () => {
    // D1 runs every statement of a prepared string, so the second one would run unchecked.
    const { db, stop } = await startLocalD1();
    try {
      const twoOnOneLine = {
        name: "0001_a.sql",
        sql: "CREATE TABLE identkit_a (id TEXT); CREATE TABLE app_b (id TEXT);\n",
      };
      await expect(migrateIdentkitD1(db, { migrations: [twoOnOneLine] })).rejects.toThrow(
        /0001_a\.sql has a statement with an inner ";"/,
      );
      expect(
        await db
          .prepare("SELECT name FROM sqlite_master WHERE name IN ('identkit_a', 'app_b')")
          .all(),
      ).toMatchObject({ results: [] });
    } finally {
      await stop();
    }
  }, 60_000);

  it("migrations: a record table without checksum gets the column and its rows are refused", async () => {
    const { db, stop } = await startLocalD1();
    try {
      // The shape that the runner before checksums created.
      const oldShape =
        "CREATE TABLE identkit_migrations (name TEXT NOT NULL PRIMARY KEY, applied_at INTEGER NOT NULL)";
      await db.prepare(oldShape).run();
      const first = { name: "0001_a.sql", sql: "CREATE TABLE identkit_a (id TEXT);\n" };
      const second = { name: "0002_b.sql", sql: "CREATE TABLE identkit_b (id TEXT);\n" };
      // An empty old table: the column is added and new records carry their checksum.
      expect(await migrateIdentkitD1(db, { migrations: [first] })).toEqual(["0001_a.sql"]);
      const row = await db
        .prepare("SELECT checksum FROM identkit_migrations WHERE name = '0001_a.sql'")
        .first();
      expect(row?.["checksum"]).toMatch(/^[0-9a-f]{64}$/);
      expect(await migrateIdentkitD1(db, { migrations: [first] })).toEqual([]);
      // A row from the old runner has no checksum: refused with a clear message.
      await db
        .prepare("INSERT INTO identkit_migrations (name, applied_at) VALUES ('0002_b.sql', 0)")
        .run();
      await expect(migrateIdentkitD1(db, { migrations: [first, second] })).rejects.toThrow(
        /0002_b\.sql was applied without a checksum/,
      );
    } finally {
      await stop();
    }
  }, 60_000);

  it("storage: times and counters are integers, booleans 0 or 1, lists JSON text", async () => {
    const db = requireDb();
    const s = requireStore();
    const accountId = "d1-types-account";
    await s.accounts.insert({
      id: accountId,
      email: "d1-types@example.org",
      webauthnUserId: "d1-types-wu",
      status: "active",
      createdAt: T0,
      personKeyDigest: null,
      assuranceLevel: null,
      identityVerifiedAt: null,
    });
    await s.credentials.insert({
      id: "d1-types-cred",
      accountId,
      publicKey: new Uint8Array([9, 8, 7]),
      counter: 4_294_967_295,
      transports: ["usb", "nfc"],
      deviceType: "singleDevice",
      backedUp: true,
      createdAt: T0,
      lastUsedAt: null,
      activatedAt: T0,
    });
    const row = await db
      .prepare(
        `SELECT typeof(created_at) AS created, typeof(counter) AS counter,
           typeof(backed_up) AS backed, backed_up, typeof(public_key) AS key, transports
         FROM identkit_credentials WHERE id = 'd1-types-cred'`,
      )
      .first();
    expect(row).toEqual({
      created: "integer",
      counter: "integer",
      backed: "integer",
      backed_up: 1,
      key: "blob",
      transports: '["usb","nfc"]',
    });
    const found = await s.credentials.findById("d1-types-cred");
    expect(found?.createdAt.getTime()).toBe(T0.getTime());
    expect(found?.counter).toBe(4_294_967_295);
    expect(found?.backedUp).toBe(true);
    expect(Array.from(found?.publicKey ?? [])).toEqual([9, 8, 7]);
    expect(found?.transports).toEqual(["usb", "nfc"]);
  });

  it("throttle: when the rounds run out under contention, reserve throws and allows nothing more", async () => {
    const tight = createD1Store(requireDb(), { throttleRetries: 1 });
    const rule = {
      maxFailures: 3,
      windowSeconds: 60,
      maxConsecutiveFailures: 100,
      lockSeconds: 60,
      maxLockSeconds: 60,
    };
    const results = await Promise.allSettled(
      Array.from({ length: 10 }, () => tight.throttle.reserve("d1-contention", T0, rule)),
    );
    const allowed = results.filter((r) => r.status === "fulfilled" && r.value.allowed);
    const contended = results.filter(
      (r) => r.status === "rejected" && r.reason instanceof D1ThrottleContentionError,
    );
    expect(allowed.length).toBeLessThanOrEqual(3);
    expect(contended.length).toBeGreaterThan(0);
    expect(results.every((r) => r.status === "fulfilled" || contended.includes(r))).toBe(true);
    expect(() => createD1Store(requireDb(), { throttleRetries: 0 })).toThrow(RangeError);
  });

  it("enrollment: concurrent issues and revocations leave at most one usable token", async () => {
    const s = requireStore();
    const accountId = "d1-enrollment-account";
    await s.accounts.insert({
      id: accountId,
      email: "d1-enrollment@example.org",
      webauthnUserId: "d1-enrollment-wu",
      status: "active",
      createdAt: T0,
      personKeyDigest: null,
      assuranceLevel: null,
      identityVerifiedAt: null,
    });
    const digests = Array.from({ length: 6 }, (_, i) => `d1-enr-${i}`);
    await Promise.all([
      ...digests.map((digest) =>
        s.enrollment.issue({
          tokenDigest: digest,
          accountId,
          createdAt: T0,
          expiresAt: addSeconds(T0, 600),
          consumedAt: null,
          revokedAt: null,
        }),
      ),
      s.enrollment.revokeAllForAccount(accountId, T0),
      s.enrollment.revokeAllForAccount(accountId, T0),
    ]);
    const usable = await Promise.all(digests.map((d) => s.enrollment.consume(d, T0)));
    expect(usable.filter((r) => r !== null).length).toBeLessThanOrEqual(1);
  });

  it("enrollment: issue is exactly one batch, the revocation of earlier tokens first", async () => {
    // Deterministic guard for the race above: a revocation can run between two separate
    // statements, but not inside one batch.
    const recorded = recordingD1(requireDb());
    const s = createD1Store(recorded.db);
    await s.accounts.insert(accountAt("d1-enrollment-batch"));
    recorded.calls.length = 0;
    await s.enrollment.issue({
      tokenDigest: "d1-enr-batch",
      accountId: "d1-enrollment-batch",
      createdAt: T0,
      expiresAt: addSeconds(T0, 600),
      consumedAt: null,
      revokedAt: null,
    });
    expect(recorded.calls).toHaveLength(1);
    expect(recorded.calls[0]?.kind).toBe("batch");
    expect(recorded.calls[0]?.queries.map((q) => q.split(" ").slice(0, 3).join(" "))).toEqual([
      "UPDATE identkit_enrollment_tokens SET",
      "INSERT INTO identkit_enrollment_tokens",
    ]);
  });

  it("read replication: refuses a D1 session unless the operator states first-primary", async () => {
    const { binding } = requireLocal();
    expect(() => createD1Store(binding.withSession())).toThrow(TypeError);
    expect(() => createD1Store(binding.withSession("first-unconstrained"))).toThrow(
      /withSession\("first-primary"\)/,
    );
    expect(() => createD1Store(binding.withSession("first-primary"))).toThrow(TypeError);
    // The plain binding needs no option.
    expect(() => createD1Store(binding)).not.toThrow();

    const s = createD1Store(binding.withSession("first-primary"), {
      sessionConstraint: "first-primary",
    });
    await s.accounts.insert(accountAt("d1-replica-account"));
    await s.sessions.insert(sessionAt("d1-replica-session", "d1-replica-account"));
    expect(await s.sessions.revoke("d1-replica-session", T0, "sign_out")).toBe(true);
    expect((await requireStore().sessions.findById("d1-replica-session"))?.revokedAt).toEqual(T0);
  });

  it("dates: an invalid Date throws and revokes nothing, as PostgreSQL refuses it", async () => {
    const s = requireStore();
    const invalid = new Date(Number.NaN);
    await s.accounts.insert(accountAt("d1-nan-account"));
    await s.sessions.insert(sessionAt("d1-nan-1", "d1-nan-account"));
    await s.sessions.insert(sessionAt("d1-nan-2", "d1-nan-account"));
    await expect(s.sessions.revoke("d1-nan-1", invalid, "sign_out")).rejects.toThrow(RangeError);
    await expect(
      s.sessions.revokeAllForAccount("d1-nan-account", invalid, "sign_out"),
    ).rejects.toThrow(RangeError);
    await expect(s.enrollment.revokeAllForAccount("d1-nan-account", invalid)).rejects.toThrow(
      RangeError,
    );
    // Nothing was written: both sessions are still live, and a valid revoke still matches.
    expect((await s.sessions.findById("d1-nan-1"))?.revokedAt).toBeNull();
    expect((await s.sessions.findById("d1-nan-2"))?.revokedAt).toBeNull();
    expect(await s.sessions.revoke("d1-nan-1", T0, "sign_out")).toBe(true);
  });

  it("throttle: the worst case of reserve is 2 queries per round, within the Free plan limit", async () => {
    // Every write misses, as if a concurrent call won each round.
    const recorded = recordingD1(requireDb(), {
      missWrite: (query) =>
        /^(UPDATE|INSERT INTO) identkit_throttles /.test(query) && query.includes("RETURNING"),
    });
    const s = createD1Store(recorded.db);
    const rule = {
      maxFailures: 3,
      windowSeconds: 60,
      maxConsecutiveFailures: 100,
      lockSeconds: 60,
      maxLockSeconds: 60,
    };
    await expect(s.throttle.reserve("d1-worst-case", T0, rule)).rejects.toThrow(
      D1ThrottleContentionError,
    );
    expect(recorded.calls).toHaveLength(2 * D1_DEFAULT_THROTTLE_RETRIES);
    expect(recorded.calls.length).toBeLessThanOrEqual(FREE_QUERIES_PER_INVOCATION);
  });

  it("throttle: a service call that reserves stays within the Free plan limit in the worst case", async () => {
    // Counts the queries of the heaviest calls that reserve a throttle, uncontended, and adds
    // the extra rounds that contention can cost (each lost round: 2 queries).
    const recorded = recordingD1(requireDb());
    const t = setup({
      store: createD1Store(recorded.db),
      policy: { ...mfaPolicy, approvalEvidenceLevels: ["signature", "code-confirmation"] },
    });
    // Counts the queries of one call and checks that the call succeeded, so a refused call
    // (fewer queries) cannot pass as a measurement.
    const count = async <R extends { status: string }>(call: () => Promise<R>, status: string) => {
      recorded.calls.length = 0;
      const result = await call();
      expect(result.status).toBe(status);
      return { queries: recorded.calls.length, result };
    };
    const flow = await t.codeFor("d1-budget@example.org");
    const signIn = await count(() => t.ik.emailSignIn.verifyCode(flow), "signed_in");
    const user = await t.signIn("d1-budget-3@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error(start.reason);
    const enrol = await count(
      () =>
        t.ik.totp.confirmEnrolment(user.token, {
          factorId: start.factorId,
          code: t.totpCode(start.secret),
        }),
      "enrolled",
    );
    t.clock.advanceSeconds(60);
    const pendingFlow = await t.codeFor("d1-budget-3@example.org");
    const pending = await t.ik.emailSignIn.verifyCode(pendingFlow);
    if (pending.status !== "second_factor_required") throw new Error(pending.status);
    const second = await count(
      () => t.ik.totp.verifySecondFactor(pending.pendingToken, { code: t.totpCode(start.secret) }),
      "signed_in",
    );
    t.clock.advanceSeconds(60);
    const stepUp = await count(
      () => t.ik.stepUp.verifyTotp(user.token, { code: t.totpCode(start.secret) }),
      "granted",
    );
    if (stepUp.result.status !== "granted") throw new Error(stepUp.result.status);
    // A step-up issues a new session token.
    const token = stepUp.result.token;
    t.clock.advanceSeconds(60);
    const payloadHash = hashPayload("d1-budget-approval");
    const approval = await t.ik.approvals.start({
      sessionToken: token,
      payloadHash,
      levels: ["code-confirmation"],
    });
    if (approval.status !== "ok" || approval.level !== "code-confirmation") {
      throw new Error(`no code confirmation: ${approval.status}`);
    }
    const approve = await count(
      () =>
        t.ik.approvals.verify({
          sessionToken: token,
          payloadHash,
          approvalId: approval.approvalId,
          code: t.totpCode(start.secret),
        }),
      "approved",
    );
    const emailStepUp = await t.ik.stepUp.requestEmailCode(token);
    if (emailStepUp.status !== "sent") throw new Error(emailStepUp.status);
    const stepUpEmail = await count(
      () =>
        t.ik.stepUp.verifyEmailCode(token, {
          flowId: emailStepUp.flowId,
          code: t.mail.last()?.code ?? "",
        }),
      "granted",
    );
    const measured = Object.fromEntries(
      Object.entries({ signIn, enrol, second, stepUp, approve, stepUpEmail }).map(([k, v]) => [
        k,
        v.queries,
      ]),
    );
    // Measured 2026-11-27: sign-in 14, enrolment 17, second factor 12, TOTP step-up 11,
    // approval by code confirmation 13, e-mail code step-up 10 queries.
    const heaviest = Math.max(...Object.values(measured));
    expect(heaviest + 2 * (D1_DEFAULT_THROTTLE_RETRIES - 1)).toBeLessThanOrEqual(
      FREE_QUERIES_PER_INVOCATION,
    );
  });

  it("api tokens: verify is one query, plus one conditional write at most once per interval", async () => {
    const recorded = recordingD1(requireDb());
    const t = setup({
      store: createD1Store(recorded.db),
      apiTokens: { prefix: "pat_", allowedScopes: ["read"] },
    });
    const created = await t.ik.accounts.create({ email: "d1-token-budget@example.org" });
    if (created.status !== "created") throw new Error(created.status);
    const token = await t.ik.apiTokens.create({
      accountId: created.account.id,
      name: "ci",
      scopes: ["read"],
      expiresInDays: 7,
    });
    if (token.status !== "created") throw new Error(token.status);
    const verifyQueries = async () => {
      recorded.calls.length = 0;
      expect((await t.ik.apiTokens.verify(token.token)).status).toBe("valid");
      return recorded.calls.map((c) => c.queries.join("; ").split(" ").slice(0, 2).join(" "));
    };
    expect(await verifyQueries()).toEqual(["SELECT t.id,", "UPDATE identkit_api_tokens"]);
    expect(await verifyQueries()).toEqual(["SELECT t.id,"]);
    t.clock.advanceSeconds(3600);
    expect(await verifyQueries()).toEqual(["SELECT t.id,", "UPDATE identkit_api_tokens"]);
  });
});
