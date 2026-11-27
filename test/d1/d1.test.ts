/**
 * D1 store tests against a local D1 database (miniflare). They need no account and no
 * network: pnpm test:d1
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { addSeconds } from "../../src/clock.js";
import {
  createD1Store,
  D1_MIGRATIONS,
  D1ThrottleContentionError,
  migrateIdentkitD1,
  type D1DatabaseLike,
} from "../../src/d1/index.js";
import type { IdentkitStore } from "../../src/storage/types.js";
import { runStoreContract } from "../store-contract.js";
import { runStoreFlows } from "../store-flows.js";
import { startLocalD1 } from "./local-d1.js";

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
});
