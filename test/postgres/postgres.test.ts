/**
 * PostgreSQL tests. They run only when DATABASE_URL points to a throwaway database:
 *
 *   DATABASE_URL=postgres://user:pass@localhost:5432/scratch pnpm test:postgres
 *
 * Each run creates its own schema and drops it at the end.
 */
import { randomBytes } from "node:crypto";
import { Kysely, PostgresDialect, sql } from "kysely";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createPostgresStore,
  migrateIdentkit,
  type IdentkitDatabase,
} from "../../src/postgres/index.js";
import type {
  IdentkitStore,
  OAuthAccessTokenRecord,
  OAuthClientRecord,
  OAuthGrantRecord,
  OidcLinkRecord,
} from "../../src/storage/types.js";
import { setup } from "../helpers.js";
import { runStoreContract } from "../store-contract.js";
import { runStoreFlows } from "../store-flows.js";
import { oauthRowsAfterAccountDelete } from "../oauth-helpers.js";

const url = process.env["DATABASE_URL"];
const schema = `identkit_test_${randomBytes(6).toString("hex")}`;

let db: Kysely<IdentkitDatabase> | undefined;
let store: IdentkitStore | undefined;

function requireStore(): IdentkitStore {
  if (!store) throw new Error("store not initialised");
  return store;
}

const DAY_MS = 86_400_000;

function oauthStore() {
  const oauth = requireStore().oauth;
  if (!oauth) throw new Error("store has no oauth");
  return oauth;
}

const tag = () => randomBytes(6).toString("hex");

/** A connection outside the store's pool, with explicit BEGIN and COMMIT. */
async function connection(): Promise<pg.Client> {
  if (!url) throw new Error("no DATABASE_URL");
  const client = new pg.Client({ connectionString: url, options: `-c search_path=${schema}` });
  await client.connect();
  return client;
}

async function backendPid(client: pg.Client): Promise<number> {
  const { rows } = await client.query<{ pid: number }>("SELECT pg_backend_pid() AS pid");
  const pid = rows[0]?.pid;
  if (pid === undefined) throw new Error("no backend pid");
  return pid;
}

/**
 * Waits until a backend other than those in `except` waits on a lock that one of `by` holds,
 * and returns its pid. Polls pg_blocking_pids, so the test goes on only once the other call is
 * really blocked, not after a guessed sleep.
 */
async function blockedBy(probe: pg.Client, by: number[], except: number[] = []): Promise<number> {
  const deadline = Date.now() + 10_000;
  for (;;) {
    const { rows } = await probe.query<{ pid: number }>(
      "SELECT pid FROM pg_stat_activity WHERE pg_blocking_pids(pid) && $1::int[]",
      [by],
    );
    const found = rows.map((r) => r.pid).find((pid) => !except.includes(pid) && !by.includes(pid));
    if (found !== undefined) return found;
    if (Date.now() > deadline) throw new Error("no call waited on the lock");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

/** Settles a promise into its value or its error, so a test can await it after other steps. */
function settle<T>(promise: Promise<T>): Promise<{ value: T } | { error: unknown }> {
  return promise.then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  );
}

async function lockAccount(id: string) {
  const inserted = await requireStore().accounts.insert({
    id,
    email: `${id}@example.org`,
    webauthnUserId: `wu-${id}`,
    status: "active",
    createdAt: new Date(),
    personKeyDigest: null,
    assuranceLevel: null,
    identityVerifiedAt: null,
  });
  if (inserted !== "inserted") throw new Error(inserted);
  return id;
}

function lockClient(id: string, overrides: Partial<OAuthClientRecord> = {}): OAuthClientRecord {
  return {
    id,
    secretDigest: null,
    secretDigestAlgorithm: null,
    authMethod: "none",
    grantTypes: ["authorization_code", "refresh_token"],
    redirectUris: ["http://127.0.0.1/cb"],
    name: null,
    source: "dynamic",
    createdAt: new Date(Date.now() - 400 * DAY_MS),
    lastUsedAt: new Date(Date.now() - 300 * DAY_MS),
    ...overrides,
  };
}

function lockGrant(accountId: string, clientId: string): OAuthGrantRecord {
  const now = Date.now();
  return {
    id: `grant-${tag()}`,
    accountId,
    clientId,
    scopes: ["mcp:read"],
    resource: "https://example.com/mcp",
    createdAt: new Date(now),
    expiresAt: new Date(now + 90 * DAY_MS),
    generation: 1,
    refreshRefDigest: `ref-${tag()}`,
    refreshDigest: `refresh-${tag()}`,
    refreshDigestAlgorithm: "hmac-sha256",
    previousRefreshDigest: null,
    refreshedAt: null,
    refreshExpiresAt: new Date(now + 30 * DAY_MS),
    codeDigest: null,
    source: "created",
  };
}

function lockToken(grantId: string, digest = `access-${tag()}`): OAuthAccessTokenRecord {
  const now = Date.now();
  return {
    digest,
    grantId,
    generation: 1,
    scopes: ["mcp:read"],
    createdAt: new Date(now),
    expiresAt: new Date(now + 3_600_000),
  };
}

/** Three idle clients in id order; the first holds a live grant. Inserted in reverse. */
async function threeIdleClients() {
  const oauth = oauthStore();
  const prefix = `lockorder-${tag()}`;
  const [busy, first, second] = [0, 1, 2].map((n) => lockClient(`${prefix}-${n}`));
  if (!busy || !first || !second) throw new Error("no clients");
  for (const c of [second, first, busy]) await oauth.insertClient(c);
  const accountId = await lockAccount(`acc-${tag()}`);
  const live = lockGrant(accountId, busy.id);
  await oauth.insertGrant(live, lockToken(live.id), { maxOtherGrants: 10, at: new Date() });
  return { oauth, busy, first, second };
}

/** Purge bounds that make the clients of `lockClient` idle, and no client of the 2030 cases. */
function purgeBounds() {
  const at = new Date();
  return {
    at,
    unusedBefore: new Date(at.getTime() - 30 * DAY_MS),
    idleBefore: new Date(at.getTime() - 180 * DAY_MS),
    windowBefore: new Date(at.getTime() - DAY_MS),
  };
}

/** The ids of these clients in their physical order on disk. */
async function heapOrder(probe: pg.Client, ids: string[]): Promise<string[]> {
  const { rows } = await probe.query<{ id: string }>(
    "SELECT id FROM identkit_oauth_clients WHERE id = ANY($1) ORDER BY ctid",
    [ids],
  );
  return rows.map((r) => r.id);
}

/** The clients that a purge with these bounds selects, by the purge rule, in id order. */
async function purgeCandidates(
  probe: pg.Client,
  b: { at: Date; unusedBefore: Date; idleBefore: Date },
): Promise<string[]> {
  const { rows } = await probe.query<{ id: string }>(
    `SELECT c.id FROM identkit_oauth_clients c
     WHERE ((c.last_used_at IS NULL AND c.created_at < $1) OR c.last_used_at < $2)
       AND NOT EXISTS (SELECT 1 FROM identkit_oauth_grants g
                       WHERE g.client_id = c.id AND g.expires_at > $3)
       AND NOT EXISTS (SELECT 1 FROM identkit_oauth_codes o
                       WHERE o.client_id = c.id AND o.expires_at > $3)
     ORDER BY c.id`,
    [b.unusedBefore, b.idleBefore, b.at],
  );
  return rows.map((r) => r.id);
}

/**
 * A second store on its own pool whose sessions use the planner settings, for example to force
 * a scan order. The caller destroys the returned database.
 */
function plannedStore(settings: string) {
  if (!url) throw new Error("no DATABASE_URL");
  const planned = new Kysely<IdentkitDatabase>({
    dialect: new PostgresDialect({
      pool: new pg.Pool({
        connectionString: url,
        max: 2,
        options: `-c search_path=${schema} ${settings}`,
      }),
    }),
  });
  const oauth = createPostgresStore(planned).oauth;
  if (!oauth) throw new Error("store has no oauth");
  return { planned, oauth };
}

/** Waits until the backend waits on a lock and `accept` takes the pids that block it. */
async function blockersOf(
  probe: pg.Client,
  pid: number,
  accept: (blockers: number[]) => boolean,
): Promise<number[]> {
  const deadline = Date.now() + 10_000;
  for (;;) {
    const { rows } = await probe.query<{ blockers: number[] }>(
      "SELECT pg_blocking_pids($1) AS blockers",
      [pid],
    );
    const blockers = rows[0]?.blockers ?? [];
    if (blockers.length > 0 && accept(blockers)) return blockers;
    if (Date.now() > deadline) throw new Error(`backend ${pid} did not reach the expected wait`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

describe.skipIf(!url)("postgresql", () => {
  beforeAll(async () => {
    const admin = new pg.Client({ connectionString: url });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.end();
    db = new Kysely<IdentkitDatabase>({
      dialect: new PostgresDialect({
        pool: new pg.Pool({ connectionString: url, max: 10, options: `-c search_path=${schema}` }),
      }),
    });
    const applied = await migrateIdentkit(db);
    expect(applied).toEqual([
      "0001_initial.sql",
      "0002_totp.sql",
      "0003_lockout_and_enrollment_revocation.sql",
      "0004_oidc_links.sql",
      "0005_api_tokens.sql",
      "0006_oauth.sql",
    ]);
    expect(await migrateIdentkit(db)).toEqual([]);
    store = createPostgresStore(db);
  });

  afterAll(async () => {
    if (db) {
      await sql.raw(`DROP SCHEMA ${schema} CASCADE`).execute(db);
      await db.destroy();
    }
  });

  runStoreContract("postgresql", () => requireStore());
  runStoreFlows("postgresql", requireStore);

  it("oauth row 28: deleting an account row removes its grants, access tokens and codes", async () => {
    if (!db) throw new Error("database not initialised");
    const k = db;
    const result = await oauthRowsAfterAccountDelete(
      requireStore(),
      async (accountId) => {
        await k.deleteFrom("identkit_accounts").where("id", "=", accountId).execute();
      },
      async (table, column, value) => {
        const { rows } = await sql<{ n: string }>`
          SELECT count(*) AS n FROM ${sql.table(table)} WHERE ${sql.ref(column)} = ${value}`.execute(
          k,
        );
        return Number(rows[0]?.n);
      },
    );
    // The control: the rows exist before the delete.
    expect(result.before).toEqual({ grants: 1, accessTokens: 1, codes: 1 });
    expect(result.after).toEqual({ grants: 0, accessTokens: 0, codes: 0 });
    // The client belongs to no account and stays.
    expect(result.client).not.toBeNull();
  });

  // Each case waits for a real lock; the timeout leaves room for blockedBy's own deadline.
  describe("oauth lock order with real transactions", { timeout: 20_000 }, () => {
    it("deleteClient against a replacing insertGrant: no deadlock, the insert fails on the client", async () => {
      // 2462828: insertGrant locks the client before it deletes the grant it replaces. Without
      // that, it would hold the old grant's row lock while its foreign key check waits on the
      // client, and deleteClient would wait on the old grant: a deadlock.
      const oauth = oauthStore();
      const accountId = await lockAccount(`acc-${tag()}`);
      const client = lockClient(`client-${tag()}`);
      expect(await oauth.insertClient(client)).toBe("inserted");
      const old = lockGrant(accountId, client.id);
      await oauth.insertGrant(old, lockToken(old.id), { maxOtherGrants: 10, at: new Date() });
      const holder = await connection();
      const probe = await connection();
      try {
        // deleteClient's first step: the client row FOR UPDATE.
        await holder.query("BEGIN ISOLATION LEVEL READ COMMITTED");
        await holder.query("SELECT id FROM identkit_oauth_clients WHERE id = $1 FOR UPDATE", [
          client.id,
        ]);
        const replacing = lockGrant(accountId, client.id);
        const inserting = settle(
          oauth.insertGrant(replacing, lockToken(replacing.id), {
            maxOtherGrants: 10,
            at: new Date(),
          }),
        );
        await blockedBy(probe, [await backendPid(holder)]);
        // deleteClient's next steps: the client's grants, then the client. With the fix the
        // insert holds no grant row lock, so these do not wait.
        await holder.query("DELETE FROM identkit_oauth_grants WHERE client_id = $1", [client.id]);
        await holder.query("DELETE FROM identkit_oauth_clients WHERE id = $1", [client.id]);
        await holder.query("COMMIT");
        const result = await inserting;
        expect(result).toMatchObject({
          error: expect.objectContaining({
            message: "oauth grant references a missing client",
          }),
        });
        const { rows } = await probe.query(
          "SELECT id FROM identkit_oauth_grants WHERE client_id = $1",
          [client.id],
        );
        expect(rows).toEqual([]);
      } finally {
        await holder.query("ROLLBACK").catch(() => undefined);
        await holder.end();
        await probe.end();
      }
    });

    it("purge against a grant insert that commits during the wait keeps the client and the grant", async () => {
      // ff326f6: the candidate lock waits on the insert's key share lock on the client, and the
      // delete is a second statement whose snapshot sees the committed grant. A single DELETE
      // would cascade it.
      const oauth = oauthStore();
      const accountId = await lockAccount(`acc-${tag()}`);
      const other = await lockAccount(`acc-${tag()}`);
      const idle = lockClient(`client-${tag()}`);
      const elsewhere = lockClient(`client-${tag()}`, { lastUsedAt: new Date() });
      await oauth.insertClient(idle);
      await oauth.insertClient(elsewhere);
      const parked = lockGrant(other, elsewhere.id);
      await oauth.insertGrant(parked, lockToken(parked.id), {
        maxOtherGrants: 10,
        at: new Date(),
      });
      const holder = await connection();
      const probe = await connection();
      try {
        // Parks the insert below on its access token: this uncommitted row has the same digest.
        const digest = `access-${tag()}`;
        await holder.query("BEGIN ISOLATION LEVEL READ COMMITTED");
        await holder.query(
          `INSERT INTO identkit_oauth_access_tokens
             (digest, grant_id, generation, scopes, created_at, expires_at)
           VALUES ($1, $2, 1, '{mcp:read}', now(), now() + interval '1 hour')`,
          [digest, parked.id],
        );
        const holderPid = await backendPid(holder);
        const grant = lockGrant(accountId, idle.id);
        const inserting = settle(
          oauth.insertGrant(grant, lockToken(grant.id, digest), {
            maxOtherGrants: 10,
            at: new Date(),
          }),
        );
        // The insert holds the account and client locks and waits on the token digest.
        const insertPid = await blockedBy(probe, [holderPid]);
        const purging = settle(oauth.purge(purgeBounds()));
        await blockedBy(probe, [insertPid], [holderPid]);
        await holder.query("ROLLBACK");
        expect(await inserting).toMatchObject({ value: { status: "inserted" } });
        const purged = await purging;
        if (!("value" in purged)) throw purged.error;
        expect(purged.value.clients.map((c) => c.id)).not.toContain(idle.id);
        expect(await oauth.findClient(idle.id)).not.toBeNull();
        expect(await oauth.findGrant(grant.id)).not.toBeNull();
      } finally {
        await holder.query("ROLLBACK").catch(() => undefined);
        await holder.end();
        await probe.end();
      }
    });

    it("purge against an approval's last-use write keeps the client", async () => {
      // The candidate lock waits on the row lock of the last-use write. This fails only if no
      // statement checks the date rule again after that wait, for example a delete by id alone
      // after an unlocked candidate read.
      const oauth = oauthStore();
      const idle = lockClient(`client-${tag()}`);
      await oauth.insertClient(idle);
      const holder = await connection();
      const probe = await connection();
      try {
        await holder.query("BEGIN ISOLATION LEVEL READ COMMITTED");
        await holder.query("UPDATE identkit_oauth_clients SET last_used_at = now() WHERE id = $1", [
          idle.id,
        ]);
        const purging = settle(oauth.purge(purgeBounds()));
        await blockedBy(probe, [await backendPid(holder)]);
        await holder.query("COMMIT");
        const purged = await purging;
        if (!("value" in purged)) throw purged.error;
        expect(purged.value.clients.map((c) => c.id)).not.toContain(idle.id);
        expect(await oauth.findClient(idle.id)).not.toBeNull();
      } finally {
        await holder.query("ROLLBACK").catch(() => undefined);
        await holder.end();
        await probe.end();
      }
    });

    it("purge locks only clients without a live grant or code, in id order", async () => {
      const { oauth, busy, first, second } = await threeIdleClients();
      const holder = await connection();
      const probe = await connection();
      try {
        // The order half needs `second` before `first` on disk, so that a scan without the
        // id order would lock `second` first.
        expect(await heapOrder(probe, [first.id, second.id])).toEqual([second.id, first.id]);
        await holder.query("BEGIN ISOLATION LEVEL READ COMMITTED");
        await holder.query("SELECT id FROM identkit_oauth_clients WHERE id = $1 FOR UPDATE", [
          first.id,
        ]);
        const purging = settle(oauth.purge(purgeBounds()));
        await blockedBy(probe, [await backendPid(holder)]);
        // The purge waits at `first`. It never locked the busy client, which sorts before it,
        // and not yet the second, which sorts after it (and lies first on disk).
        await probe.query("BEGIN");
        for (const c of [busy, second]) {
          await expect(
            probe.query("SELECT id FROM identkit_oauth_clients WHERE id = $1 FOR UPDATE NOWAIT", [
              c.id,
            ]),
            c.id,
          ).resolves.toMatchObject({ rowCount: 1 });
        }
        await probe.query("ROLLBACK");
        await holder.query("COMMIT");
        const purged = await purging;
        if (!("value" in purged)) throw purged.error;
        const mine = purged.value.clients
          .map((c) => c.id)
          .filter((id) => id.startsWith(first.id.slice(0, -2)));
        expect(mine.toSorted()).toEqual([first.id, second.id]);
        expect(await oauth.findClient(busy.id)).not.toBeNull();
      } finally {
        await probe.query("ROLLBACK").catch(() => undefined);
        await holder.query("ROLLBACK").catch(() => undefined);
        await holder.end();
        await probe.end();
      }
    });

    it("two overlapping purges that scan in opposite orders lock in id order and never deadlock", async () => {
      // One purge scans the clients in heap order (`second` first), the other by primary key
      // (`first` first). Only the id order of the candidate lock keeps them from a cycle:
      // without it, each holds the client that the other waits for, and one fails with 40P01.
      const { busy, first, second } = await threeIdleClients();
      const heap = plannedStore(
        "-c enable_indexscan=off -c enable_indexonlyscan=off -c enable_bitmapscan=off " +
          "-c enable_hashjoin=off -c enable_mergejoin=off",
      );
      const byKey = plannedStore(
        "-c enable_seqscan=off -c enable_bitmapscan=off " +
          "-c enable_hashjoin=off -c enable_mergejoin=off",
      );
      const holdFirst = await connection();
      const holdSecond = await connection();
      const probe = await connection();
      try {
        const bounds = purgeBounds();
        expect(await heapOrder(probe, [first.id, second.id])).toEqual([second.id, first.id]);
        // No other client would take part in the lock order.
        expect(await purgeCandidates(probe, bounds)).toEqual([first.id, second.id]);
        for (const [held, c] of [
          [holdFirst, first],
          [holdSecond, second],
        ] as const) {
          await held.query("BEGIN ISOLATION LEVEL READ COMMITTED");
          await held.query("SELECT id FROM identkit_oauth_clients WHERE id = $1 FOR UPDATE", [
            c.id,
          ]);
        }
        const firstPid = await backendPid(holdFirst);
        const secondPid = await backendPid(holdSecond);
        const one = settle(heap.oauth.purge(bounds));
        const onePid = await blockedBy(probe, [firstPid, secondPid]);
        const two = settle(byKey.oauth.purge(bounds));
        const twoPid = await blockedBy(probe, [firstPid, secondPid, onePid], [onePid]);
        await holdFirst.query("COMMIT");
        // Wait until the second purge waits on something other than the holder of `first`:
        // with the id order on the first purge, without it on the client `second`, after it
        // locked `first`. Only then the holder of `second` lets the first purge go on.
        await blockersOf(probe, twoPid, (blockers) => !blockers.includes(firstPid));
        await holdSecond.query("COMMIT");
        const results = [await one, await two];
        const prefix = first.id.slice(0, -2);
        const deleted: string[] = [];
        for (const result of results) {
          if (!("value" in result)) throw result.error;
          deleted.push(
            ...result.value.clients.map((c) => c.id).filter((id) => id.startsWith(prefix)),
          );
        }
        expect(deleted.toSorted()).toEqual([first.id, second.id]);
        expect(await oauthStore().findClient(busy.id)).not.toBeNull();
      } finally {
        for (const held of [holdFirst, holdSecond]) {
          await held.query("ROLLBACK").catch(() => undefined);
          await held.end();
        }
        await probe.end();
        await heap.planned.destroy();
        await byKey.planned.destroy();
      }
    });
  });

  it("enrollment: revokeAllForAccount waits for the account row lock that issue takes", async () => {
    const database = db;
    if (!database) throw new Error("database not initialised");
    const t = setup({ store: requireStore() });
    const created = await t.ik.accounts.create({ email: "pg-enrollment@example.org" });
    if (created.status !== "created") throw new Error("not created");
    const accountId = created.account.id;
    const at = t.clock.now();

    // A transaction that holds the account row lock, as a running `issue` does, and inserts a
    // token only after the revocation started.
    let lockTaken!: () => void;
    const locked = new Promise<void>((resolve) => (lockTaken = resolve));
    let release!: () => void;
    const released = new Promise<void>((resolve) => (release = resolve));
    const holder = database.transaction().execute(async (trx) => {
      await trx
        .selectFrom("identkit_accounts")
        .select("id")
        .where("id", "=", accountId)
        .forUpdate()
        .executeTakeFirst();
      lockTaken();
      await released;
      await trx
        .insertInto("identkit_enrollment_tokens")
        .values({
          token_digest: `pg-lock-${randomBytes(8).toString("hex")}`,
          account_id: accountId,
          created_at: at,
          expires_at: new Date(at.getTime() + 60_000),
          consumed_at: null,
          revoked_at: null,
        })
        .execute();
    });
    await locked;

    let settled = false;
    const revoking = requireStore()
      .enrollment.revokeAllForAccount(accountId, at)
      .then((count) => {
        settled = true;
        return count;
      });
    try {
      await new Promise((resolve) => setTimeout(resolve, 300));
      // Without the row lock the revocation would finish now and miss the token below.
      expect(settled).toBe(false);
    } finally {
      // Never leave the transaction open: it would block the schema drop.
      release();
      await holder;
    }
    expect(await revoking).toBe(1);
  });
  it("oidc links: exclusive inserts keep one link per account under a REPEATABLE READ default", async () => {
    if (!url) throw new Error("no DATABASE_URL");
    // A pool whose sessions default to REPEATABLE READ, as a role or database setting can do.
    const pool = new pg.Pool({
      connectionString: url,
      max: 4,
      options: `-c search_path=${schema}`,
    });
    pool.on("connect", (client) => {
      void client.query("SET default_transaction_isolation = 'repeatable read'");
    });
    const rr = new Kysely<IdentkitDatabase>({ dialect: new PostgresDialect({ pool }) });
    try {
      const shown = await sql<{
        default_transaction_isolation: string;
      }>`SHOW default_transaction_isolation`.execute(rr);
      expect(shown.rows[0]?.default_transaction_isolation).toBe("repeatable read");
      const rrStore = createPostgresStore(rr);
      const links = rrStore.oidcLinks;
      if (!links) throw new Error("store has no oidcLinks");
      const t = setup({ store: requireStore() });
      const created = await t.ik.accounts.create({ email: "pg-oidc-rr@example.org" });
      if (created.status !== "created") throw new Error("not created");
      const accountId = created.account.id;
      const link = (n: number): OidcLinkRecord => ({
        id: `pg-rr-link-${n}-${randomBytes(4).toString("hex")}`,
        accountId,
        linkKey: JSON.stringify(["google", `pg-rr-${n}-${randomBytes(4).toString("hex")}`]),
        provider: "google",
        issuer: "https://accounts.google.com",
        subject: `pg-rr-${n}`,
        tenantId: null,
        source: "sign_in",
        createdAt: new Date(),
      });

      // Hold the account row lock, so both inserts take their snapshot before either commits.
      let release!: () => void;
      const released = new Promise<void>((resolve) => (release = resolve));
      let lockTaken!: () => void;
      const locked = new Promise<void>((resolve) => (lockTaken = resolve));
      const holder = rr.transaction().execute(async (trx) => {
        await trx
          .selectFrom("identkit_accounts")
          .select("id")
          .where("id", "=", accountId)
          .forUpdate()
          .executeTakeFirst();
        lockTaken();
        await released;
      });
      await locked;
      const inserts = [1, 2].map((n) => links.insert(link(n), { exclusive: true }));
      await new Promise((resolve) => setTimeout(resolve, 300));
      release();
      await holder;
      const results = await Promise.all(inserts);
      expect(results.toSorted()).toEqual(["account_has_link", "inserted"]);
      expect(await links.listByAccount(accountId)).toHaveLength(1);
    } finally {
      await rr.destroy();
    }
  });
});
