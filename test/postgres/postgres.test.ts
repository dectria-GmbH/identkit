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
import type { IdentkitStore, OidcLinkRecord } from "../../src/storage/types.js";
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
