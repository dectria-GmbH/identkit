/**
 * PostgreSQL store behaviour that needs no database: a Kysely instance whose driver records the
 * compiled SQL and answers with a given result or error. The full PostgreSQL suite
 * (postgres.test.ts) runs only with DATABASE_URL.
 */
import {
  Kysely,
  PostgresAdapter,
  PostgresIntrospector,
  PostgresQueryCompiler,
  type CompiledQuery,
  type DatabaseConnection,
  type Driver,
  type QueryResult,
} from "kysely";
import { describe, expect, it } from "vitest";
import { createPostgresStore, type IdentkitDatabase } from "../../src/postgres/index.js";
import type {
  ApiTokenRecord,
  OAuthAccessTokenRecord,
  OAuthGrantRecord,
} from "../../src/storage/types.js";

type Answer = (query: CompiledQuery) => QueryResult<unknown> | Error;

function scriptedStore(answer: Answer) {
  const sqls: string[] = [];
  /** The transaction steps the driver saw, in order, among the statements in `sqls`. */
  const steps: string[] = [];
  const connection: DatabaseConnection = {
    executeQuery<R>(query: CompiledQuery): Promise<QueryResult<R>> {
      sqls.push(query.sql);
      steps.push(query.sql);
      const result = answer(query);
      return result instanceof Error
        ? Promise.reject(result)
        : Promise.resolve(result as QueryResult<R>);
    },
    // oxlint-disable-next-line require-yield
    async *streamQuery() {
      throw new Error("not used");
    },
  };
  const driver: Driver = {
    init: async () => undefined,
    acquireConnection: async () => connection,
    beginTransaction: async () => void steps.push("BEGIN"),
    commitTransaction: async () => void steps.push("COMMIT"),
    rollbackTransaction: async () => void steps.push("ROLLBACK"),
    releaseConnection: async () => undefined,
    destroy: async () => undefined,
  };
  const db = new Kysely<IdentkitDatabase>({
    dialect: {
      createAdapter: () => new PostgresAdapter(),
      createDriver: () => driver,
      createQueryCompiler: () => new PostgresQueryCompiler(),
      createIntrospector: (k) => new PostgresIntrospector(k),
    },
  });
  const store = createPostgresStore(db);
  const tokens = store.apiTokens;
  const oauth = store.oauth;
  if (!tokens || !oauth) throw new Error("the PostgreSQL store has apiTokens and oauth");
  return { tokens, oauth, sqls, steps };
}

const sqlError = (code: string) => Object.assign(new Error(`sqlstate ${code}`), { code });

/** Answers of an active account, an existing client and no grants. */
const grantAnswer = (query: CompiledQuery): QueryResult<unknown> => {
  if (query.sql.includes('from "identkit_accounts"')) return { rows: [{ status: "active" }] };
  if (query.sql.includes('from "identkit_oauth_clients"')) return { rows: [{ id: "c1" }] };
  if (query.sql.includes("count(*)")) return { rows: [{ live: "0" }] };
  if (query.sql.startsWith("insert")) return { rows: [{ id: "g1" }] };
  return { rows: [] };
};

describe("postgresql store without a database", () => {
  it("rule: markUsed treats a serialization failure or deadlock as a lost race", async () => {
    for (const code of ["40001", "40P01"]) {
      const { tokens } = scriptedStore(() => sqlError(code));
      expect(await tokens.markUsed("t1", new Date(), new Date()), code).toBe(false);
    }
    // Every other error still goes up.
    const { tokens } = scriptedStore(() => sqlError("57P01"));
    await expect(tokens.markUsed("t1", new Date(), new Date())).rejects.toThrow("sqlstate 57P01");
    const won = scriptedStore(() => ({ rows: [{ id: "t1" }] }));
    expect(await won.tokens.markUsed("t1", new Date(), new Date())).toBe(true);
  });

  it("rule: insert locks the account row FOR NO KEY UPDATE before the count", async () => {
    const { tokens, sqls } = scriptedStore((query) => {
      if (query.sql.includes("count(*)")) return { rows: [{ active: "0" }] };
      if (query.sql.startsWith("insert")) return { rows: [{ id: "t1" }] };
      return { rows: [] };
    });
    const at = new Date();
    const record: ApiTokenRecord = {
      id: "t1",
      accountId: "a1",
      name: "n",
      scopes: ["s"],
      digest: "d",
      digestAlgorithm: "hmac-sha256",
      source: "created",
      createdAt: at,
      expiresAt: at,
      lastUsedAt: null,
      revokedAt: null,
      revokeReason: null,
    };
    expect(await tokens.insert(record, { maxActive: 5, at })).toBe("inserted");
    const lock = sqls.findIndex((s) => s.includes('from "identkit_accounts"'));
    const count = sqls.findIndex((s) => s.includes("count(*)"));
    expect(sqls[lock]).toMatch(/ for no key update$/);
    expect(lock).toBeGreaterThanOrEqual(0);
    expect(lock).toBeLessThan(count);
  });

  it("rule: deleteGrantsForAccount deletes grants and codes in one transaction", async () => {
    const grantRow = {
      id: "g1",
      account_id: "a1",
      client_id: "c1",
      scopes: ["mcp:read"],
      resource: "https://example.com/mcp",
      created_at: new Date(0),
      expires_at: new Date(1),
      generation: 1,
      refresh_ref_digest: null,
      refresh_digest: null,
      refresh_digest_algorithm: null,
      previous_refresh_digest: null,
      refreshed_at: null,
      refresh_expires_at: null,
      code_digest: null,
      source: "created",
    };
    const { oauth, steps } = scriptedStore((query) => {
      if (query.sql.includes('delete from "identkit_oauth_codes"')) return sqlError("57P01");
      return { rows: [grantRow] };
    });
    // Review a2 r1 L5: the grant delete committed on its own, so a failed code delete lost the
    // ended grants for good.
    await expect(oauth.deleteGrantsForAccount("a1")).rejects.toThrow("sqlstate 57P01");
    expect(steps.map((s) => (s.startsWith("delete from") ? s.split(" ")[2] : s))).toEqual([
      "BEGIN",
      '"identkit_oauth_grants"',
      '"identkit_oauth_codes"',
      "ROLLBACK",
    ]);
  });

  it("rule: insertGrant and importGrant lock the account, then the client, before any grant row", async () => {
    const at = new Date();
    const grant: OAuthGrantRecord = {
      id: "g1",
      accountId: "a1",
      clientId: "c1",
      scopes: ["mcp:read"],
      resource: "https://example.com/mcp",
      createdAt: at,
      expiresAt: new Date(at.getTime() + 60_000),
      generation: 1,
      refreshRefDigest: null,
      refreshDigest: null,
      refreshDigestAlgorithm: null,
      previousRefreshDigest: null,
      refreshedAt: null,
      refreshExpiresAt: null,
      codeDigest: null,
      source: "import",
    };
    const token: OAuthAccessTokenRecord = {
      digest: "d",
      grantId: "g1",
      generation: 1,
      scopes: ["mcp:read"],
      createdAt: at,
      expiresAt: grant.expiresAt,
    };
    // Review a2 r2 L1: the client row was locked only by the foreign key check of the insert,
    // after a replacing insert held its grant row lock, so deleteClient could deadlock with it.
    const calls = [
      (s: ReturnType<typeof scriptedStore>) =>
        s.oauth.insertGrant(grant, token, { maxOtherGrants: 5, at }),
      (s: ReturnType<typeof scriptedStore>) =>
        s.oauth.importGrant(grant, { maxOtherGrants: 5, at }),
    ];
    for (const call of calls) {
      const scripted = scriptedStore(grantAnswer);
      await call(scripted);
      const { sqls } = scripted;
      const account = sqls.findIndex((q) => q.includes('from "identkit_accounts"'));
      const client = sqls.findIndex((q) => q.includes('from "identkit_oauth_clients"'));
      const firstGrant = sqls.findIndex((q) => q.includes('"identkit_oauth_grants"'));
      expect(sqls[account]).toMatch(/ for no key update$/);
      expect(sqls[client]).toMatch(/ for key share$/);
      expect(account).toBeGreaterThanOrEqual(0);
      expect(client).toBeGreaterThan(account);
      expect(firstGrant).toBeGreaterThan(client);
    }
    // A missing client fails before any grant row is touched, as the foreign key would.
    const missing = scriptedStore((query) =>
      query.sql.includes('from "identkit_oauth_clients"') ? { rows: [] } : grantAnswer(query),
    );
    await expect(
      missing.oauth.insertGrant(grant, token, { maxOtherGrants: 5, at }),
    ).rejects.toThrow("oauth grant references a missing client");
    expect(missing.sqls.some((q) => q.includes('"identkit_oauth_grants"'))).toBe(false);
  });
});
