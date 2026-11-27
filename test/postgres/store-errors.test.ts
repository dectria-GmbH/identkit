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
import type { ApiTokenRecord } from "../../src/storage/types.js";

type Answer = (query: CompiledQuery) => QueryResult<unknown> | Error;

function scriptedStore(answer: Answer) {
  const sqls: string[] = [];
  const connection: DatabaseConnection = {
    executeQuery<R>(query: CompiledQuery): Promise<QueryResult<R>> {
      sqls.push(query.sql);
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
    beginTransaction: async () => undefined,
    commitTransaction: async () => undefined,
    rollbackTransaction: async () => undefined,
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
  const tokens = createPostgresStore(db).apiTokens;
  if (!tokens) throw new Error("the PostgreSQL store has apiTokens");
  return { tokens, sqls };
}

const sqlError = (code: string) => Object.assign(new Error(`sqlstate ${code}`), { code });

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
});
