import { splitStatements } from "../sql-statements.js";
import { D1_MIGRATIONS } from "./migrations-sql.js";
import type { D1DatabaseLike } from "./types.js";

/** One D1 migration: the file name in `migrations-d1/` and its SQL. */
export interface D1Migration {
  name: string;
  sql: string;
}

const NAME = /^\d{4}_[a-z0-9_]+\.sql$/;

/** SHA-256 of the migration SQL as hex. Web Crypto, so it runs on Workers and Node. */
async function checksum(sql: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sql));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function refuseChanged(name: string, recorded: unknown, expected: string): void {
  if (recorded !== expected) {
    throw new Error(
      `migration ${name} differs from the applied one: a migration file must not change ` +
        "after it was applied",
    );
  }
}

/**
 * Applies the identkit D1 migrations that are not applied yet, in name order, and returns
 * the names it applied. It records them in `identkit_migrations` with a SHA-256 checksum of
 * their SQL, and throws if an applied migration has a different SQL now. Each migration runs as one
 * `batch()` (one transaction) that first records its name: if a concurrent run applied it
 * first, the name is taken, the batch rolls back, and this run skips it. Works on Workers
 * without a file system. Do not mix it with `wrangler d1 migrations apply` for the same
 * database: each tool keeps its own record.
 */
export async function migrateIdentkitD1(
  db: D1DatabaseLike,
  options: { migrations?: readonly D1Migration[] } = {},
): Promise<string[]> {
  const migrations = (options.migrations ?? D1_MIGRATIONS).toSorted((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  );
  for (const { name } of migrations) {
    if (!NAME.test(name)) throw new Error(`invalid migration name: ${name}`);
  }
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS identkit_migrations (
        name TEXT NOT NULL PRIMARY KEY,
        checksum TEXT NOT NULL,
        applied_at INTEGER NOT NULL
      )`,
    )
    .run();
  const { results } = await db.prepare("SELECT name, checksum FROM identkit_migrations").all();
  const done = new Map(results.map((r) => [r["name"], r["checksum"]]));
  const applied: string[] = [];
  for (const migration of migrations) {
    const sum = await checksum(migration.sql);
    if (done.has(migration.name)) {
      refuseChanged(migration.name, done.get(migration.name), sum);
      continue;
    }
    try {
      await db.batch([
        db
          .prepare(
            "INSERT INTO identkit_migrations (name, checksum, applied_at) VALUES (?1, ?2, ?3)",
          )
          .bind(migration.name, sum, Date.now()),
        ...splitStatements(migration.sql).map((statement) => db.prepare(statement)),
      ]);
    } catch (error) {
      const recorded = await db
        .prepare("SELECT checksum FROM identkit_migrations WHERE name = ?1")
        .bind(migration.name)
        .first();
      if (recorded) {
        refuseChanged(migration.name, recorded["checksum"], sum);
        continue;
      }
      throw error;
    }
    applied.push(migration.name);
  }
  return applied;
}
