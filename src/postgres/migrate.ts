import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { sql, type Kysely } from "kysely";
import { splitStatements } from "../sql-statements.js";
import type { IdentkitDatabase } from "./schema.js";

export { splitStatements };

/** Folder with the plain SQL migrations that ship with the package. */
export const MIGRATIONS_DIR = fileURLToPath(new URL("../../migrations/", import.meta.url));

/** Arbitrary constant that serializes concurrent migration runs. */
const MIGRATION_LOCK_KEY = 4_873_210_771;

/**
 * Applies the identkit SQL migrations that are not applied yet, each in its own
 * transaction, in file name order. Run it with a role that may create tables, not with the
 * runtime role. Consumers with their own migration tool can apply the files in
 * `MIGRATIONS_DIR` instead.
 */
export async function migrateIdentkit(
  db: Kysely<IdentkitDatabase>,
  options: { directory?: string } = {},
): Promise<string[]> {
  const directory = options.directory ?? MIGRATIONS_DIR;
  const files = (await readdir(directory))
    .filter((f) => /^\d{4}_[a-z0-9_]+\.sql$/.test(f))
    .toSorted();
  const applied: string[] = [];

  await sql`CREATE TABLE IF NOT EXISTS identkit_migrations (
    name text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
  )`.execute(db);

  for (const name of files) {
    const text = await readFile(join(directory, name), "utf8");
    const done = await db.transaction().execute(async (trx) => {
      await sql`SELECT pg_advisory_xact_lock(${MIGRATION_LOCK_KEY})`.execute(trx);
      const existing = await trx
        .selectFrom("identkit_migrations")
        .select("name")
        .where("name", "=", name)
        .executeTakeFirst();
      if (existing) return false;
      for (const statement of splitStatements(text)) {
        await sql.raw(statement).execute(trx);
      }
      await trx
        .insertInto("identkit_migrations")
        .values({ name, applied_at: new Date() })
        .execute();
      return true;
    });
    if (done) applied.push(name);
  }
  return applied;
}
