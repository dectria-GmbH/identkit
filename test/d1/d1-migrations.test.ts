import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { D1_MIGRATIONS } from "../../src/d1/index.js";
import { splitStatements } from "../../src/sql-statements.js";

const directory = fileURLToPath(new URL("../../migrations-d1/", import.meta.url));

const TABLE = /^CREATE TABLE (?:IF NOT EXISTS )?(IDENTKIT_\w+)[ (]/;
const INDEX = /^CREATE (UNIQUE )?INDEX (?:IF NOT EXISTS )?IDENTKIT_\w+ ON (IDENTKIT_\w+)[ (]/;

/**
 * The rule for every D1 migration after the first: additive only, so the previous Worker
 * version runs on the new schema. Only these statements pass: `CREATE TABLE identkit_*`,
 * `CREATE [UNIQUE] INDEX identkit_* ON identkit_*`, `ALTER TABLE identkit_* ADD COLUMN` (a
 * NOT NULL column only with a DEFAULT), and `UPDATE` or `INSERT INTO` an identkit_ table. A
 * UNIQUE index passes only on a table that the same migration creates: on an existing table it
 * can fail on existing rows or make the writes of the previous Worker version fail. Triggers,
 * views and every object of the application fail. Returns the statements that break the rule.
 */
function nonAdditive(sql: string): string[] {
  const statements = splitStatements(sql).map((st) => st.replace(/\s+/g, " ").toUpperCase());
  const created = new Set(statements.flatMap((st) => TABLE.exec(st)?.[1] ?? []));
  return splitStatements(sql).filter((_, i) => {
    const s = statements[i] ?? "";
    if (/\bDROP\b/.test(s) || /\bRENAME\b/.test(s)) return true;
    if (TABLE.test(s)) return false;
    const index = INDEX.exec(s);
    if (index) return index[1] !== undefined && index[2] !== undefined && !created.has(index[2]);
    if (/^ALTER TABLE IDENTKIT_\w+ ADD COLUMN /.test(s)) {
      return /\bNOT NULL\b/.test(s) && !/\bDEFAULT\b/.test(s);
    }
    return !/^(UPDATE IDENTKIT_\w+ |INSERT INTO IDENTKIT_\w+[ (])/.test(s);
  });
}

/** The first migration may create only identkit_ tables and identkit_ indexes on them. */
const firstMigrationAllows = (statement: string) =>
  /^CREATE TABLE identkit_\w+ \(/.test(statement) ||
  /^CREATE (UNIQUE )?INDEX identkit_\w+ ON identkit_\w+ \(/.test(statement);

describe("d1 migrations", () => {
  const files = readdirSync(directory)
    .filter((f) => /^\d{4}_[a-z0-9_]+\.sql$/.test(f))
    .toSorted();

  it("the D1 entry carries exactly the files in migrations-d1/ (pnpm generate:d1-migrations)", () => {
    expect(D1_MIGRATIONS.map((m) => m.name)).toEqual(files);
    for (const migration of D1_MIGRATIONS) {
      expect(migration.sql).toBe(readFileSync(`${directory}${migration.name}`, "utf8"));
    }
  });

  it("every migration after the first is additive", () => {
    for (const name of files.slice(1)) {
      expect({ name, broken: nonAdditive(readFileSync(`${directory}${name}`, "utf8")) }).toEqual({
        name,
        broken: [],
      });
    }
  });

  it("the additive check flags drops, renames, triggers, views, foreign objects and a late unique index", () => {
    expect(
      nonAdditive(
        [
          "ALTER TABLE identkit_sessions ADD COLUMN note TEXT;",
          "ALTER TABLE identkit_sessions ADD COLUMN level INTEGER NOT NULL DEFAULT 0;",
          "CREATE INDEX identkit_sessions_note_idx ON identkit_sessions (note);",
          "CREATE TABLE identkit_new (id TEXT PRIMARY KEY);",
          "CREATE UNIQUE INDEX identkit_new_id_idx ON identkit_new (id);",
          "INSERT INTO identkit_new (id) VALUES ('x');",
          "UPDATE identkit_new SET id = id;",
        ].join("\n"),
      ),
    ).toEqual([]);
    const bad = [
      "DROP TABLE identkit_challenges;",
      "ALTER TABLE identkit_sessions DROP COLUMN revoke_reason;",
      "ALTER TABLE identkit_sessions RENAME COLUMN state TO phase;",
      "ALTER TABLE identkit_sessions ADD COLUMN level INTEGER NOT NULL;",
      "CREATE TABLE users (id TEXT);",
      "CREATE INDEX users_idx ON identkit_sessions (id);",
      "DELETE FROM identkit_sessions;",
      "CREATE TRIGGER identkit_t AFTER INSERT ON users BEGIN SELECT 1; END;",
      "CREATE TRIGGER identkit_t2 AFTER INSERT ON identkit_sessions BEGIN SELECT 1; END;",
      "CREATE VIEW users_v AS SELECT * FROM users;",
      "CREATE VIEW identkit_v AS SELECT * FROM identkit_sessions;",
      "CREATE INDEX identkit_x ON users (email);",
      "CREATE UNIQUE INDEX identkit_sessions_digest_idx ON identkit_sessions (token_digest);",
      "UPDATE users SET email = email;",
    ];
    expect(nonAdditive(bad.join("\n"))).toHaveLength(bad.length);
  });

  it("the first migration creates only identkit_ tables and indexes", () => {
    const first = files[0];
    if (!first) throw new Error("no D1 migration");
    const statements = splitStatements(readFileSync(`${directory}${first}`, "utf8"));
    expect(statements.filter((s) => !firstMigrationAllows(s))).toEqual([]);
    expect(statements.filter((s) => s.startsWith("CREATE TABLE"))).toHaveLength(10);
  });
});
