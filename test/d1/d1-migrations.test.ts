import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { D1_MIGRATIONS } from "../../src/d1/index.js";
import { splitStatements } from "../../src/sql-statements.js";

const directory = fileURLToPath(new URL("../../migrations-d1/", import.meta.url));

/**
 * The rule for every D1 migration after the first: additive only, so the previous Worker
 * version runs on the new schema. Returns the statements that break it.
 */
function nonAdditive(sql: string): string[] {
  return splitStatements(sql).filter((statement) => {
    const s = statement.replace(/\s+/g, " ").toUpperCase();
    if (/\bDROP\b/.test(s) || /\bRENAME\b/.test(s)) return true;
    if (s.startsWith("ALTER TABLE ") && !/^ALTER TABLE IDENTKIT_\w+ ADD COLUMN /.test(s))
      return true;
    if (/ADD COLUMN /.test(s) && /\bNOT NULL\b/.test(s) && !/\bDEFAULT\b/.test(s)) return true;
    if (/^CREATE (UNIQUE )?INDEX (IF NOT EXISTS )?(?!IDENTKIT_)/.test(s)) return true;
    if (/^CREATE TABLE (IF NOT EXISTS )?(?!IDENTKIT_)/.test(s)) return true;
    return !/^(CREATE|ALTER TABLE|UPDATE IDENTKIT_|INSERT INTO IDENTKIT_)/.test(s);
  });
}

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

  it("the additive check flags a drop, a rename, a NOT NULL column without default and a foreign name", () => {
    expect(
      nonAdditive(
        [
          "ALTER TABLE identkit_sessions ADD COLUMN note TEXT;",
          "ALTER TABLE identkit_sessions ADD COLUMN level INTEGER NOT NULL DEFAULT 0;",
          "CREATE INDEX identkit_sessions_note_idx ON identkit_sessions (note);",
          "CREATE TABLE identkit_new (id TEXT PRIMARY KEY);",
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
    ];
    expect(nonAdditive(bad.join("\n"))).toHaveLength(bad.length);
  });

  it("the first migration creates only identkit_ tables and indexes", () => {
    const first = files[0];
    if (!first) throw new Error("no D1 migration");
    const statements = splitStatements(readFileSync(`${directory}${first}`, "utf8"));
    expect(statements.every((s) => /^CREATE (UNIQUE )?(TABLE|INDEX) identkit_/.test(s))).toBe(true);
    expect(statements.filter((s) => s.startsWith("CREATE TABLE"))).toHaveLength(10);
  });
});
