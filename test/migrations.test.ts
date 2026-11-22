import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { MIGRATIONS_DIR, splitStatements } from "../src/postgres/index.js";

describe("migrations", () => {
  it("splits the initial migration into its CREATE statements", () => {
    const text = readFileSync(join(MIGRATIONS_DIR, "0001_initial.sql"), "utf8");
    const statements = splitStatements(text);
    expect(statements).toHaveLength(14);
    expect(statements.every((s) => s.startsWith("CREATE "))).toBe(true);
    expect(statements.filter((s) => s.startsWith("CREATE TABLE"))).toHaveLength(9);
  });
});
