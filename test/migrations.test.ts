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

  it("splits the TOTP migration into its statements, without editing the first one", () => {
    const text = readFileSync(join(MIGRATIONS_DIR, "0002_totp.sql"), "utf8");
    const statements = splitStatements(text);
    expect(statements.map((s) => s.split(/\s+/).slice(0, 3).join(" "))).toEqual([
      "ALTER TABLE identkit_sessions",
      "ALTER TABLE identkit_sessions",
      "ALTER TABLE identkit_challenges",
      "ALTER TABLE identkit_challenges",
      "CREATE TABLE identkit_totp_factors",
      "CREATE UNIQUE INDEX",
      "CREATE INDEX identkit_totp_factors_account_idx",
    ]);
  });

  it("splits the lockout and enrollment migration into its statements", () => {
    const text = readFileSync(
      join(MIGRATIONS_DIR, "0003_lockout_and_enrollment_revocation.sql"),
      "utf8",
    );
    const statements = splitStatements(text);
    expect(statements.map((s) => s.split(/\s+/).slice(0, 3).join(" "))).toEqual([
      "ALTER TABLE identkit_throttles",
      "ALTER TABLE identkit_enrollment_tokens",
      "CREATE INDEX identkit_enrollment_tokens_account_idx",
    ]);
  });

  it("splits the OIDC link migration into its statements, a new table only", () => {
    const text = readFileSync(join(MIGRATIONS_DIR, "0004_oidc_links.sql"), "utf8");
    const statements = splitStatements(text);
    expect(statements.map((s) => s.split(/\s+/).slice(0, 3).join(" "))).toEqual([
      "CREATE TABLE identkit_oidc_links",
      "CREATE INDEX identkit_oidc_links_account_idx",
    ]);
    expect(text).not.toMatch(/\b(DROP|RENAME|ALTER)\b/i);
  });
});
