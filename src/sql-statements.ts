/** Splits a migration file at semicolons that end a line. Comment lines are dropped. */
export function splitStatements(text: string): string[] {
  const withoutComments = text
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n");
  return withoutComments
    .split(/;\s*(?:\n|$)/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}
