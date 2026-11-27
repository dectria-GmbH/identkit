// Writes src/d1/migrations-sql.ts from the files in migrations-d1/, so the D1 entry carries
// the migrations as strings and needs no file system at runtime. A test fails if the module
// and the files differ. Run it after a change in migrations-d1/: pnpm generate:d1-migrations
import { readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { format, resolveConfig } from "prettier";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const directory = resolve(root, "migrations-d1");
const target = resolve(root, "src/d1/migrations-sql.ts");

const names = (await readdir(directory))
  .filter((f) => /^\d{4}_[a-z0-9_]+\.sql$/.test(f))
  .toSorted();
const entries = [];
for (const name of names) {
  const sql = await readFile(resolve(directory, name), "utf8");
  entries.push(`  { name: ${JSON.stringify(name)}, sql: ${JSON.stringify(sql)} },`);
}
const source = `// Generated from migrations-d1/ by scripts/generate-d1-migrations.mjs. Do not edit.
import type { D1Migration } from "./migrate.js";

export const D1_MIGRATIONS: readonly D1Migration[] = [
${entries.join("\n")}
];
`;
const options = { ...(await resolveConfig(target)), filepath: target };
await writeFile(target, await format(source, options));
console.log(`wrote ${names.length} migrations to src/d1/migrations-sql.ts`);
