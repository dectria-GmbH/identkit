// Fails if a runtime-neutral entry of the built package reaches Node-only code. It bundles
// each entry from `dist` with the resolve conditions of Cloudflare Workers and records every
// import of a Node built-in module, before tree shaking. In identkit's own modules it also
// flags the Node globals `Buffer` and `process` in the bundled code, with comments removed.
// Run it after `pnpm build`.
import { builtinModules } from "node:module";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { rolldown } from "rolldown";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dist = resolve(root, "dist") + sep;
const entries = ["dist/index.js", "dist/testing/index.js"];
const builtins = new Set(builtinModules.flatMap((name) => [name, `node:${name}`]));
const nodeGlobal = /(?<![.\w$])(Buffer|process)\s*[.([]/g;

const isBuiltin = (id) => id.startsWith("node:") || builtins.has(id.split("/")[0] ?? "");
const show = (id) => (id ? relative(root, id) : "?");

const findings = [];
for (const entry of entries) {
  const bundle = await rolldown({
    input: resolve(root, entry),
    platform: "browser",
    resolve: { conditionNames: ["workerd", "worker", "browser", "import", "default"] },
    external: (id, importer) => {
      if (!isBuiltin(id)) return false;
      findings.push(`${entry}: ${id} imported by ${show(importer)}`);
      return true;
    },
    onLog: (level, log) => {
      if (level === "warn") findings.push(`${entry}: bundler warning: ${log.message}`);
    },
  });
  const { output } = await bundle.generate({ format: "esm", comments: false });
  await bundle.close();
  let own = 0;
  for (const chunk of output) {
    if (chunk.type !== "chunk") continue;
    for (const [id, module] of Object.entries(chunk.modules)) {
      if (!id.startsWith(dist)) continue;
      own += 1;
      for (const match of (module.code ?? "").matchAll(nodeGlobal)) {
        findings.push(`${entry}: global ${match[1]} in ${show(id)}`);
      }
    }
  }
  console.log(`${entry}: bundled, ${own} identkit modules checked for Node globals`);
}

if (findings.length > 0) {
  console.error(`Node-only code reachable from a runtime-neutral entry:\n${findings.join("\n")}`);
  process.exit(1);
}
console.log("no Node built-in module or global reachable from the root or testing entry");
