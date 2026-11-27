// Fails if a runtime-neutral entry of the built package reaches Node-only code. Run it after
// `pnpm build`. Optional argument: another package root, for the self-test fixtures.
//
// For each entry it bundles `dist` with the resolve conditions of Cloudflare Workers and checks:
// - every import of a Node built-in module, before tree shaking;
// - the Node globals `Buffer` and `process` (also through `globalThis.` and `instanceof`) in the
//   bundled code with comments removed; in dependencies only where ALLOWED_DEPENDENCY_GLOBALS
//   records a runtime guard;
// - `import()` and `require()` with a computed specifier, which no static check can follow;
// - `getBuiltinModule` outside identkit's loader `node-crypto.js`, and loader calls that do not
//   name one of the sync exports in SYNC_EXPORTS;
// - that identkit's own code calls no sync export: an entry that re-exports everything except
//   the sync exports must bundle without any loader call (FAKE_ADAPTER_MEMBERS aside).
import { builtinModules } from "node:module";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { rolldown } from "rolldown";
import { parseAst } from "rolldown/parseAst";

const root = resolve(process.argv[2] ?? resolve(dirname(fileURLToPath(import.meta.url)), ".."));
const dist = resolve(root, "dist") + sep;
const entries = ["dist/index.js", "dist/testing/index.js", "dist/d1/index.js"];
const conditionNames = ["workerd", "worker", "browser", "import", "default"];
const builtins = new Set(builtinModules.flatMap((name) => [name, `node:${name}`]));

/** Sync exports that may load node:crypto through the loader, by the name they pass to it. */
const SYNC_EXPORTS = new Set([
  "approvalChallenge",
  "hashPayload",
  "generateTotpCode",
  "callbackFor",
  "createSoftwareAuthenticator",
]);
/** Sync members of returned objects: tree shaking cannot drop them, so the strict pass allows them. */
const FAKE_ADAPTER_MEMBERS = new Set(["callbackFor"]);
/** Node globals that a dependency uses behind a runtime guard: package name -> globals. */
const ALLOWED_DEPENDENCY_GLOBALS = new Map([
  // Uses Buffer only when `btoa`/`atob` are missing; Workers have both.
  ["pvtsutils", new Set(["Buffer"])],
  // Reads `globalThis.Buffer` as a feature check and falls back to `btoa`/`atob`.
  ["@peculiar/utils", new Set(["Buffer"])],
]);

const NODE_GLOBALS = new Set(["Buffer", "process"]);
const GLOBAL_OBJECTS = new Set(["globalThis", "self", "global", "window"]);
const LOADER = /^nodeCrypto(?:\$\d+)?$/;

const isBuiltin = (id) => id.startsWith("node:") || builtins.has(id.split("/")[0] ?? "");
const show = (id) => (id ? relative(root, id) : "?");
const isLoader = (id) => id === resolve(dist, "node-crypto.js");

function packageName(id) {
  const parts = id.split(`${sep}node_modules${sep}`).at(-1)?.split(sep) ?? [];
  return parts[0]?.startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0];
}

async function bundle(input, label, plugins = []) {
  const findings = [];
  const build = await rolldown({
    input,
    platform: "browser",
    plugins,
    resolve: { conditionNames },
    external: (id, importer) => {
      if (!isBuiltin(id)) return false;
      findings.push(`${label}: ${id} imported by ${show(importer)}`);
      return true;
    },
    onLog: (level, log) => {
      if (level === "warn") findings.push(`${label}: bundler warning: ${log.message}`);
    },
  });
  const { output } = await build.generate({ format: "esm", comments: false });
  await build.close();
  const modules = output.flatMap((chunk) =>
    chunk.type === "chunk"
      ? Object.entries(chunk.modules).map(([id, module]) => ({ id, code: module.code ?? "" }))
      : [],
  );
  return { findings, modules };
}

/** A string the parser knows: a string literal or a template literal without expressions. */
function staticString(node) {
  if (node?.type === "Literal" && typeof node.value === "string") return node.value;
  if (node?.type === "TemplateLiteral" && node.expressions.length === 0) {
    return node.quasis[0]?.value.cooked ?? undefined;
  }
  return undefined;
}

/** Visits every AST node with its parent and the key under which the parent holds it. */
function walk(node, visit, parent = null, key = null) {
  if (!node || typeof node.type !== "string") return;
  visit(node, parent, key);
  for (const [childKey, child] of Object.entries(node)) {
    if (Array.isArray(child)) for (const item of child) walk(item, visit, node, childKey);
    else if (child && typeof child === "object") walk(child, visit, node, childKey);
  }
}

/** True if the identifier names a variable, not a property or key of an object. */
function isReference(parent, key) {
  if (!parent) return true;
  if (parent.type === "MemberExpression" && key === "property" && !parent.computed) return false;
  if (
    ["Property", "MethodDefinition", "PropertyDefinition"].includes(parent.type) &&
    key === "key" &&
    !parent.computed
  ) {
    return false;
  }
  return true;
}

/** Node globals, computed imports, getBuiltinModule and loader calls in one module. */
function scanModule(id, code, allowedLoaderNames) {
  const found = [];
  const isOwn = id.startsWith(dist);
  const allowedGlobals = isOwn
    ? new Set(isLoader(id) ? ["process"] : [])
    : (ALLOWED_DEPENDENCY_GLOBALS.get(packageName(id)) ?? new Set());
  walk(parseAst(code), (node, parent, key) => {
    let global;
    if (node.type === "Identifier" && NODE_GLOBALS.has(node.name) && isReference(parent, key)) {
      global = node.name;
    } else if (
      node.type === "MemberExpression" &&
      !node.computed &&
      node.object.type === "Identifier" &&
      GLOBAL_OBJECTS.has(node.object.name) &&
      NODE_GLOBALS.has(node.property.name)
    ) {
      global = node.property.name;
    }
    if (global && !allowedGlobals.has(global)) found.push(`global ${global}`);
    if (node.type === "ImportExpression" && staticString(node.source) === undefined) {
      found.push("import() with a computed specifier");
    }
    if (node.type === "CallExpression" && node.callee.type === "Identifier") {
      const callee = node.callee.name;
      if (callee === "require" && staticString(node.arguments[0]) === undefined) {
        found.push("require() with a computed specifier");
      }
      if (LOADER.test(callee) && isOwn) {
        const name = staticString(node.arguments[0]);
        if (name === undefined || !allowedLoaderNames.has(name)) {
          found.push(`node:crypto loader called for ${name ?? "a computed name"}`);
        }
      }
    }
    if (
      (node.type === "Identifier" || node.type === "IdentifierName") &&
      node.name === "getBuiltinModule" &&
      !(isOwn && isLoader(id))
    ) {
      found.push("getBuiltinModule outside the loader");
    }
  });
  return found;
}

function scan(label, modules, allowedLoaderNames) {
  const findings = [];
  let own = 0;
  for (const { id, code } of modules) {
    if (id.startsWith(dist)) own += 1;
    for (const finding of scanModule(id, code, allowedLoaderNames)) {
      findings.push(`${label}: ${show(id)}: ${finding}`);
    }
  }
  return { findings, own };
}

/** An entry that re-exports everything except the sync exports. */
async function strictEntry(entry) {
  const names = Object.keys(await import(pathToFileURL(resolve(root, entry)).href));
  const kept = names.filter((name) => !SYNC_EXPORTS.has(name));
  const id = "\0strict-entry";
  return {
    input: id,
    plugins: [
      {
        name: "strict-entry",
        resolveId: (source) => (source === id ? id : null),
        load: (source) =>
          source === id
            ? `export { ${kept.join(", ")} } from ${JSON.stringify(resolve(root, entry))};`
            : null,
      },
    ],
  };
}

const findings = [];
for (const entry of entries) {
  const full = await bundle(resolve(root, entry), entry);
  const fullScan = scan(entry, full.modules, SYNC_EXPORTS);
  findings.push(...full.findings, ...fullScan.findings);

  const strict = await strictEntry(entry);
  const label = `${entry} without sync exports`;
  const reduced = await bundle(strict.input, label, strict.plugins);
  findings.push(...reduced.findings);
  for (const finding of scan(label, reduced.modules, FAKE_ADAPTER_MEMBERS).findings) {
    if (finding.includes("node:crypto loader called")) findings.push(finding);
  }
  console.log(`${entry}: bundled, ${fullScan.own} identkit modules checked`);
}

if (findings.length > 0) {
  console.error(`Node-only code reachable from a runtime-neutral entry:\n${findings.join("\n")}`);
  process.exit(1);
}
console.log("no Node built-in module or global reachable from the root, testing or d1 entry");
