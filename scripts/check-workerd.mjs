// Runs test/workerd/smoke-worker.js in workerd (through Miniflare) without nodejs_compat, against
// the built `dist` entries, `identkit/d1` included (against a local D1 binding). Run it after
// `pnpm build`. Exits non-zero if a check fails.
// It also times `sessions.validate` with the memory store, in workerd and on Node.
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Miniflare } from "miniflare";
import { rolldown } from "rolldown";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const BENCH_CALLS = 2000;

async function bundleWorker() {
  const build = await rolldown({
    input: resolve(root, "test/workerd/smoke-worker.js"),
    platform: "browser",
    resolve: { conditionNames: ["workerd", "worker", "browser", "import", "default"] },
  });
  const { output } = await build.generate({ format: "esm" });
  await build.close();
  const chunks = output.filter((item) => item.type === "chunk");
  if (chunks.length !== 1) throw new Error(`expected one chunk, got ${chunks.length}`);
  return chunks[0].code;
}

/** The software authenticator signs with node:crypto, so it runs here, on Node. */
async function authenticatorService() {
  const { createSoftwareAuthenticator } = await import(resolve(root, "dist/testing/index.js"));
  let authenticator;
  const reset = () => {
    authenticator = createSoftwareAuthenticator({ origin: "https://portal.example" });
  };
  reset();
  return async (request) => {
    const action = new URL(request.url).pathname.slice(1);
    const options = await request.json();
    if (action === "reset") {
      reset();
      return Response.json({});
    }
    if (action === "register") return Response.json(authenticator.register(options));
    if (action === "assert") return Response.json(authenticator.assert(options));
    return new Response("unknown action", { status: 404 });
  };
}

/**
 * A fake Microsoft identity platform on Node, reached from workerd through a service binding,
 * so identkit's requests go through workerd's real `fetch` (headers, body, abort signal).
 * `POST http://idp/authorize` plays the user; every other request is the provider itself.
 */
async function identityProviderService() {
  const { createFakeOidcProvider } = await import(resolve(root, "dist/testing/index.js"));
  const { OIDC_CLIENT } = await import(resolve(root, "test/workerd/smoke-config.js"));
  const fake = await createFakeOidcProvider({ kind: "microsoft", ...OIDC_CLIENT });
  return async (request) => {
    if (request.url === "http://idp/authorize") {
      const { url, claims } = await request.json();
      return Response.json({ query: (await fake.authorize(url, claims)).toString() });
    }
    if (request.url === "http://idp/requests") return Response.json(fake.requests());
    const body = request.method === "POST" ? await request.text() : undefined;
    return fake.fetch(request.url, { method: request.method, headers: request.headers, body });
  };
}

/** Wall time per call of `sessions.validate` in workerd: two runs, so setup cost cancels out. */
async function benchWorkerd(mf) {
  const time = async (n) => {
    const started = performance.now();
    const response = await mf.dispatchFetch(`http://smoke/bench?n=${n}`);
    const body = await response.json();
    if (body.valid !== n) throw new Error(`bench: ${body.valid} of ${n} sessions valid`);
    return performance.now() - started;
  };
  await time(10);
  const base = await time(0);
  const full = await time(BENCH_CALLS);
  return (full - base) / BENCH_CALLS;
}

/** CPU time per call of `sessions.validate` on Node, as a proxy. */
async function benchNode() {
  const { createIdentkit, createHmacHasher, createMemoryStore } = await import(
    resolve(root, "dist/index.js")
  );
  const testing = await import(resolve(root, "dist/testing/index.js"));
  const { basePolicy, config } = await import(resolve(root, "test/workerd/smoke-config.js"));
  const mail = testing.createRecordingMailSender();
  const ik = createIdentkit({
    config,
    sealer: testing.createTestSealer(),
    isPrivilegedAccount: () => false,
    store: createMemoryStore(),
    hasher: createHmacHasher(crypto.getRandomValues(new Uint8Array(32))),
    mail,
    audit: testing.createRecordingAuditSink(),
    clock: testing.createFakeClock(),
    policy: basePolicy,
  });
  const requested = await ik.emailSignIn.requestCode({ email: "person@example.org" });
  const signedIn = await ik.emailSignIn.verifyCode({
    flowId: requested.flowId,
    code: mail.last().code,
  });
  for (let i = 0; i < 100; i += 1) await ik.sessions.validate(signedIn.token);
  const before = process.cpuUsage();
  for (let i = 0; i < BENCH_CALLS; i += 1) {
    if (!(await ik.sessions.validate(signedIn.token))) throw new Error("session not valid");
  }
  const used = process.cpuUsage(before);
  return (used.user + used.system) / 1000 / BENCH_CALLS;
}

const mf = new Miniflare({
  // One bundled module. A Node built-in import stays a bare import that workerd must resolve.
  modulesRoot: root,
  modules: [
    {
      type: "ESModule",
      path: resolve(root, "smoke-worker.mjs"),
      contents: await bundleWorker(),
    },
  ],
  compatibilityDate: "2026-07-01",
  compatibilityFlags: [],
  serviceBindings: {
    AUTHENTICATOR: await authenticatorService(),
    IDP: await identityProviderService(),
  },
  d1Databases: { DB: "identkit-smoke" },
});

let failed = false;
try {
  const results = await (await mf.dispatchFetch("http://smoke/")).json();
  for (const result of results) {
    console.log(
      `${result.ok ? "ok  " : "FAIL"} ${result.name}${result.ok ? "" : `\n${result.error}`}`,
    );
    if (!result.ok) failed = true;
  }
  if (results.length === 0) failed = true;
  const workerdMs = await benchWorkerd(mf);
  console.log(`sessions.validate in workerd: ${workerdMs.toFixed(4)} ms wall time per call`);
} finally {
  await mf.dispose();
}
const nodeMs = await benchNode();
console.log(`sessions.validate on Node: ${nodeMs.toFixed(4)} ms CPU time per call`);

if (failed) {
  console.error("workerd smoke test failed");
  process.exit(1);
}
console.log("workerd smoke test passed without nodejs_compat");
