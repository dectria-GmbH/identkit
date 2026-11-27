import { Miniflare } from "miniflare";
import type { D1DatabaseLike } from "../../src/d1/index.js";

/**
 * A local D1 database: miniflare runs workerd with the D1 binding over SQLite in memory. The
 * statements of the store run through the same D1 API as in a deployed Worker.
 */
export async function startLocalD1(): Promise<{
  db: D1DatabaseLike;
  /** The same binding with its full type, for the Sessions API (`withSession`). */
  binding: Awaited<ReturnType<Miniflare["getD1Database"]>>;
  stop: () => Promise<void>;
}> {
  const mf = new Miniflare({
    modules: true,
    script: "export default { fetch() { return new Response(null, { status: 404 }); } };",
    d1Databases: { DB: "identkit-test" },
  });
  // The assignment also checks at compile time that a Workers `D1Database` fits the port.
  const binding = await mf.getD1Database("DB");
  const db: D1DatabaseLike = binding;
  return { db, binding, stop: () => mf.dispose() };
}
