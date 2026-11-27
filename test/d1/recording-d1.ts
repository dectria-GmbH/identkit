import type { D1DatabaseLike, D1PreparedStatementLike } from "../../src/d1/index.js";

/** One call into D1: a single statement, or one `batch()` with its statements in order. */
export interface D1Call {
  kind: "statement" | "batch";
  queries: string[];
}

const compact = (query: string) => query.replace(/\s+/g, " ").trim();

/**
 * Wraps a D1 binding and records each call that reaches D1. Each record is one query against
 * the per-invocation limit (a `batch()` counts once). `missWrite` makes a matching statement
 * return no row without running it, as if a concurrent call changed the state first.
 */
export function recordingD1(
  db: D1DatabaseLike,
  options: { missWrite?: (query: string) => boolean } = {},
): { db: D1DatabaseLike; calls: D1Call[] } {
  const calls: D1Call[] = [];
  const inner = new WeakMap<D1PreparedStatementLike, D1PreparedStatementLike>();
  const queryOf = new WeakMap<D1PreparedStatementLike, string>();

  function wrap(query: string, statement: D1PreparedStatementLike): D1PreparedStatementLike {
    const record = () => calls.push({ kind: "statement", queries: [compact(query)] });
    const wrapped: D1PreparedStatementLike = {
      bind: (...values) => wrap(query, statement.bind(...values)),
      first: async () => {
        record();
        if (options.missWrite?.(compact(query))) return null;
        return statement.first();
      },
      all: async () => {
        record();
        return statement.all();
      },
      run: async () => {
        record();
        return statement.run();
      },
    };
    inner.set(wrapped, statement);
    queryOf.set(wrapped, query);
    return wrapped;
  }

  return {
    calls,
    db: {
      prepare: (query) => wrap(query, db.prepare(query)),
      batch: async (statements) => {
        calls.push({
          kind: "batch",
          queries: statements.map((s) => compact(queryOf.get(s) ?? "<unknown statement>")),
        });
        return db.batch(
          statements.map((s) => {
            const unwrapped = inner.get(s);
            if (!unwrapped) throw new Error("batch got a statement that the wrapper did not make");
            return unwrapped;
          }),
        );
      },
    },
  };
}
