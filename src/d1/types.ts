/**
 * The part of the Cloudflare D1 binding that the identkit D1 store uses. A `D1Database` from
 * the Workers runtime fits it, so identkit needs no Cloudflare types at runtime.
 */
export interface D1PreparedStatementLike {
  bind(...values: unknown[]): D1PreparedStatementLike;
  first(): Promise<Record<string, unknown> | null>;
  all(): Promise<{ results: Record<string, unknown>[] }>;
  run(): Promise<unknown>;
}

/**
 * Pass the plain binding (`env.DB`), which reads only from the primary. A D1 session
 * (`env.DB.withSession(...)`) fits this type too, but `createD1Store` accepts one only with the
 * option `sessionConstraint: "first-primary"`, and only a session new in this request: a session
 * with another constraint, from a bookmark, or reused from an earlier request can read from a
 * lagging read replica. A wrapper around a session must forward `getBookmark`, or the store
 * cannot detect the session.
 */
export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
  /** Runs the statements in order as one transaction. A failed statement rolls back all. */
  batch(statements: D1PreparedStatementLike[]): Promise<unknown[]>;
}
