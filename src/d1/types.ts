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
 * Pass the plain binding (`env.DB`), which reads from the primary. A D1 session
 * (`env.DB.withSession(...)`) fits this type too, but `createD1Store` accepts one only with the
 * option `sessionConstraint: "first-primary"`: a session with another constraint or from a
 * bookmark can read from a lagging read replica.
 */
export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
  /** Runs the statements in order as one transaction. A failed statement rolls back all. */
  batch(statements: D1PreparedStatementLike[]): Promise<unknown[]>;
}
