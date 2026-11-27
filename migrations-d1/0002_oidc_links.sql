-- identkit D1 schema, version 2: links between accounts and subjects at external OpenID
-- Connect providers. It holds the same data as the PostgreSQL migration 0004. Additive: a new
-- table only, so the previous Worker version runs on this schema.
-- The link key identifies the subject (Microsoft tenant and object id, Google subject, issuer
-- and subject for other providers), never the e-mail address. It is unique: one subject signs
-- in to at most one account.

CREATE TABLE identkit_oidc_links (
  id TEXT NOT NULL PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  link_key TEXT NOT NULL UNIQUE,
  provider TEXT NOT NULL,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  tenant_id TEXT,
  source TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX identkit_oidc_links_account_idx ON identkit_oidc_links (account_id);
