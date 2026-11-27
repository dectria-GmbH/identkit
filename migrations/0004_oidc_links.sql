-- identkit schema, version 4: links between accounts and subjects at external OpenID Connect
-- providers. Additive: a new table only, so the previous release runs on this schema.
-- The link key identifies the subject (Microsoft tenant and object id, Google subject, issuer
-- and subject for other providers), never the e-mail address. It is unique: one subject signs
-- in to at most one account. provider and source have no CHECK constraint, so a later provider
-- kind needs no constraint change; the store checks each value it reads.

CREATE TABLE identkit_oidc_links (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  link_key text NOT NULL UNIQUE,
  provider text NOT NULL,
  issuer text NOT NULL,
  subject text NOT NULL,
  tenant_id text,
  source text NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE INDEX identkit_oidc_links_account_idx ON identkit_oidc_links (account_id);
