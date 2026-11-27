-- identkit schema, version 5: personal API tokens. Additive: a new table only, so the previous
-- release runs on this schema.
-- A token is stored only as a digest of the whole token, never in plain text. digest_algorithm
-- names how: hmac-sha256 (keyed, for every token identkit creates) or sha256 (unkeyed, only for
-- tokens imported from an earlier system). The digest is unique, so verify is one indexed read.
-- digest_algorithm, source and scopes have no CHECK constraint, so a later value needs no
-- constraint change; the store checks each value it reads.

CREATE TABLE identkit_api_tokens (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  name text NOT NULL,
  scopes text[] NOT NULL,
  digest text NOT NULL UNIQUE,
  digest_algorithm text NOT NULL,
  source text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  last_used_at timestamptz,
  revoked_at timestamptz,
  revoke_reason text
);

CREATE INDEX identkit_api_tokens_account_idx ON identkit_api_tokens (account_id);
