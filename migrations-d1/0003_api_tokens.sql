-- identkit D1 schema, version 3: personal API tokens. It holds the same data as the PostgreSQL
-- migration 0005. Additive: a new table only, so the previous Worker version runs on this schema.
-- A token is stored only as a digest of the whole token, never in plain text. digest_algorithm
-- names how: hmac-sha256 (keyed, for every token identkit creates) or sha256 (unkeyed, only for
-- tokens imported from an earlier system). The digest is unique, so verify is one indexed read.
-- scopes is TEXT with a JSON array of strings.

CREATE TABLE identkit_api_tokens (
  id TEXT NOT NULL PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  scopes TEXT NOT NULL,
  digest TEXT NOT NULL UNIQUE,
  digest_algorithm TEXT NOT NULL,
  source TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER,
  revoke_reason TEXT
);

CREATE INDEX identkit_api_tokens_account_idx ON identkit_api_tokens (account_id);
