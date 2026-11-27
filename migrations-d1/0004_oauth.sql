-- identkit D1 schema, version 4: the OAuth authorization server. It holds the same data as the
-- PostgreSQL migration 0006. Additive: new tables only, so the previous Worker version runs on
-- this schema.
-- Every secret (client secret, authorization code, access token, refresh token) is stored only
-- as a digest, never in plain text. Times are INTEGER milliseconds; lists are TEXT with a JSON
-- array of strings. Grants are deleted when they end, not marked: the foreign keys remove their
-- access tokens, and a client or account delete removes its grants and codes.

CREATE TABLE identkit_oauth_clients (
  id TEXT NOT NULL PRIMARY KEY,
  secret_digest TEXT,
  secret_digest_algorithm TEXT,
  auth_method TEXT NOT NULL,
  grant_types TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  name TEXT,
  source TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);

CREATE TABLE identkit_oauth_grants (
  id TEXT NOT NULL PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES identkit_oauth_clients (id) ON DELETE CASCADE,
  scopes TEXT NOT NULL,
  resource TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  refresh_ref_digest TEXT UNIQUE,
  refresh_digest TEXT,
  refresh_digest_algorithm TEXT,
  previous_refresh_digest TEXT,
  refreshed_at INTEGER,
  refresh_expires_at INTEGER,
  code_digest TEXT UNIQUE,
  source TEXT NOT NULL
);

-- One grant per (account, client). Named, so a later release can replace it.
CREATE UNIQUE INDEX identkit_oauth_grants_account_client_idx
  ON identkit_oauth_grants (account_id, client_id);
CREATE INDEX identkit_oauth_grants_client_idx ON identkit_oauth_grants (client_id);

CREATE TABLE identkit_oauth_access_tokens (
  digest TEXT NOT NULL PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES identkit_oauth_grants (id) ON DELETE CASCADE,
  generation INTEGER NOT NULL,
  scopes TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX identkit_oauth_access_tokens_grant_idx
  ON identkit_oauth_access_tokens (grant_id, expires_at);

CREATE TABLE identkit_oauth_codes (
  digest TEXT NOT NULL PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES identkit_oauth_clients (id) ON DELETE CASCADE,
  account_id TEXT NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  -- 1 if the authorization request named redirect_uri; the token request must then name it.
  redirect_uri_explicit INTEGER NOT NULL CHECK (redirect_uri_explicit IN (0, 1)),
  code_challenge TEXT NOT NULL,
  resource TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX identkit_oauth_codes_account_idx ON identkit_oauth_codes (account_id);
CREATE INDEX identkit_oauth_codes_client_idx ON identkit_oauth_codes (client_id);
CREATE INDEX identkit_oauth_codes_expires_idx ON identkit_oauth_codes (expires_at);

-- Dynamic client registrations per key and UTC day. key is "deployment" or a keyed digest of
-- the caller's address key, never the address itself.
CREATE TABLE identkit_oauth_registration_counts (
  key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL CHECK (count >= 0),
  PRIMARY KEY (key, window_start)
);
