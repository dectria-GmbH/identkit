-- identkit schema, version 6: the OAuth authorization server. Additive: new tables only, so the
-- previous release runs on this schema.
-- Every secret (client secret, authorization code, access token, refresh token) is stored only
-- as a digest, never in plain text. secret_digest_algorithm and refresh_digest_algorithm name
-- how: hmac-sha256 (keyed, for every secret identkit issues) or sha256 (unkeyed, only for
-- secrets imported from an earlier system). Enumerations have no CHECK constraint, so a later
-- value needs no constraint change; the store checks each value it reads.
-- Grants are deleted when they end, not marked: the foreign keys remove their access tokens,
-- and a client or account delete removes its grants and codes.

CREATE TABLE identkit_oauth_clients (
  id text PRIMARY KEY,
  secret_digest text,
  secret_digest_algorithm text,
  auth_method text NOT NULL,
  grant_types text[] NOT NULL,
  redirect_uris text[] NOT NULL,
  name text,
  source text NOT NULL,
  created_at timestamptz NOT NULL,
  last_used_at timestamptz
);

CREATE TABLE identkit_oauth_grants (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  client_id text NOT NULL REFERENCES identkit_oauth_clients (id) ON DELETE CASCADE,
  scopes text[] NOT NULL,
  resource text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  generation integer NOT NULL,
  refresh_ref_digest text UNIQUE,
  refresh_digest text,
  refresh_digest_algorithm text,
  previous_refresh_digest text,
  refreshed_at timestamptz,
  refresh_expires_at timestamptz,
  code_digest text UNIQUE,
  source text NOT NULL
);

-- One grant per (account, client). Named, so a later release can replace it.
CREATE UNIQUE INDEX identkit_oauth_grants_account_client_idx
  ON identkit_oauth_grants (account_id, client_id);
CREATE INDEX identkit_oauth_grants_client_idx ON identkit_oauth_grants (client_id);

CREATE TABLE identkit_oauth_access_tokens (
  digest text PRIMARY KEY,
  grant_id text NOT NULL REFERENCES identkit_oauth_grants (id) ON DELETE CASCADE,
  generation integer NOT NULL,
  scopes text[] NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE INDEX identkit_oauth_access_tokens_grant_idx
  ON identkit_oauth_access_tokens (grant_id, expires_at);

CREATE TABLE identkit_oauth_codes (
  digest text PRIMARY KEY,
  client_id text NOT NULL REFERENCES identkit_oauth_clients (id) ON DELETE CASCADE,
  account_id text NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,
  code_challenge text NOT NULL,
  resource text NOT NULL,
  scopes text[] NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE INDEX identkit_oauth_codes_account_idx ON identkit_oauth_codes (account_id);
CREATE INDEX identkit_oauth_codes_client_idx ON identkit_oauth_codes (client_id);
CREATE INDEX identkit_oauth_codes_expires_idx ON identkit_oauth_codes (expires_at);

-- Dynamic client registrations per key and UTC day. key is "deployment" or a keyed digest of
-- the caller's address key, never the address itself.
CREATE TABLE identkit_oauth_registration_counts (
  key text NOT NULL,
  window_start timestamptz NOT NULL,
  count integer NOT NULL CHECK (count >= 0),
  PRIMARY KEY (key, window_start)
);
