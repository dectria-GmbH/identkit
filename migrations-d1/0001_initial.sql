-- identkit schema for Cloudflare D1 (SQLite), version 1. It holds the same data as the
-- PostgreSQL migrations 0001 to 0003. Secrets are stored only as keyed hashes in the *_digest
-- columns, TOTP secrets only sealed.
--
-- Types: every time is an INTEGER of milliseconds since the Unix epoch (UTC), so SQLite
-- compares times as numbers. A boolean is an INTEGER 0 or 1. A list of strings is TEXT with a
-- JSON array. The store never compares it in SQL. A public key is a BLOB.
--
-- Every table and index starts with identkit_, so the schema can share a database with other
-- tables. Allowed values of enumerations (status, purpose, method) are not CHECK constraints:
-- SQLite cannot change a CHECK without rebuilding the table, and later migrations must stay
-- additive. The store checks each value it reads.

CREATE TABLE identkit_accounts (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  webauthn_user_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  person_key_digest TEXT UNIQUE,
  assurance_level TEXT,
  identity_verified_at INTEGER
);

CREATE TABLE identkit_otp_flows (
  id TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,
  email TEXT NOT NULL,
  address_digest TEXT NOT NULL,
  session_id TEXT,
  code_digest TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL CHECK (attempts >= 0),
  max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
  consumed_at INTEGER,
  superseded_at INTEGER,
  CHECK (attempts <= max_attempts)
);

CREATE INDEX identkit_otp_flows_open_idx ON identkit_otp_flows (address_digest, purpose)
  WHERE consumed_at IS NULL AND superseded_at IS NULL;

CREATE INDEX identkit_otp_flows_expires_idx ON identkit_otp_flows (expires_at);

CREATE TABLE identkit_otp_send_gates (
  gate_key TEXT PRIMARY KEY,
  last_sent_at INTEGER NOT NULL
);

CREATE TABLE identkit_throttles (
  key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  attempts INTEGER NOT NULL,
  locked_until INTEGER,
  lock_count INTEGER NOT NULL CHECK (lock_count >= 0),
  consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0)
);

CREATE TABLE identkit_sessions (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  token_digest TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL,
  auth_methods TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL,
  step_up_method TEXT,
  step_up_at INTEGER,
  revoked_at INTEGER,
  revoke_reason TEXT,
  CHECK ((step_up_method IS NULL) = (step_up_at IS NULL))
);

CREATE INDEX identkit_sessions_account_live_idx ON identkit_sessions (account_id)
  WHERE revoked_at IS NULL;

CREATE TABLE identkit_credentials (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL CHECK (counter >= 0 AND counter <= 4294967295),
  transports TEXT NOT NULL,
  device_type TEXT NOT NULL,
  backed_up INTEGER NOT NULL CHECK (backed_up IN (0, 1)),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  -- Null while the registration that created it is still running. Such rows are not usable.
  activated_at INTEGER
);

CREATE INDEX identkit_credentials_account_idx ON identkit_credentials (account_id);

CREATE TABLE identkit_challenges (
  id TEXT PRIMARY KEY,
  challenge_digest TEXT NOT NULL UNIQUE,
  purpose TEXT NOT NULL,
  account_id TEXT,
  session_id TEXT,
  enrollment_token_digest TEXT,
  payload_hash TEXT,
  nonce TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX identkit_challenges_expires_idx ON identkit_challenges (expires_at);

CREATE TABLE identkit_enrollment_tokens (
  token_digest TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  revoked_at INTEGER
);

CREATE INDEX identkit_enrollment_tokens_account_idx ON identkit_enrollment_tokens (account_id);

CREATE TABLE identkit_verifications (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  vendor_reference TEXT UNIQUE,
  status TEXT NOT NULL,
  assurance_level TEXT,
  evidence_reference TEXT,
  failure_reason TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  completed_at INTEGER
);

CREATE TABLE identkit_totp_factors (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  sealed_secret TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  digits INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  enrolment_session_id TEXT,
  -- Null until a first valid code confirmed the enrolment. Such rows are not usable.
  activated_at INTEGER,
  -- Latest accepted time step. A step at or below it is never accepted again.
  last_used_step INTEGER CHECK (last_used_step >= 0),
  last_used_at INTEGER
);

-- At most one active TOTP factor per account.
CREATE UNIQUE INDEX identkit_totp_factors_one_active_idx ON identkit_totp_factors (account_id)
  WHERE activated_at IS NOT NULL;

CREATE INDEX identkit_totp_factors_account_idx ON identkit_totp_factors (account_id);
