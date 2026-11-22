-- identkit schema, version 1. Secrets (codes, session and enrollment tokens, person keys) are
-- stored only as keyed hashes in the *_digest columns. WebAuthn challenges are stored as keyed
-- hashes too; an approval challenge can be recomputed from its stored nonce and payload hash,
-- because it is public by design and only binds the signature to the payload.

CREATE TABLE identkit_accounts (
  id text PRIMARY KEY,
  email text NOT NULL UNIQUE,
  webauthn_user_id text NOT NULL UNIQUE,
  status text NOT NULL CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL,
  person_key_digest text UNIQUE,
  assurance_level text CHECK (assurance_level IN ('low', 'substantial', 'high')),
  identity_verified_at timestamptz
);

CREATE TABLE identkit_otp_flows (
  id text PRIMARY KEY,
  purpose text NOT NULL CHECK (purpose IN ('sign_in', 'step_up')),
  email text NOT NULL,
  address_digest text NOT NULL,
  session_id text,
  code_digest text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  attempts integer NOT NULL CHECK (attempts >= 0),
  max_attempts integer NOT NULL CHECK (max_attempts > 0),
  consumed_at timestamptz,
  superseded_at timestamptz,
  CHECK (attempts <= max_attempts)
);

CREATE INDEX identkit_otp_flows_open_idx ON identkit_otp_flows (address_digest, purpose)
  WHERE consumed_at IS NULL AND superseded_at IS NULL;

CREATE INDEX identkit_otp_flows_expires_idx ON identkit_otp_flows (expires_at);

CREATE TABLE identkit_otp_send_gates (
  gate_key text PRIMARY KEY,
  last_sent_at timestamptz NOT NULL
);

CREATE TABLE identkit_throttles (
  key text PRIMARY KEY,
  window_start timestamptz NOT NULL,
  attempts integer NOT NULL,
  locked_until timestamptz,
  lock_count integer NOT NULL CHECK (lock_count >= 0)
);

CREATE TABLE identkit_sessions (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  token_digest text NOT NULL UNIQUE,
  state text NOT NULL CHECK (state IN ('pending_second_factor', 'complete')),
  auth_methods text[] NOT NULL,
  created_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  step_up_method text CHECK (step_up_method IN ('email_otp', 'passkey')),
  step_up_at timestamptz,
  revoked_at timestamptz,
  revoke_reason text,
  CHECK ((step_up_method IS NULL) = (step_up_at IS NULL))
);

CREATE INDEX identkit_sessions_account_live_idx ON identkit_sessions (account_id)
  WHERE revoked_at IS NULL;

CREATE TABLE identkit_credentials (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  public_key bytea NOT NULL,
  counter bigint NOT NULL CHECK (counter >= 0 AND counter <= 4294967295),
  transports text[] NOT NULL,
  device_type text NOT NULL CHECK (device_type IN ('singleDevice', 'multiDevice')),
  backed_up boolean NOT NULL,
  created_at timestamptz NOT NULL,
  last_used_at timestamptz
);

CREATE INDEX identkit_credentials_account_idx ON identkit_credentials (account_id);

CREATE TABLE identkit_challenges (
  id text PRIMARY KEY,
  challenge_digest text NOT NULL UNIQUE,
  purpose text NOT NULL
    CHECK (purpose IN ('registration', 'sign_in', 'second_factor', 'step_up', 'approval')),
  account_id text,
  session_id text,
  enrollment_token_digest text,
  payload_hash text,
  nonce text,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE INDEX identkit_challenges_expires_idx ON identkit_challenges (expires_at);

CREATE TABLE identkit_enrollment_tokens (
  token_digest text PRIMARY KEY,
  account_id text NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);

CREATE TABLE identkit_verifications (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  vendor_reference text UNIQUE,
  status text NOT NULL
    CHECK (status IN ('pending', 'processing', 'verified', 'failed', 'expired', 'conflict')),
  assurance_level text CHECK (assurance_level IN ('low', 'substantial', 'high')),
  evidence_reference text,
  failure_reason text,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  completed_at timestamptz
);
