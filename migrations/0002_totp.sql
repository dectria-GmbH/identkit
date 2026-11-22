-- identkit schema, version 2: TOTP factors and approvals confirmed by a TOTP code.
-- A TOTP secret must be read back to verify a code, so it cannot be hashed. It is stored only
-- sealed (authenticated encryption through the SecretSealer port, bound to the factor id and
-- account), never in plain text.

ALTER TABLE identkit_sessions DROP CONSTRAINT identkit_sessions_step_up_method_check;

ALTER TABLE identkit_sessions ADD CONSTRAINT identkit_sessions_step_up_method_check
  CHECK (step_up_method IN ('email_otp', 'passkey', 'totp'));

ALTER TABLE identkit_challenges DROP CONSTRAINT identkit_challenges_purpose_check;

ALTER TABLE identkit_challenges ADD CONSTRAINT identkit_challenges_purpose_check
  CHECK (purpose IN ('registration', 'sign_in', 'second_factor', 'step_up', 'approval',
    'approval_code'));

CREATE TABLE identkit_totp_factors (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES identkit_accounts (id) ON DELETE CASCADE,
  sealed_secret text NOT NULL,
  algorithm text NOT NULL CHECK (algorithm IN ('SHA1', 'SHA256', 'SHA512')),
  digits integer NOT NULL CHECK (digits IN (6, 8)),
  created_at timestamptz NOT NULL,
  enrolment_session_id text,
  -- Null until a first valid code confirmed the enrolment; such rows are not usable.
  activated_at timestamptz,
  -- Latest accepted time step. A step at or below it is never accepted again.
  last_used_step bigint CHECK (last_used_step >= 0),
  last_used_at timestamptz
);

-- At most one active TOTP factor per account.
CREATE UNIQUE INDEX identkit_totp_factors_one_active_idx ON identkit_totp_factors (account_id)
  WHERE activated_at IS NOT NULL;

CREATE INDEX identkit_totp_factors_account_idx ON identkit_totp_factors (account_id);
