-- identkit schema, version 3.
-- Throttles: a count of failed attempts since the last success that a new window does not
-- reset. It drives the consecutive-failure limit (`maxConsecutiveFailures`). Existing rows
-- start at 0.
-- Enrollment tokens: a revocation time. A new token or an administrative revocation sets it on
-- the earlier tokens of the account, and a revoked token cannot be used.

ALTER TABLE identkit_throttles
  ADD COLUMN consecutive_failures integer NOT NULL DEFAULT 0
  CHECK (consecutive_failures >= 0);

ALTER TABLE identkit_enrollment_tokens ADD COLUMN revoked_at timestamptz;

CREATE INDEX identkit_enrollment_tokens_account_idx ON identkit_enrollment_tokens (account_id);
