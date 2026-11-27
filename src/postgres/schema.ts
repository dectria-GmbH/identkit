/** Kysely table types for the identkit schema in `migrations/`. */
export interface IdentkitDatabase {
  identkit_accounts: {
    id: string;
    email: string;
    webauthn_user_id: string;
    status: string;
    created_at: Date;
    person_key_digest: string | null;
    assurance_level: string | null;
    identity_verified_at: Date | null;
  };
  identkit_otp_flows: {
    id: string;
    purpose: string;
    email: string;
    address_digest: string;
    session_id: string | null;
    code_digest: string;
    created_at: Date;
    expires_at: Date;
    attempts: number;
    max_attempts: number;
    consumed_at: Date | null;
    superseded_at: Date | null;
  };
  identkit_otp_send_gates: {
    gate_key: string;
    last_sent_at: Date;
  };
  identkit_throttles: {
    key: string;
    window_start: Date;
    attempts: number;
    locked_until: Date | null;
    lock_count: number;
    consecutive_failures: number;
  };
  identkit_sessions: {
    id: string;
    account_id: string;
    token_digest: string;
    state: string;
    auth_methods: string[];
    created_at: Date;
    last_seen_at: Date;
    absolute_expires_at: Date;
    step_up_method: string | null;
    step_up_at: Date | null;
    revoked_at: Date | null;
    revoke_reason: string | null;
  };
  identkit_credentials: {
    id: string;
    account_id: string;
    public_key: Uint8Array;
    /** bigint column; node-postgres returns it as a string. */
    counter: string | number;
    transports: string[];
    device_type: string;
    backed_up: boolean;
    created_at: Date;
    last_used_at: Date | null;
    activated_at: Date | null;
  };
  identkit_challenges: {
    id: string;
    challenge_digest: string;
    purpose: string;
    account_id: string | null;
    session_id: string | null;
    enrollment_token_digest: string | null;
    payload_hash: string | null;
    nonce: string | null;
    created_at: Date;
    expires_at: Date;
  };
  identkit_enrollment_tokens: {
    token_digest: string;
    account_id: string;
    created_at: Date;
    expires_at: Date;
    consumed_at: Date | null;
    revoked_at: Date | null;
  };
  identkit_verifications: {
    id: string;
    account_id: string;
    vendor_reference: string | null;
    status: string;
    assurance_level: string | null;
    evidence_reference: string | null;
    failure_reason: string | null;
    created_at: Date;
    expires_at: Date;
    completed_at: Date | null;
  };
  identkit_totp_factors: {
    id: string;
    account_id: string;
    sealed_secret: string;
    algorithm: string;
    digits: number;
    created_at: Date;
    enrolment_session_id: string | null;
    activated_at: Date | null;
    /** bigint column; node-postgres returns it as a string. */
    last_used_step: string | number | null;
    last_used_at: Date | null;
  };
  identkit_oidc_links: {
    id: string;
    account_id: string;
    link_key: string;
    provider: string;
    issuer: string;
    subject: string;
    tenant_id: string | null;
    source: string;
    created_at: Date;
  };
  identkit_migrations: {
    name: string;
    applied_at: Date;
  };
}
