# identkit

Identity toolkit for TypeScript: accounts, e-mail codes, passkeys, TOTP, sessions, step-up and approval evidence.

Status: early development, release 0.1.1. It covers sign-in by e-mail code, passkeys, TOTP
(authenticator apps), sessions, step-up, approval evidence at two levels, an identity
verification port and storage. See "Not built" for what comes later.

identkit is a library, not a server. The core has no HTTP framework dependency: you call it from
your own routes and set cookies yourself.

## Install

```sh
pnpm add identkit
```

For the PostgreSQL store, also install Kysely and a PostgreSQL driver such as `pg`:

```sh
pnpm add kysely pg
```

## Requirements

- ESM only.
- Root entry `identkit` and `identkit/testing`: Node.js 24 or later, or a runtime with the Web
  Crypto API (`globalThis.crypto`) such as Cloudflare Workers, also without `nodejs_compat`.
  They import no Node built-in module. CI checks this statically with `pnpm check:runtime` and
  runs the built entries in workerd without `nodejs_compat` with `pnpm check:workerd`.
- `identkit/postgres`: Node.js 24 or later, PostgreSQL 17 (the version the test suite runs
  against) and [Kysely](https://kysely.dev) 0.29 (optional peer dependency).

### Sync and async pairs

Web Crypto has no synchronous hash, HMAC or signature. A few functions that were synchronous
before Web Crypto support keep their signature and results, but they work only on Node: they
load `node:crypto` when called and throw `NodeCryptoUnavailableError` (code
`node_crypto_unavailable`) elsewhere. Each has an async sibling with the same result that works
everywhere:

| Node only, sync              | Any runtime, async                |
| ---------------------------- | --------------------------------- |
| `hashPayload`                | `hashPayloadAsync`                |
| `approvalChallenge`          | `approvalChallengeAsync`          |
| `generateTotpCode` (testing) | `generateTotpCodeAsync` (testing) |
| fake adapter `callbackFor`   | fake adapter `callbackForAsync`   |

`createSoftwareAuthenticator` (testing) has no async form: its `register` and `assert` sign with
`node:crypto` and need Node. identkit's own code uses only the async forms. On Web Crypto
runtimes, create keys with `crypto.getRandomValues(new Uint8Array(32))` instead of
`randomBytes(32)` from the quick start.

## Quick start

```ts
import { randomBytes } from "node:crypto";
import { createAesGcmSealer, createHmacHasher, createIdentkit, createMemoryStore } from "identkit";

const identkit = createIdentkit({
  config, // see "Configuration": every time and limit value is required
  policy: {
    signInMethods: ["email_otp", "passkey"],
    secondFactor: "if_enrolled",
    secondFactorMethods: ["passkey", "totp"],
    stepUpMethods: ["passkey", "totp"],
    approvalEvidenceLevels: ["signature"],
    createAccountOnFirstSignIn: true,
  },
  isPrivilegedAccount: (account) => adminEmails.has(account.email), // or () => false
  store: createMemoryStore(), // or createPostgresStore(db) from "identkit/postgres"
  hasher: createHmacHasher(secretKeyBytes), // at least 32 random bytes, kept secret
  sealer: createAesGcmSealer({ keys: { k1: sealKeyBytes }, activeKeyId: "k1" }), // for TOTP
  mail: { sendCode: async ({ to, code, expiresInMinutes }) => sendYourMail(to, code) },
  audit: { emit: (event) => auditLog.write(event) },
});

// Route "request code"
const requested = await identkit.emailSignIn.requestCode({ email });
// Route "verify code"
const result = await identkit.emailSignIn.verifyCode({ flowId, code });
if (result.status === "signed_in") setSessionCookie(result.token);

// Every authenticated request
const session = await identkit.sessions.validate(tokenFromCookie);
```

## Public API

`createIdentkit(options)` returns these services:

- `emailSignIn`: `requestCode({ email })`, `verifyCode({ flowId, code })`.
- `passkeys`: `startRegistration(grant)`, `finishRegistration(grant, response)`,
  `startSignIn()`, `finishSignIn(response)`, `startSecondFactor(pendingToken)`,
  `finishSecondFactor(pendingToken, response)`, `list(accountId)`, `remove(sessionToken, id)`,
  `revoke(accountId, id)`, `issueEnrollmentToken(accountId)`, `revokeEnrollmentTokens(accountId)`.
- `totp`: `startEnrolment(sessionToken)`, `confirmEnrolment(sessionToken, { factorId, code })`,
  `verifySecondFactor(pendingToken, { code })`, `get(accountId)`, `remove(sessionToken)`,
  `revoke(accountId)` (also deletes pending enrolments), `reseal(accountId)`.
- `stepUp`: `requestEmailCode(sessionToken)`, `verifyEmailCode(sessionToken, { flowId, code })`,
  `startPasskey(sessionToken)`, `finishPasskey(sessionToken, response)`,
  `verifyTotp(sessionToken, { code })`.
- `sessions`: `validate(token)`, `requireStepUp(token, { methods })`, `rotate(token)`,
  `revoke(token)`, `revokeById(id)`, `revokeAll(accountId, { exceptSessionId })`.
- `approvals`: `start({ sessionToken, payloadHash, levels? })`,
  `verify({ sessionToken, payloadHash, levels?, response })` or
  `verify({ sessionToken, payloadHash, levels?, approvalId, code })`.
- `accounts`: `create({ email })`, `get(id)`, `findByEmail(email)`, `disable(id)`, `unlock(id)`,
  `unlockAddress(email)`.
- `identityVerification`: `start({ accountId, returnUrl })`, `handleCallback(payload)`,
  `refresh(verificationId)`, `get(verificationId)`.

Administrative calls take bare ids and trust their caller. Expose them only to privileged code,
or check ownership yourself before you pass client input: all of `accounts`,
`passkeys.list`, `passkeys.revoke`, `passkeys.issueEnrollmentToken`,
`passkeys.revokeEnrollmentTokens`, `totp.get`, `totp.revoke`,
`totp.reseal`, `sessions.revokeById`,
`sessions.revokeAll`, `identityVerification.start`, `identityVerification.refresh` and
`identityVerification.get`.

Standalone functions: `checkApprovalEvidence({ evidence, verifier | hasher })`, `hashPayload(payload)`,
`hashPayloadAsync(payload)`, `approvalChallenge(nonce, payloadHash, accountId)`,
`approvalChallengeAsync(nonce, payloadHash, accountId)`, `normalizeEmail(input)`, `parseConfig(input)`,
`createAesGcmSealer({ keys, activeKeyId })`, `applyThrottle(state, at, rule)`, `lockDuration(rule, lockCount)` and the type `ThrottleState` (for custom stores). Constant `TOTP_INTEROPERABLE_PARAMETERS`
(`{ algorithm: "SHA1", digits: 6 }`).

`checkApprovalEvidence` returns an object with a `status`. Switch on the exact status and
accept only the one you mean: the object is always truthy, so never use it as a boolean, and
never accept on `status !== "invalid"`. It takes exactly one options object and throws
`InvalidArgumentError` (code `invalid_argument`) for any other shape, also from untyped
JavaScript. It replaces `verifyApprovalEvidence` from the first increment, which is gone
without an alias, so an old call site fails instead of accepting.

Signature proofs stored from the first increment have no `level` field; `checkApprovalEvidence`
reports them as `invalid`. Add `level: "signature"` to them before you check them again.

`approvals.verify` returns `{ status: "approved", evidence }`. `evidence.level` comes from the
pending approval that `start` stored, never from the verify input; check it before you show or
use the evidence.

Subpath `identkit/postgres`: `createPostgresStore(db)`, `migrateIdentkit(db)`, `MIGRATIONS_DIR`.

Subpath `identkit/testing`: `createFakeClock`, `createRecordingMailSender`,
`createRecordingAuditSink`, `createFakeIdentityVerificationAdapter`,
`createSoftwareAuthenticator`, `createTestSealer`, `generateTotpCode`, `generateTotpCodeAsync`.
These are for tests and demos only.

Passkey options and responses use the WebAuthn JSON forms, so a browser can pass them to
`PublicKeyCredential.parseCreationOptionsFromJSON()` and send back `credential.toJSON()`.

## Sign-in policy

The operator chooses the methods. identkit enforces the policy on every call; it does not store
the policy or decide who may change it. Pass a function to apply policy changes at once.

Every field is required; there is no default.

| Field                        | Values                                         | Effect                                                                                                                                                                                     |
| ---------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `signInMethods`              | `email_otp`, `passkey`                         | Methods that may start a session. TOTP never starts a session on its own.                                                                                                                  |
| `secondFactor`               | `none`, `if_enrolled`                          | After an e-mail code: full session, or a pending state that needs a second factor if the account has one (passkey or TOTP).                                                                |
| `secondFactorMethods`        | `passkey`, `totp` (one or both)                | Methods that may complete the pending state.                                                                                                                                               |
| `stepUpMethods`              | `email_otp`, `passkey`, `totp`                 | Methods that may satisfy a step-up. `requireStepUp` can narrow the list, never widen it.                                                                                                   |
| `approvalEvidenceLevels`     | `signature`, `code-confirmation` (one or both) | Approval evidence levels accepted, exactly as listed. `["signature"]` refuses code confirmations; a code-only list refuses signatures. A call can narrow it with `levels`, never widen it. |
| `createAccountOnFirstSignIn` | `true`, `false`                                | If false, an e-mail code sign-in for an unknown address fails like a wrong code.                                                                                                           |

Second factor after an e-mail code:

- The option `isPrivilegedAccount(account)` is required and must return a boolean (anything
  else fails the sign-in). The consumer decides who is privileged.
  A privileged account always needs a second factor, whatever `secondFactor` says. If it has
  none, the e-mail code yields no session: `second_factor_unavailable` with reason
  `enrolment_required`. Onboard such accounts with a passkey enrollment token, or enrol the
  factor before you mark the account privileged. If the hook throws, the sign-in fails.
- With `if_enrolled` (or a privileged account), every enrolled factor counts, also one that
  `secondFactorMethods` does not allow. If the account has factors but none is allowed, the
  answer is `second_factor_unavailable` with reason `method_not_allowed`, not a session from the
  code alone. So a change of `secondFactorMethods` cannot lower the sign-in of an account below
  its factors. A change of `secondFactor` to `none` does: non-privileged accounts then sign in
  with the e-mail code alone, whatever factors they have.
- A TOTP factor counts at sign-in even if the policy names TOTP only through
  `approvalEvidenceLevels`. With `if_enrolled` and no `totp` in `secondFactorMethods`, such an
  account gets `method_not_allowed`; list `totp` in `secondFactorMethods` if you let accounts
  enrol TOTP.
- `second_factor_required` lists the `methods` that can complete the sign-in. Only the holder of
  a valid code sees them.

OWASP ASVS 5.0.0 requirement 6.3.6 (Level 3) says e-mail is not used as an authentication
mechanism, and NIST SP 800-63B-4 does not accept e-mail as an out-of-band authenticator. An
e-mail code is a proof of control of the address. For sensitive actions, require a passkey
step-up: `sessions.requireStepUp(token, { methods: ["passkey"] })`.

## Configuration

Every time and limit value is required configuration. identkit has no hidden defaults. The
example values below are what the tests use. Values marked "assumption" are not confirmed by a
standard or an owner decision; choose your own from your risk analysis.

| Setting                                          | Example | Bounds enforced                          | Source                                                                                                                                                                    |
| ------------------------------------------------ | ------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `emailOtp.codeTtlSeconds`                        | 600     | 60 to 600                                | Upper bound: OWASP ASVS 5.0.0 6.5.5 (out-of-band codes at most 10 minutes). Value: assumption at the bound.                                                               |
| `emailOtp.maxAttemptsPerCode`                    | 5       | 1 to 10                                  | Assumption                                                                                                                                                                |
| `emailOtp.resendCooldownSeconds`                 | 30      | 1 to 3600                                | Assumption                                                                                                                                                                |
| `emailOtp.addressLockout.maxFailures`            | 10      | 1 to 100                                 | Failures per window. Assumption.                                                                                                                                          |
| `emailOtp.addressLockout.maxConsecutiveFailures` | 100     | 1 to 100, at least `maxFailures`         | Failures since the last success, across windows. Upper bound taken from NIST SP 800-63B-4 (at most 100 consecutive failed attempts per authenticator). Value: assumption. |
| `emailOtp.addressLockout.windowSeconds`          | 900     | 60 to 86400                              | Assumption                                                                                                                                                                |
| `emailOtp.addressLockout.lockSeconds`            | 900     | 60 to 86400                              | Assumption                                                                                                                                                                |
| `emailOtp.addressLockout.maxLockSeconds`         | 86400   | 60 to 30 days, at least `lockSeconds`    | Assumption                                                                                                                                                                |
| `sessions.idleTimeoutSeconds`                    | 900     | 60 to 86400                              | Assumption (ASVS 7.3.1 asks for a documented inactivity timeout, no value)                                                                                                |
| `sessions.absoluteTimeoutSeconds`                | 43200   | 60 to 30 days, at least the idle timeout | Assumption (ASVS 7.3.2 asks for a documented maximum lifetime, no value)                                                                                                  |
| `sessions.pendingTimeoutSeconds`                 | 300     | 30 to 3600                               | Assumption                                                                                                                                                                |
| `stepUp.validitySeconds`                         | 300     | 30 to 3600                               | Assumption                                                                                                                                                                |
| `webauthn.challengeTtlSeconds`                   | 300     | 30 to 600                                | Assumption                                                                                                                                                                |
| `identityVerification.timeoutSeconds`            | 1800    | 60 to 7 days                             | Assumption                                                                                                                                                                |
| `enrollment.tokenTtlSeconds`                     | 86400   | 60 to 7 days                             | Assumption                                                                                                                                                                |
| `totp.issuer`                                    | text    | 1 to 64 characters, no colon             | Design choice: the name the authenticator app shows                                                                                                                       |
| `totp.algorithm`                                 | `SHA1`  | `SHA1`, `SHA256`, `SHA512`               | RFC 6238 allows all three. `SHA1` is the interoperable value (assumption, see "TOTP")                                                                                     |
| `totp.digits`                                    | 6       | 6 or 8                                   | RFC 4226 allows 6 to 8 digits. 6 is the interoperable value (assumption, see "TOTP")                                                                                      |
| `totp.driftSteps`                                | 1       | 0 to 1                                   | Upper bound: RFC 6238 section 5.2 recommends at most one time step. Value: assumption at the bound.                                                                       |
| `totp.enrolmentTtlSeconds`                       | 600     | 60 to 900                                | Assumption                                                                                                                                                                |
| `totp.approvalTtlSeconds`                        | 300     | 30 to 600                                | Assumption                                                                                                                                                                |
| `totp.lockout.maxFailures`                       | 10      | 1 to 100                                 | Failures per window. Assumption.                                                                                                                                          |
| `totp.lockout.maxConsecutiveFailures`            | 100     | 1 to 100, at least `maxFailures`         | Failures since the last success, across windows. Upper bound taken from NIST SP 800-63B-4 (at most 100 consecutive failed attempts per authenticator). Value: assumption. |
| `totp.lockout.windowSeconds`                     | 900     | 60 to 86400                              | Assumption                                                                                                                                                                |
| `totp.lockout.lockSeconds`                       | 900     | 60 to 86400                              | Assumption                                                                                                                                                                |
| `totp.lockout.maxLockSeconds`                    | 86400   | 60 to 30 days, at least `lockSeconds`    | Assumption                                                                                                                                                                |

Fixed values:

| Value                              | Setting                                                                 | Source                                                |
| ---------------------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------- |
| Code length                        | 6 decimal digits                                                        | Design choice                                         |
| Token and challenge entropy        | 256 bits from `node:crypto`                                             | ASVS 5.0.0 7.2.3 asks for at least 128 bits           |
| Hash key length                    | at least 32 bytes                                                       | Design choice (HMAC-SHA-256 key)                      |
| TOTP time step                     | 30 seconds                                                              | RFC 6238 section 5.2 recommends 30 seconds            |
| TOTP secret length                 | 20, 32 or 64 bytes (the hash output length for SHA-1, SHA-256, SHA-512) | RFC 4226 asks for at least 128 bits, recommends 160   |
| Sealer key length                  | exactly 32 bytes (AES-256)                                              | Design choice                                         |
| Code attempts per pending approval | 1                                                                       | Design choice: a wrong code ends the pending approval |

Options that are not configuration but are required: `isPrivilegedAccount` (see "Sign-in
policy"), and `sealer` whenever the policy names TOTP (`secondFactorMethods`, `stepUpMethods`,
or `code-confirmation` in `approvalEvidenceLevels`). With a policy object, a missing sealer fails at
`createIdentkit`; with a policy function, at the first TOTP call.

`webauthn` also needs `rpId` (your host name), `rpName` and `origins` (full origins, https only,
plain http only for `localhost`).

## How the rules work

E-mail codes:

- The request path never reads account data. A known and an unknown address get the same
  answer and the same work: a code goes to both. An account is created or found only after a
  correct code.
- A code is stored as an HMAC over the flow id, purpose, address, session and code. It works
  once, for the flow that requested it, until it expires. Attempts are counted before the
  comparison, so concurrent guesses cannot exceed the limit. After the limit the flow locks.
- Failed attempts are also counted per address and purpose across flows, for known and unknown
  addresses alike, with two limits:
  - Per window: after `maxFailures` failures in one window, the address locks for `lockSeconds`.
    A new window starts this count again.
  - Consecutive: after `maxConsecutiveFailures` failures since the last success, the address
    locks, whatever the windows. A new window does not start this count again. While the count
    is at the limit, the end of each lock lets exactly one attempt through. The attempt after
    it locks the address again, whatever its code; a correct code in that one attempt resets
    the counts. Between the two attempts the address does not show as locked, so a code request
    still gets a code.
- Each further lock without a success in between lasts twice as long, up to `maxLockSeconds`. A
  success resets both counts and the lock length. An attacker who stays just under the window
  limit is locked at the consecutive limit. Example with the values above: 100 wrong codes in
  the first 2.5 hours, then 6 more in the rest of the day, then about one per day. That rate
  holds only while nobody enters a correct code. Each success by the owner resets the counts and
  gives the attacker `maxConsecutiveFailures` new attempts: an owner who signs in every day
  allows about 100 wrong codes per day.
- identkit does not disable an address for good at the consecutive limit: every lock ends on
  time. NIST SP 800-63B-4 asks that an authenticator allows at most 100 consecutive failed
  attempts. identkit holds that bound until the first consecutive lock; after it, one more
  attempt is allowed per lock, at most one per `maxLockSeconds` once the lock length reached it.
  The timed release lets the owner back in once the attacker stops. It does not stop a
  persistent attacker: two attempts at the end of each lock keep the address locked for as long
  as the attacker goes on.
- The way out is the operator call `accounts.unlock(accountId)`, or `accounts.unlockAddress(email)`
  for an address without an account. It clears the lock, the lock length and both counts of the
  address (sign-in and step-up) and, for `unlock`, of the account's TOTP. It writes the audit
  event `lockout.released` before it clears anything, so a lock is never lifted without the
  event; if the call throws, some locks may be lifted and others not, so call it again. Restrict
  it to an operator role: whoever can call it can guess without limit. A passkey sign-in is not
  affected by the e-mail or TOTP locks.
- A person who can request codes for an address can trigger a lock: it trades a denial of
  service for brute-force protection. Escalation makes the brute-force bound stronger and a
  lasting lockout cheaper: once the consecutive limit is reached, two attempts at the end of
  each lock keep the address locked. Set `maxLockSeconds` equal to `lockSeconds` to turn
  escalation off; the consecutive limit still applies.
- identkit limits per address only. Add rate limits per client and in total in your HTTP layer:
  an attacker who guesses against many addresses at once is not limited by the per-address
  count.
- A new code for the same address and purpose supersedes the previous one. The resend cooldown
  applies per address and purpose. Both apply to every address, so they reveal no account, but a
  `cooldown` answer shows that someone requested a code for the address in the last seconds. The
  owner always gets the newest code by mail.
- A success resets the failure count of the address. Someone who probes the count with wrong
  codes can therefore tell that a correct code was entered for the address in between. The probe
  is noisy: the owner receives every code it requests.
- The mail sender receives only the recipient, the code, the purpose and the lifetime.

Sessions:

- Tokens are 256-bit random values. The store holds only their HMAC.
- `validate` applies the idle and the absolute timeout and extends the idle time.
- Every privilege change issues a new token and invalidates the old one: completing the second
  factor, every step-up, and `rotate`.
- A fresh sign-in counts as a step-up by the method used.
- A session waiting for its second factor is not a session: `validate` returns null for it.

Passkeys:

- Registration asks for a discoverable credential with user verification and no attestation.
  identkit accepts only the `none` attestation format.
- The first passkey needs a full session with a fresh step-up. A further passkey needs a fresh
  passkey step-up. An enrollment token (single use, for onboarding or recovery) also allows
  registration. Adding or removing a passkey revokes the other sessions of the account.
- Enrollment tokens can be revoked. A new token revokes every earlier token of the account, and
  so do `passkeys.revoke` and `passkeys.revokeEnrollmentTokens`. A registration that is using a
  token at that moment fails its next check after the insert and its passkey goes. A
  registration that passed its last check before the revocation keeps its passkey, so list the
  account's passkeys after a revocation. For a recovery, revoke the lost passkey first and issue
  the token after it.
- Every challenge is single use, bound to its purpose, and expires. The challenges of
  registration, second factor, step-up and approval are also bound to a session. The challenge
  of the discoverable sign-in (`startSignIn`) has no session: any client can complete it with a
  registered passkey. Origin and RP ID checks protect it, as in plain WebAuthn.
- Assertions need user verification, a configured origin and the RP ID. Ceremonies in a
  cross-origin frame are refused. The signature counter must increase unless the authenticator
  always reports zero.
- After a passkey ceremony wrote its result, identkit checks again that the same credential (id,
  account and public key) is still registered and the account is active. A revocation that races
  with a sign-in, second factor, step-up or approval therefore yields no session, step-up or
  proof. A new passkey is stored as pending: no read sees it, so it cannot sign in, step up or
  approve. The registration applies its grant again after the insert and activates the passkey
  only if the session is still live and no other passkey appeared meanwhile; otherwise it
  deletes it. After the activation it checks once more; if the grant no longer holds, it deletes
  the passkey and ends every session of the account; an error on the way does the same. A crash
  in between leaves an unusable pending row.
- If the store fails on both deletes of that passkey, identkit tries twice to disable the
  account, ends all its sessions and throws: the passkey may still be active without a valid
  grant. The audit event `passkey.registration_failed` says `cleanup_failed_account_disabled`
  (with an `account.disabled` event) or, if the disable failed too,
  `cleanup_failed_disable_failed`. In the second case the account stays active and the passkey
  can sign in; `finishRegistration` then throws `PasskeyCleanupError`, which names the account
  and the credential, so your code learns it also when the audit sink was down. In both cases
  an operator first removes the passkey with `passkeys.revoke(accountId, credentialId)` (the
  credential id is in the error, or in `passkeys.list(accountId)`) and only then enables the
  account again in the store; identkit has no call to enable an account. Enabling it first
  brings the passkey back into use.
- A registration that is already running is cancelled only by revocation, not by a token
  rotation: `rotate` and step-ups keep the session, so a registration started before them
  completes. Use `sessions.revokeById` or `revokeAll` to cut off a stolen session.
- Registration, removal and revocation of a passkey revoke sessions before the audit event, so
  a failing audit sink cannot skip the revocation.
- An e-mail sign-in checks the second-factor rule again after it created the session, so a first
  passkey registered at the same moment cannot leave a full session from a code alone.

TOTP:

- TOTP follows RFC 6238 over HOTP (RFC 4226), with `node:crypto` HMAC and no other dependency.
  The tests check the RFC 6238 test vectors for SHA-1, SHA-256 and SHA-512.
- SHA-1, 6 digits and 30 seconds is the interoperable choice: several authenticator apps are
  reported to ignore the `algorithm` and `digits` parameters of a provisioning URI and always
  use these values. This is an assumption from common reports; identkit was not tested with
  real apps. An enrolled factor keeps its algorithm and digits when the configuration changes.
- Enrolment needs a full session with a fresh step-up; if the account has a passkey, a passkey
  step-up. It returns the secret (base32) and an `otpauth://` provisioning URI once, for a QR
  code that your UI renders. The factor stays pending, invisible to every check, until
  `confirmEnrolment` accepts a first valid code within `enrolmentTtlSeconds`, from the same
  session. The confirming code's time step is consumed. An account has at most one active TOTP
  factor; remove it before you enrol another.
- After the activation identkit checks the grant once more. If the session was revoked or its
  step-up lost meanwhile, the factor goes and every session of the account ends. The same
  cleanup runs if anything throws from the activation on, also an activation that committed
  and then lost its reply. If the store fails on every delete (two tries, then a delete of all
  the account's factors), identkit tries twice to disable the account, ends all its sessions
  and throws: the factor may still be active, and someone without the grant may know its
  secret. The audit event `totp.enrolment_failed` says `cleanup_failed_account_disabled`
  (with an `account.disabled` event) or, if the disable failed too,
  `cleanup_failed_disable_failed`. On the error paths no grant may have been lost; the account
  is disabled all the same. An operator removes the factor with `totp.revoke(accountId)` and
  enables the account again in the store; identkit has no call to enable an account.
- A code is accepted within `driftSteps` time steps on either side of the current one. All
  candidates are computed and compared in constant time.
- Replay: the store keeps the latest accepted time step per factor and accepts a step only if
  it is higher, in one atomic compare-and-set (a conditional `UPDATE` in PostgreSQL). So a step
  is accepted once, for any purpose: a code used for a sign-in, a step-up, an approval or the
  enrolment cannot be used again, also not by a parallel request, and an older step is refused
  after a newer one. RFC 6238 section 5.2 asks that an OTP is not accepted a second time.
- Failed codes count per account, across second factor, step-up and approval, because they all
  test the same secret. They are counted before the comparison, so parallel guesses cannot
  exceed the limit. The lock and its escalation work like the e-mail address lock; a success
  resets the count. Confirmation attempts count separately per account. Anyone who holds the
  first factor (a pending session) or a session can trigger the lock: a denial of service traded
  for brute-force protection. As for e-mail codes, every success (a second factor, a step-up or a
  code approval by the owner) gives a guesser `maxConsecutiveFailures` new attempts, and a
  persistent guesser keeps TOTP locked; `accounts.unlock(accountId)` lifts the lock.
- Adding or removing a second factor needs a fresh step-up with the strongest factor the
  account has: passkey, else TOTP; with no factor, any fresh step-up. So a first passkey on an
  account with only TOTP needs a TOTP step-up. Removing a passkey still needs a passkey step-up.
  The named step-up counts only while the policy still lists its method in `stepUpMethods`: if
  the operator drops it, only an administrative call (`passkeys.revoke`, `totp.revoke`, an
  enrollment token) can change the account's factors.
  Enrolment, removal and administrative revocation revoke the other sessions of the account (all
  of them for `revoke`). If that revocation fails, enrolment removes the factor again and ends
  every session; removal retries once; `revoke` ends all sessions also when it finds no factor,
  so a retry after an error completes it.
- A TOTP second factor or step-up checks after its write that the same factor is still the
  account's active factor. A removal that raced with the check yields no session and no step-up.

Secret storage and rotation:

- A TOTP secret must be read back to verify a code, so it cannot be hashed. identkit stores it
  only sealed through the `SecretSealer` port: `seal(plaintext, context)` and
  `open(sealed, context)` with authenticated encryption. The context binds the value to its
  factor id and account, so a sealed secret copied to another row does not open.
- `createAesGcmSealer({ keys, activeKeyId })` uses AES-256-GCM with a random 96-bit IV per value
  and a 32-byte key per key id that you supply. The sealed form is
  `v1.<keyId>.<iv>.<ciphertext>.<tag>`; key id and context are authenticated. A wrong key, a
  changed value or another context rejects with `SealedSecretError`, which carries no data. A
  TOTP check that cannot open the secret fails closed and throws.
- Rotation: add the new key and make it active, keeping the old one. Call `totp.reseal(accountId)`
  for every account with a TOTP factor; it opens with the old key and seals with the active one
  (compare-and-set). When no stored value starts with `v1.<oldKeyId>.`, drop the old key.
  identkit does not run this job for you.
- The plaintext secret leaves identkit only in the result of `startEnrolment`. It is not in
  any later result, error, audit event or log (identkit writes no logs); a test scans every
  emitted event, error and console call. identkit wipes its own buffer copies after use;
  JavaScript strings it returned once cannot be wiped.
- Implement `SecretSealer` yourself to keep the key in a key management service.

Approval evidence:

Two levels. Every evidence and every approval event carries `level`, so you can show and
report it. A signature is a proof; a code confirmation is a server record, not a proof.

Choosing the level:

- The policy lists the accepted levels (`approvalEvidenceLevels`). A call can pass `levels` to
  narrow them for one action, for example `levels: ["signature"]` for a high-value payment. Set
  `levels` in your server code, never from client input. A filter that leaves no level throws
  `MethodNotAllowedError`; a malformed one throws `InvalidArgumentError`.
- `start` picks the level, never the client: the strongest one that is allowed and that the
  account can use. That is `signature` if the account has a passkey, else `code-confirmation`
  if it has a TOTP factor.
- `verify` consumes only a pending approval that `start` stored, and the evidence gets that
  approval's level. The level must still be allowed by the policy and `levels` at that moment.

Level `signature`:

- The challenge is `SHA-256("identkit/approval/v1" || nonce || payloadHash || accountId)`. The
  person signs it with a passkey of the session's account. `verify` recomputes the challenge from
  the payload hash it receives, so a signature for one payload cannot approve another.
- The evidence holds the raw assertion and the nonce. `checkApprovalEvidence({ evidence,
verifier })` checks it again later with a public key you supply: challenge, signature, RP ID,
  origin and counter, and returns `{ status: "verified", level: "signature" }`. It cannot check
  `verifiedAt`, and it cannot know that `credentialId` belonged to `accountId`: take the public
  key from your own record of that account's credentials.

Level `code-confirmation`:

- `start` returns an `approvalId` for one pending approval of the session's account. `verify`
  with the `approvalId` and a current TOTP code consumes the pending approval (one attempt) and
  the code's time step. It succeeds only for the same session, account and payload hash. After
  the code is accepted, identkit checks again that the factor is still active and the session
  still live, so a removal or revocation that raced with the check yields no evidence.
- The evidence holds `version`, `level`, `accountId`, `payloadHash`, `recordedAt`, the accepted
  `timeStep` and `mac`: an HMAC over these fields with the `SecretHasher` key. It holds no code.
- What this level does not give:
  - The code is not bound to the payload. It shows that someone with the account's TOTP secret
    entered a current code while the approval was pending, not that the person saw the payload.
  - The server holds the TOTP secret too, so the server, or anyone with its sealed store and
    key, could produce the same record.
  - A third party cannot check it. `checkApprovalEvidence({ evidence, hasher })` needs the
    deployment's `SecretHasher`, rejects a record whose HMAC does not match as `invalid`, and
    reports a matching one as `recorded_not_independently_verifiable`, never `verified`. That
    status means only that this deployment wrote the record and nobody changed it since.
- Use it where an authenticator app is the only second factor and a server record is enough.
  For evidence that others must be able to check, require level `signature`.

One account per person:

- An address belongs to at most one account.
- An identity verification result carries a stable person key. identkit stores its HMAC and
  links it to at most one account. A second account for the same person ends as `conflict`.
- A verification reads `verified` only after the person is linked. If the link fails, it reads
  `pending` and the next `refresh` completes it. Such a verification does not time out: it waits
  for the vendor to report success again.

## Identity verification port

Implement `IdentityVerificationAdapter` for a vendor: `start`, `parseCallback` (authenticate the
callback, throw if it is not authentic) and `fetchResult`. A result reports `verified` with an
assurance level (`low`, `substantial`, `high`), an evidence reference and a person key, or
`failed`, or `pending`. identkit applies the timeout. `createFakeIdentityVerificationAdapter`
succeeds, fails or never answers, for tests and demos. It is unsafe for production: it verifies
nobody. Without `callbackSecret` it signs callbacks with a random secret per instance.

## Audit events

identkit awaits `audit.emit` for every security-relevant event. If the sink throws, the operation
fails. Events carry ids and reasons, never a code, token, challenge, key, person key, TOTP
secret, sealed secret, provisioning URI or e-mail address. `addressDigest` is the HMAC of the
address, for correlation. Approval events carry `level`; TOTP events carry `factorId`.

## Cookies

identkit returns tokens; your HTTP layer stores them. Recommendations:

- Name the session cookie with the `__Host-` prefix: `Secure`, `Path=/`, no `Domain`.
- Set `HttpOnly` and `SameSite=Lax` (or `Strict` if your flows allow it).
- Do not set `Max-Age` beyond the absolute timeout. A session cookie without `Max-Age` is fine.
- Store the pending token of a second-factor sign-in and the `flowId` of a code request in
  separate short-lived cookies with the same attributes.
- After a rotation, replace the cookie with the new token in the same response.
- Check the `Origin` header on state-changing requests in addition to `SameSite`.

## Storage

`createMemoryStore()` keeps everything in process memory. Use it for tests and demos.

`createPostgresStore(db)` takes a Kysely instance with a PostgreSQL dialect. Apply the plain SQL
migrations in `migrations/` first, with `migrateIdentkit(db)` or with your own migration tool.
Use a database role for migrations that differs from the runtime role.

identkit does not delete expired rows. Remove expired codes, challenges and sessions, pending
credentials older than the challenge lifetime, and pending TOTP factors (`activated_at` null)
older than `totp.enrolmentTtlSeconds`, with a scheduled job if you need to.

Migration `0002_totp.sql` adds the TOTP factor table and widens two check constraints (step-up
method `totp`, challenge purpose `approval_code`). It does not change `0001_initial.sql`.

Migration `0003_lockout_and_enrollment_revocation.sql` adds the consecutive failure count to
`identkit_throttles` (existing rows start at 0) and `revoked_at` to
`identkit_enrollment_tokens`. It does not change the earlier files.

## Operator duties

identkit leaves these to the consumer:

- Purge old rows. identkit does not delete them (see "Storage"). Each `passkeys.startSignIn` and
  each `emailSignIn.requestCode` writes rows without authentication (a challenge; a flow, a send
  gate and a mail), so without a scheduled job these tables grow with every call.
- Purge `identkit_throttles` only by this rule, or not at all. A deleted row resets the failure
  counts and the lock length of its address or account, and gives an attacker a fresh set of
  guesses. The rule deletes rows that are idle: their last window started and their last lock
  ended more than `N` days ago. It never deletes a running lock. It does delete rows with a
  failure count or a lock count above zero, by design: a success deletes the row, so every
  stored row has one. After a purge the key starts from zero: `maxConsecutiveFailures`
  attempts, then one per lock end while the lock length grows back to `maxLockSeconds`. With
  the example values that is 106 attempts in the first day (100, then 6 lock ends; a test
  checks this count), then about one per day. An attacker who keeps guessing keeps the row
  fresh and is never purged; one who waits `N` days between bursts gains at most about 106
  attempts per key per `N` days. Choose `N` of at least one day, so no running window is
  purged, and from your risk analysis (30 days is an example, not a recommendation from a
  standard):

  ```sql
  DELETE FROM identkit_throttles
  WHERE window_start < now() - interval '30 days'
    AND (locked_until IS NULL OR locked_until < now() - interval '30 days');
  ```

- Restrict `accounts.unlock` and `accounts.unlockAddress` to an operator role, like every other
  administrative call.
- A custom store (your own `IdentkitStore`) must apply the throttle rules in
  `throttle.reserve`: call `applyThrottle(state, at, rule)` from `identkit` on the stored state
  (`null` for a key without a row) inside one atomic section, store every field of `next`, and
  return `result`. A store that skips a field compiles, but skips a limit. The other two
  throttle calls:
  - `throttle.peek(key, at)` returns the stored `lockedUntil` while `at` is before it, else
    null. It writes nothing.
  - `throttle.reset(key)` removes every field of the key; the PostgreSQL store deletes the row.
    A reset that clears only the attempts keeps the consecutive count and the lock length, so a
    success or an unlock stays incomplete.

  A store does not need `lockDuration`: `applyThrottle` computes the lock. The PostgreSQL store
  expects the isolation level READ COMMITTED, the PostgreSQL default.

- Limit unauthenticated calls in your HTTP layer: per client and in total, for `requestCode`,
  `startSignIn` and every verify route. identkit limits per address and per account only.
- Treat audit events as personal data where the payload is. Approval events carry
  `payloadHash`, a plain SHA-256 of the approved payload. If the payload has low entropy (for
  example an account number and an amount), a reader of the audit log can find it by trying
  values. Put a random id into every payload that you hash.
- Keep `identkit/testing` out of production code. Its fake adapters verify nobody.

## Development

```sh
pnpm install
pnpm check          # typecheck, lint, format check, tests, build
```

The PostgreSQL tests run only with a throwaway database. Each run creates and drops its own
schema:

```sh
DATABASE_URL=postgres://user:password@localhost:5432/scratch pnpm test:postgres
```

Without `DATABASE_URL` the PostgreSQL suite is reported as skipped.

## Not built

- OIDC, token issuance, SMS codes and delegated agent identities.
- QR code rendering: identkit returns the provisioning URI as a string.
- Recovery codes, and TOTP enrolment through an enrollment token (privileged accounts without a
  factor onboard through a passkey enrollment token).
- More than one TOTP factor per account.
- A built-in job that reseals every TOTP secret after a key change; call `totp.reseal` per
  account.
- A rule that requires a second factor at step-up for privileged accounts: the hook applies to
  sign-in after an e-mail code only.
- Tests with real authenticator apps and real devices. The TOTP code is checked against the RFC
  test vectors and a software generator only.

## Security

To report a vulnerability, use GitHub private vulnerability reporting: open the "Security" tab of
the repository and choose "Report a vulnerability". Do not open a public issue for a
vulnerability. See [SECURITY.md](SECURITY.md).

## Licence

MIT, see [LICENSE](LICENSE). identkit is maintained by dectria GmbH.
