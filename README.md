# identkit

Identity toolkit for TypeScript: accounts, e-mail codes, passkeys, TOTP, sessions, step-up and approval evidence.

Status: early development, release 0.1.1. It covers sign-in by e-mail code, passkeys, TOTP
(authenticator apps), sign-in through an external OpenID Connect provider (Microsoft, Google or
any other), sessions, personal API tokens, an OAuth authorization server for MCP clients,
step-up, approval evidence at two levels, an identity verification port and storage. See "Not built" for what comes later.

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

The Cloudflare D1 store (`identkit/d1`) needs no further package.

## Requirements

- ESM only.
- Root entry `identkit` and `identkit/testing`: Node.js 24 or later, or a runtime with the Web
  Crypto API (`globalThis.crypto`) such as Cloudflare Workers, also without `nodejs_compat`.
  They import no Node built-in module. CI checks this statically with `pnpm check:runtime` and
  runs the built entries in workerd without `nodejs_compat` with `pnpm check:workerd`.
- `identkit/postgres`: Node.js 24 or later, PostgreSQL 17 (the version the test suite runs
  against) and [Kysely](https://kysely.dev) 0.29 (optional peer dependency).
- `identkit/d1`: Cloudflare Workers with a D1 binding, also without `nodejs_compat`. It imports
  no Node built-in module (checked by `pnpm check:runtime`) and no Cloudflare package.

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
  store: createMemoryStore(), // or createPostgresStore(db) or createD1Store(env.DB)
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
- `accounts`: `create({ email })`, `get(id)`, `findByEmail(email)`, `disable(id)` (also revokes
  the account's sessions and API tokens and ends its OAuth grants), `unlock(id)`,
  `unlockAddress(email)`.
- `identityVerification`: `start({ accountId, returnUrl })`, `handleCallback(payload)`,
  `refresh(verificationId)`, `get(verificationId)`.
- `oidc`: `begin({ provider, loginHint? })`, `finish({ transaction, params })`,
  `importLink(input)`, `listLinks(accountId)`, `removeLink(accountId, linkId)`. See "External
  sign-in (OpenID Connect)".
- `apiTokens`: `create({ accountId, name, scopes, expiresInDays })`, `verify(token)`,
  `list(accountId)`, `revoke({ accountId, tokenId })`, `revokeAll(accountId)`, `import(input)`.
  See "Personal API tokens".
- `oauth`: `metadata`, `wwwAuthenticate(input)`, `register({ body, addressKey? })`,
  `authorize.begin`, `authorize.approve`, `authorize.deny`, `token({ form, authorization })`,
  `revoke({ form, authorization })`, `validateAccessToken(token, { resource? })`,
  `listGrants(accountId)`, `revokeGrant({ accountId, grantId })`, `revokeAll(accountId)`,
  `getClient(clientId)`, `deleteClient(clientId)`, `importClient(input)`, `importGrant(input)`,
  `purge()`. See "OAuth authorization server (MCP clients)".

Administrative calls take bare ids and trust their caller. Expose them only to privileged code,
or check ownership yourself before you pass client input: all of `accounts`,
`passkeys.list`, `passkeys.revoke`, `passkeys.issueEnrollmentToken`,
`passkeys.revokeEnrollmentTokens`, `totp.get`, `totp.revoke`,
`totp.reseal`, `sessions.revokeById`,
`sessions.revokeAll`, `identityVerification.start`, `identityVerification.refresh`,
`identityVerification.get`, `oidc.importLink`, `oidc.listLinks`, `oidc.removeLink`, every
`apiTokens` call except `verify`, and `oauth.listGrants`, `oauth.revokeGrant`, `oauth.revokeAll`,
`oauth.getClient`, `oauth.deleteClient`, `oauth.importClient`, `oauth.importGrant` and
`oauth.purge`.

Standalone functions: `checkApprovalEvidence({ evidence, verifier | hasher })`, `hashPayload(payload)`,
`hashPayloadAsync(payload)`, `approvalChallenge(nonce, payloadHash, accountId)`,
`approvalChallengeAsync(nonce, payloadHash, accountId)`, `normalizeEmail(input)`, `parseConfig(input)`,
`createAesGcmSealer({ keys, activeKeyId })`, `applyThrottle(state, at, rule)`, `lockDuration(rule, lockCount)` and the type `ThrottleState` (for custom stores),
`microsoftProvider(options)`, `googleProvider(options)`, `oidcProvider(options)`,
`createJwksCache()`, `parseBearerToken(header)`, `apiTokenOptionsSchema`, `oauthOptionsSchema` and the constant
`MICROSOFT_CONSUMER_TENANT_ID`. Constant `TOTP_INTEROPERABLE_PARAMETERS`
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

Subpath `identkit/d1`: `createD1Store(db, options?)`, `migrateIdentkitD1(db)`, `D1_MIGRATIONS`,
`D1_DEFAULT_THROTTLE_RETRIES`, `D1ThrottleContentionError` and the types `D1DatabaseLike`,
`D1StoreOptions`, `D1Migration`.

Subpath `identkit/testing`: `createFakeClock`, `createRecordingMailSender`,
`createRecordingAuditSink`, `createFakeIdentityVerificationAdapter`,
`createSoftwareAuthenticator`, `createTestSealer`, `generateTotpCode`, `generateTotpCodeAsync`,
`createFakeOidcProvider`, `createOAuthTestClient` (registers a client and drives the
authorization step, the exchange, refresh and revocation like an MCP client) and
`createPkcePair`.
These are for tests and demos only.

Passkey options and responses use the WebAuthn JSON forms, so a browser can pass them to
`PublicKeyCredential.parseCreationOptionsFromJSON()` and send back `credential.toJSON()`.

## Sign-in policy

The operator chooses the methods. identkit enforces the policy on every call; it does not store
the policy or decide who may change it. Pass a function to apply policy changes at once.

Every field is required; there is no default.

| Field                        | Values                                         | Effect                                                                                                                                                                                     |
| ---------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `signInMethods`              | `email_otp`, `passkey`, `oidc`                 | Methods that may start a session. TOTP never starts a session on its own. `oidc` is sign-in through an external provider (`identkit.oidc`).                                                |
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
| `oidc.transactionTtlSeconds`                     | 600     | 60 to 1800                               | Time between `begin` and `finish`. Assumption.                                                                                                                            |
| `oidc.clockSkewSeconds`                          | 60      | 0 to 300                                 | Tolerance for `exp`, `nbf` and `iat`. Assumption.                                                                                                                         |
| `oidc.jwksCacheSeconds`                          | 3600    | 60 to 86400                              | How long provider keys are used before a new fetch. Assumption.                                                                                                           |
| `oidc.jwksRefetchIntervalSeconds`                | 60      | 10 to 3600                               | Least time between two key fetches for an unknown key id. Assumption.                                                                                                     |
| `oidc.httpTimeoutSeconds`                        | 10      | 1 to 60                                  | Timeout of each request to the provider. Assumption.                                                                                                                      |

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

The section `oidc` is optional; every value inside it is required. It is needed only with the
option `oidc` (see "External sign-in (OpenID Connect)").

Options that are not configuration but are required: `isPrivilegedAccount` (see "Sign-in
policy"), and `sealer` whenever the policy names TOTP or the option `oidc` is set (`secondFactorMethods`, `stepUpMethods`,
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
- No idle end: set `idleTimeoutSeconds` equal to `absoluteTimeoutSeconds` (both at most 86400).
  The idle end then never comes before the absolute one, so a session lasts exactly the absolute
  time, used or not. A test checks this with 43200 seconds.
- The option `onAllSessionsRevoked(event)` is called after every `sessions.revokeAll`, also when
  `accounts.disable`, a passkey change, a TOTP change or `oidc.removeLink` calls it, and also
  when no session was live. It does not cover personal API tokens or OAuth grants:
  `sessions.revokeAll` leaves them live (see "Personal API tokens" and "OAuth authorization
  server"). `event` holds `accountId`, `exceptSessionId` (the session that stayed,
  or null) and `revokedSessionIds`. Use it to end sessions your application keeps itself, for
  example with a per-account version. It runs last: after the revocation and after the calling
  operation's own writes and audit events (the disable, the new or removed passkey, the TOTP
  change, the removed link). If it throws, the call throws `AllSessionsRevokedHookError` (after a
  rollback, `OperationRolledBackError`; see below), and everything identkit does is done: the
  identkit sessions stay revoked and the audit events are written, unless `auditError` is set
  (see below). Some calls cannot be repeated (a finished
  passkey registration or TOTP enrolment, a `totp.remove` whose factor is gone), so re-run the
  hook with `sessions.revokeAll(error.accountId, error.revokeAllOptions)`. One exception: if
  the error's `tokenRevocationError` or `grantRevocationError` is set (only `accounts.disable`
  sets them), call `accounts.disable` again instead; it also runs the hook again (see "Personal
  API tokens").
  `revokeAll` is idempotent and calls the hook also when no session was live. Make the hook
  idempotent too. On such a re-run `revokedSessionIds` is empty, because the sessions are already
  revoked: do not depend on it to find the sessions to end.
- A TOTP enrolment or a passkey registration rolls back when its grant changed before it
  completed, and when the store fails after the new factor or passkey was stored (also on the
  revocation of the other sessions): identkit removes the factor or passkey and revokes every
  session of the account. A grant change is recorded with reason `grant_changed` and the call
  returns `denied`. If an error comes up on the way (the store's, the audit sink's or the
  hook's), the call throws `OperationRolledBackError` instead, with the first error as `cause`.
  Its `hookFailed` is true if the hook threw or the store failed before identkit could call it;
  then call `sessions.revokeAll(error.accountId, error.revokeAllOptions)` to finish the
  revocation and run the hook. `revokeAllOptions` is always `{}`, so that call also ends the
  session that started the operation.
- The rule for callers: if you catch `OperationRolledBackError`, the operation did not take
  effect. One exception: a rolled-back OAuth code exchange leaves the replaced grant ended (see
  "OAuth authorization server"). Any other error means that identkit did not roll back: what it wrote before the error
  stands, and `AllSessionsRevokedHookError` means that the operation's writes are complete. An
  error from `confirmEnrolment` or `finishRegistration` can also come before the activation, so
  after any other error check `totp.get` or `passkeys.list` before you tell the person that the
  factor or passkey is active. A rollback that cannot remove the new factor or passkey throws
  the store's error or `PasskeyCleanupError` (see Passkeys and TOTP below).
- The hook runs also when the audit sink throws, on the `session.revoked` events or on the
  operation's own events, so a failing sink cannot leave your application's sessions live.
  identkit still offers every other event of the operation to the sink (a refused
  `session.revoked` does not skip `account.disabled`, `totp.removed` or `passkey.registered`).
  Then the first sink error goes up after the hook ran. If the hook throws as well,
  `AllSessionsRevokedHookError` goes up, because only the hook needs a re-run, and its
  `auditError` holds that first sink error: the refused event is missing, and later events may
  be missing too if the sink stayed down. In `totp.confirmEnrolment`, `auditError` can also hold
  the throttle store's error from the reset after a successful enrolment. Without such a
  failure, `auditError` is undefined. In short: sink fails only, the sink's error goes up; hook
  fails only, `AllSessionsRevokedHookError` without `auditError`; both fail,
  `AllSessionsRevokedHookError` with `auditError`. After a rollback, each of these goes up as
  `OperationRolledBackError` instead.
- A sink error on the `session.revoked` events is not a failed revocation: the sessions are
  revoked. On the success path a TOTP enrolment or a passkey registration then stands, as when
  the sink refuses `totp.enrolled` or `passkey.registered`, and the sink's error goes up. On a
  rollback the sink's error goes up as the `cause` of `OperationRolledBackError`, unless an
  earlier error came first.

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
  the passkey and ends every session of the account; an error on the way does the same, also a
  store error on the revocation of the other sessions after the last check (see Sessions for
  `OperationRolledBackError`). A crash in between leaves an unusable pending row.
- If the store fails on both deletes of that passkey, identkit tries twice to disable the
  account, ends all its sessions and throws: the passkey may still be active without a valid
  grant. The disable, as `accounts.disable`, also revokes the account's API tokens and ends its
  OAuth grants. The audit event `passkey.registration_failed` says
  `cleanup_failed_account_disabled` (with an `account.disabled` event, an `api_token.revoked`
  event per token and an `oauth.grant_ended` event per grant) or, if the disable failed too,
  `cleanup_failed_disable_failed`. In the second case the account may still be active, so the
  passkey can sign in, or its API tokens or OAuth grants may not be ended;
  `finishRegistration` then throws `PasskeyCleanupError`, which names the account and the
  credential, so your code learns it also when the audit sink was down. In both cases an
  operator first removes the passkey with `passkeys.revoke(accountId, credentialId)` (the
  credential id is in the error, or in `passkeys.list(accountId)`) and only then enables the
  account again in the store; identkit has no call to enable an account. Enabling it first
  brings the passkey back into use. After `cleanup_failed_disable_failed`, the operator also
  calls `accounts.disable(accountId)` until it succeeds before the account is enabled again;
  otherwise its API tokens and OAuth grants can come back into use.
- A registration that is already running is cancelled only by revocation, not by a token
  rotation: `rotate` and step-ups keep the session, so a registration started before them
  completes. Use `sessions.revokeById` or `revokeAll` to cut off a stolen session.
- Registration, removal and revocation of a passkey revoke sessions before the audit event and
  call `onAllSessionsRevoked` after it, also when the audit sink throws. So a failing audit sink
  skips neither the revocation nor the hook.
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
  secret. The disable, as `accounts.disable`, also revokes the account's API tokens and ends its
  OAuth grants. The audit event `totp.enrolment_failed` says `cleanup_failed_account_disabled`
  (with an `account.disabled` event, an `api_token.revoked` event per token and an
  `oauth.grant_ended` event per grant) or, if the disable failed too,
  `cleanup_failed_disable_failed`: the account may still be active, or its API tokens or OAuth
  grants may not be ended. On the error paths no grant may have been lost; the account is disabled all
  the same. An operator removes the factor with `totp.revoke(accountId)` and enables the account
  again in the store; identkit has no call to enable an account. After
  `cleanup_failed_disable_failed`, the operator first calls `accounts.disable(accountId)` until
  it succeeds; otherwise the account's API tokens and OAuth grants can come back into use.
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
  every session; `revoke` ends all sessions also when it finds no factor, so a retry after an
  error completes it. Removal retries once. If the retry fails too, the factor stays removed and
  `remove` throws `SessionsNotRevokedError`: a retried `remove` answers `not_found`, so finish
  with `sessions.revokeAll(error.accountId, error.revokeAllOptions)`, which also runs the hook.
  If the first attempt committed and lost its reply, the retry finds no live session: the hook
  gets an empty `revokedSessionIds`, and no `session.revoked` event is recorded for the sessions
  that the first attempt revoked.
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

## External sign-in (OpenID Connect)

identkit signs people in through an external OpenID Connect provider with the authorization code
flow, PKCE (S256), `state` and `nonce`. It is a client only: it issues no tokens, and it keeps no
provider tokens (no refresh token, no access token for APIs).

Before you turn on the option `oidc`, deploy this release to every instance and finish any
gradual deployment. An earlier release cannot read a session whose method is `oidc` and fails
it; a rollback after the first OIDC sign-in fails those sessions too (see Storage).

```ts
import { createJwksCache, googleProvider, microsoftProvider } from "identkit";

// Module scope: on Workers the keys then survive between requests of one isolate.
const jwksCache = createJwksCache();

const identkit = createIdentkit({
  ...options, // config with the `oidc` section, a sealer, a store with links
  policy: { ...policy, signInMethods: ["email_otp", "passkey", "oidc"] },
  oidc: {
    providers: [
      microsoftProvider({
        clientId,
        clientSecret,
        redirectUri: "https://app.example/auth/callback",
      }),
      googleProvider({
        clientId: gId,
        clientSecret: gSecret,
        redirectUri: "https://app.example/auth/callback",
      }),
    ],
    jwksCache,
  },
});

// Route "sign in with Microsoft"
const { authorizationUrl, transaction } = await identkit.oidc.begin({ provider: "microsoft" });
setCookie("__Host-oidc", transaction, {
  httpOnly: true,
  secure: true,
  sameSite: "Lax",
  maxAge: 600,
});
redirect(authorizationUrl);

// Route "callback"
const result = await identkit.oidc.finish({
  transaction: cookie("__Host-oidc"),
  params: new URL(request.url).searchParams,
});
// Single use: clear the transaction cookie after every finish, success or failure.
deleteCookie("__Host-oidc");
if (result.status === "signed_in") setSessionCookie(result.token);
```

Providers:

- `microsoftProvider({ clientId, clientSecret, redirectUri, tenant?, allowedTenants?, upnAsAddress?, allowGuests?, prompt? })`:
  Microsoft identity platform v2.0. `tenant` is `common` (default), `organizations`,
  `consumers` or a tenant id. Scopes `openid email profile`, `prompt=select_account` by default.
  The multi-tenant endpoints sign tokens for every tenant, so identkit checks that `iss` is
  `https://login.microsoftonline.com/{tid}/v2.0` for the token's own `tid`. `allowedTenants`
  limits sign-in to those tenant ids. `allowGuests` (default false) lets a guest bind by address,
  but never a personal account; see the binding rules.
- `googleProvider({ clientId, clientSecret, redirectUri, hostedDomains?, prompt? })`: issuer
  `https://accounts.google.com` (also accepted without `https://`, as Google documents).
  `hostedDomains` limits sign-in to those Workspace domains (`hd` claim).
- `oidcProvider({ id, issuer, authorizationEndpoint, tokenEndpoint, jwksUri, clientId, clientSecret, redirectUri, scopes?, tokenEndpointAuthMethod?, algorithms?, prompt? })`:
  any other provider. No discovery request: you give the endpoints. `iss` must equal `issuer`.
- The client secret is not a property of the returned object; identkit sends it only to the
  token endpoint. Endpoints and the redirect URI must be https (plain http only for localhost).
  identkit follows no redirect from a provider endpoint: a redirect fails the request, so the
  secret never goes to a redirect target.
- Every factory takes `extraAudiences` (default none): audiences besides the client id that you
  trust in an ID token. A token with any other audience is refused.

The flow:

- `begin` returns the authorization URL and `transaction`: state, nonce and PKCE verifier, sealed
  with your `SecretSealer` (AES-256-GCM, its own context). identkit stores nothing at `begin`.
  Keep `transaction` in a short-lived cookie (`__Host-` prefix, `HttpOnly`, `Secure`,
  `SameSite=Lax`, since the callback is a top-level GET from the provider). The cookie binds the
  flow to the browser that started it: a callback with another flow's `state` fails
  (`state_mismatch`) before any request to the provider.
- identkit keeps no state per flow, so it cannot make `transaction` single use: within its
  lifetime it opens again for another code from the same authorization URL. So clear the cookie
  after `finish`, whatever the result. Serve the callback route with `Referrer-Policy:
no-referrer`, and never redirect from it to a value from the query: a code that leaks from the
  callback URL (Referer header, logs, an open redirect) could otherwise complete a flow that an
  attacker started (RFC 9700, section 4.5.3). PKCE and the nonce do not help there, because the
  attacker started that flow.
- `finish` opens the transaction, checks its lifetime and `state`, exchanges the code with the
  verifier (client secret by `client_secret_post` for the presets, `client_secret_basic` by
  default for `oidcProvider`), and verifies the ID token: signature with the provider's keys
  (RS256 with at least 2048 bits; ES256 for `oidcProvider` if listed in `algorithms`; never
  `none` or HMAC; a token with `crit` is refused; keys come only from the configured JWKS URI),
  `iss`, `aud` contains the client id and no audience outside `extraAudiences`, `azp` is the
  client id when present and required with several audiences, `exp`, `nbf` and `iat` with
  `clockSkewSeconds`, and `nonce`. An RSA key must have at least 2048 bits and the exponent 65537.
  Provider responses are limited in bytes.
- Keys are cached per JWKS URI for `jwksCacheSeconds`. A token with an unknown key id causes one
  more fetch, at most one per `jwksRefetchIntervalSeconds`. Concurrent fetches are shared. So one
  `finish` makes at most two outgoing requests (token and keys), and one with a warm cache. Pass
  one `createJwksCache()` from module scope; without it each identkit instance has its own cache,
  which on Workers means one per request.
- Results: `signed_in` (with `accountCreated` and `linkCreated`), `second_factor_required`,
  `second_factor_unavailable`, `refused` with a reason (`organization_not_allowed`,
  `consumer_tenant`, `guest_account`, `unverified_address`, `no_account`, `account_disabled`, `account_has_link`,
  `refused_by_hook`) or `failed` with a reason (`invalid_transaction`, `transaction_expired`,
  `state_mismatch`, `provider_error` with the provider's `error` code if it is a plain word,
  `missing_code`, `token_request_failed`, `keys_unavailable`, `invalid_id_token`). Only the
  person who completed the provider's sign-in sees a refusal, and it names only their own
  address's state, so identkit returns the reason.

Links, never the address:

- identkit links an account to a subject at the provider, never to the address: Microsoft by
  tenant id and object id (`tid`, `oid`), Google by `sub`, other providers by issuer and `sub`. A
  subject belongs to at most one account (unique link key). A known subject signs in to its
  account, whatever its token says about the address. A disabled account is refused.
- `linksPerAccount` (option, default `one`): an account holds at most one link, so an account
  linked to one provider cannot sign in with another, and a second subject with the same address
  (for example a guest account or a re-created user) does not bind. `any` allows several.

First binding (no link for the subject yet), in this order:

1. `allowedTenants`, a tenant authority, or `hostedDomains` refuse other organizations
   (`organization_not_allowed`), for every sign-in, linked or not.
2. Microsoft personal accounts never bind (`consumer_tenant`), also with `allowGuests: true`: a
   token of the consumer tenant (`9188040d-6c67-4c5b-b112-36a304b66dad`), and a personal account
   invited as a guest into a work tenant (`idp` is `live.com`, a host under `live.com`, or an STS
   URI of the consumer tenant). This is identkit's requirement, not a claim that Microsoft leaves
   their address unchecked: a personal account belongs to no organization's tenant, so no tenant
   administrator has verified the domain of its address, which is what `xms_edov` reports for a
   work account. A link you import for one still signs in.
3. Microsoft guests never bind by default (`guest_account`): a user who is homed in another
   tenant or at another identity provider and signs in to your authority tenant (relevant with a
   tenant id as `tenant`). identkit counts a token as a guest's if the optional claim `acct` is 1,
   or if `idp` is present and is neither `iss` nor a Microsoft STS URI of the token's own tenant
   (Microsoft documents `idp` as equal to the issuer except for users from another tenant, and as
   `live.com` or the consumer tenant for an invited personal account). An unknown `idp` form
   counts as a guest, so it fails closed. With `allowGuests: true` a guest (except a personal
   account, see rule 2) binds by `email` with `xms_edov` true, never by `preferred_username`. A
   link you import for a guest still signs in.
   Limit: Microsoft does not document the `idp` value for a member of a federated domain (a
   tenant domain that signs in at AD FS or another identity provider). If Entra puts the
   federation provider there, identkit counts every such member as a guest and refuses its first
   binding with `guest_account`. You can tell: the person gets `refused` with `guest_account`,
   and the audit sink records `oidc.binding_refused` with that reason, while you know the person
   is a member of your tenant or your tenant has no guests. Ways out: import a link for the
   person (`oidc.importLink`; a linked subject signs in), or set `allowGuests: true`, which also
   lets real guests bind by a verified address.
4. The address must be verified by the provider (`unverified_address` otherwise): Google and
   other providers by `email_verified` true. Microsoft by `email` with the optional claim
   `xms_edov` true (add the optional claims `email` and `xms_edov` to the app registration). With
   `upnAsAddress: true`, Microsoft also binds a member (not a guest) by `preferred_username` when
   `xms_edov` is missing. Entra accepts as a user principal name suffix only a domain verified in
   the tenant, but Microsoft documents `preferred_username` as mutable and not meant for
   authorization, so this is your decision; it stays off by default. The address must also stay
   the same under identkit's normalization except for ASCII case: an address that NFC or Unicode
   lowercase would change (for example the Kelvin sign, which lowercases to `k`) does not bind,
   because it could turn into another account's address. An address with non-ASCII characters
   (in the local part or the domain) does not bind either: identkit's address check accepts only
   ASCII addresses.
5. The account of that address. If there is none, identkit creates one if the policy's
   `createAccountOnFirstSignIn` is true, as for e-mail codes, else `no_account`. A disabled
   account is refused. With `linksPerAccount: "one"`, an account that has a link is refused
   (`account_has_link`).
6. `mayBind(request)` (option): your own rule, for example refused subjects or a rebind window
   after an administrative reset. It gets the provider, kind, issuer, subject, tenant id, the
   address and the account (or null). It runs last and can only refuse (`refused_by_hook`). It
   must return a boolean; anything else fails the sign-in. It is not called for a subject that has
   a link.

Concurrent first sign-ins of one subject leave one link; each signs in to the linked account.

Session: the session records `oidc` as its method and has no step-up: identkit cannot vouch for
what the provider checked. The second-factor rule of e-mail codes applies (policy `secondFactor`
and `isPrivilegedAccount`). Require a step-up with your own methods before sensitive actions.

Migration from your own provider sign-in:

- `oidc.importLink(input)` records the link of an existing account, so the person signs in to
  the same account. `input` is `{ accountId, provider: "microsoft", tenantId, objectId }`,
  `{ accountId, provider: "google", subject }` or `{ accountId, provider: "oidc", issuer, subject }`.
  It is idempotent:
  `imported`, `already_linked`, `linked_elsewhere` (the subject belongs to another account),
  `account_has_link` (with `linksPerAccount: "one"`) or `no_account`. Run it before you switch
  the sign-in over.
- `oidc.removeLink(accountId, linkId)` removes a link and revokes every session of the account.
  The subject can then bind again by its address, so use `mayBind` if a reset must not allow
  that at once.

## Personal API tokens

A personal API token lets a script or another service act for an account without a session. The
owner creates it, sees it once, and sends it as a bearer token. identkit checks it; your code
decides what its scopes allow.

```ts
const identkit = createIdentkit({
  ...options, // a store with apiTokens: the memory, PostgreSQL and D1 stores have it
  apiTokens: { prefix: "pat_", allowedScopes: ["items:read", "items:write"] },
});

// Route "create token": the person is signed in, with a fresh step-up.
const created = await identkit.apiTokens.create({
  accountId: session.accountId,
  name: "deploy script",
  scopes: ["items:read"],
  expiresInDays: 30,
});
if (created.status === "created") showOnce(created.token);

// Every API request
const result = await identkit.apiTokens.verify(
  parseBearerToken(request.headers.get("authorization")) ?? "",
);
if (result.status !== "valid") return new Response(null, { status: 401 });
// result.accountId, result.tokenId, result.scopes
```

Without the option `apiTokens`, every `identkit.apiTokens` call throws `NotConfiguredError`.
`createIdentkit` throws `NotConfiguredError` if the store has no `apiTokens`, and
`InvalidArgumentError` for an invalid option.

Options (configurable; the defaults are design choices, not values from a standard):

| Option                      | Default       | Bounds                                                       |
| --------------------------- | ------------- | ------------------------------------------------------------ |
| `prefix`                    | required      | a letter, then letters, digits or `_`; at most 32 characters |
| `allowedScopes`             | required      | 1 or more, no repeats; each 1 to 128 visible ASCII, no space |
| `allowedExpiryDays`         | `[7, 30, 90]` | 1 or more, no repeats; each 1 to 3650                        |
| `maxActiveTokensPerAccount` | 5             | 1 to 1000                                                    |
| `lastUsedIntervalSeconds`   | 3600          | 0 to 86400                                                   |
| `acceptLegacyDigests`       | `false`       | see "Import"                                                 |
| `onAuditError`              | none          | a function; see "Audit and errors"                           |

The token:

- A token is the prefix and 43 base64url characters from 32 random bytes (256 bits). The whole
  token matches `^<prefix>[A-Za-z0-9_-]{43}$`. Choose a distinct prefix, so that secret scanners
  can find a leaked token.
- `create` returns the token once. The store keeps only its HMAC (the `SecretHasher`, purpose
  `api-token`), never the token. No result, error or audit event after `create` holds the token
  or its digest.
- `parseBearerToken(header)` returns the token of an `Authorization: Bearer <token>` header, or
  null. It does not check the format; `verify` does.

Rules:

- `create` takes a name (1 to 64 characters; no control characters, no format characters such as
  bidi controls and zero-width characters, no lone surrogates and no line or paragraph
  separators, so a list shows the name as it reads; and not blank: at least one character other
  than white space, U+00A0 and the invisible fillers U+034F, U+115F, U+1160, U+2800, U+3164 and
  U+FFA0), scopes (a non-empty set from
  `allowedScopes`, stored in the given order) and `expiresInDays` (one of `allowedExpiryDays`).
  Invalid input throws `InvalidArgumentError`. It returns `limit_reached` if the account has
  `maxActiveTokensPerAccount` active tokens (not revoked and not expired). Every store enforces
  the limit atomically: parallel creates never leave more active tokens.
- `verify` refuses a value that is not a string of the configured format (`malformed`) before
  any digest or read. Then it makes one indexed read by digest, which also returns the status
  of the account, and compares the stored digest again in constant time. It refuses `unknown`,
  `revoked`, `expired` (at `expiresAt` and after) and `account_disabled`. If more than one stored
  token matches (one token imported twice, see "Import"), it refuses `ambiguous`, whatever the
  state, account or scopes of the copies: it never picks one. It looks for the legacy digest of
  the token also when `acceptLegacyDigests` is off, so a second copy refuses the token in either
  setting; a legacy copy alone verifies only while the option is on.
- `verify` returns the account id, the token id, `expiresAt` and the stored scopes that
  `allowedScopes` still lists, in stored order. If you remove a scope from `allowedScopes`,
  tokens lose it at once (fewer rights, never more). A token with no listed scope left is
  refused (`no_allowed_scope`). `list` shows the scopes as stored.
- Scopes are opaque strings: identkit gives them no meaning. Check them in your code on every
  request. If an agent acts for a person with narrower rights, intersect the token's scopes with
  that grant before you act.
- `verify` writes `lastUsedAt` at most once per `lastUsedIntervalSeconds`, with a conditional
  write, and records `api_token.used` only then. So a verify is one read and at most one write.
  Of concurrent verifies, one writes.
- A revocation takes effect for every verify that starts after it. identkit does not delete rows:
  `list` shows tokens that are not revoked, expired ones included.
- Measured with `pnpm check:workerd` on 2026-11-27 (memory store, so without database time):
  `apiTokens.verify` takes 0.0102 ms wall time per call in workerd and 0.0335 ms CPU time per call
  on Node; `sessions.validate` took 0.0105 ms and 0.0291 ms in the same run. Every verify computes
  the keyed HMAC and the unkeyed SHA-256 of the token (to find a legacy copy, see "Import"); the
  figures include both. Workers Free allows 10 ms
  CPU time per HTTP request (Cloudflare,
  [Workers limits](https://developers.cloudflare.com/workers/platform/limits/), read 2026-11-27).

Accounts and sessions:

- `accounts.disable` revokes every token of the account (reason `account_disabled`), also when
  the option `apiTokens` is not set, if the store has `apiTokens`. And `verify` refuses a token
  whose account is not active, also one that a parallel `create` stored after the revocation.
  If the token revocation throws (for example on a schema without the token table),
  `accounts.disable` still revokes the sessions, offers its events to the sink and runs
  `onAllSessionsRevoked`. The error that goes up, in this order:
  - If the session revocation throws, its error goes up. The hook has not run, and the token
    store's error is dropped.
  - Else, if the hook throws, its `AllSessionsRevokedHookError` goes up. If the token
    revocation failed too, the error carries the store's error as `tokenRevocationError`, and
    its message says to call `accounts.disable` again and includes the store error's message.
    An `Error` in that field serializes to `{}` in JSON, so log the message.
  - Else, if the sink refused an event, the sink's error goes up unchanged, and the token
    store's error is dropped.
  - Else the token store's error goes up.

  A failed hook leaves your application's sessions live, and a refused event is lost for good.
  The tokens stay unusable while the account is disabled, but they are not revoked. So after
  any error from `accounts.disable`, call it again until it succeeds. Until then the account's
  API tokens may not be revoked, and enabling the account again directly in the store brings
  them back. The retry repeats every step: it reports a token store error that persists,
  revokes the remaining tokens, records their `api_token.revoked` events and runs the hook
  again. It does not record `account.disabled` or `session.revoked` again, also not when the
  sink refused them the first time.

- Tokens are separate from sessions. `sessions.revokeAll`, a passkey or TOTP change and
  `oidc.removeLink` do not revoke tokens (except a passkey or TOTP cleanup that disables the
  account, see "Passkeys" and "TOTP"), and `onAllSessionsRevoked` is not called for tokens.
  Call `apiTokens.revokeAll(accountId)` where a sign-out everywhere must also end tokens, for
  example after an account takeover.
- Every call except `verify` takes a bare account id and trusts its caller. Check the person
  first: a session, and a fresh step-up for `create`.

Audit and errors:

- `api_token.created` and `api_token.imported` (with `tokenId` and `scopes`; the import also with
  `method`, the digest algorithm), `api_token.revoked` (with `reason`: `revoked`, `revoked_all`
  or `account_disabled`) and `api_token.used`.
- If the sink refuses the event of `create` or `import`, identkit deletes the new token and throws
  `OperationRolledBackError` (`hookFailed` false): nothing took effect. If that delete fails, the
  store's error goes up and the token stands; a created token is then unusable, because its
  plaintext was never returned, and it counts against the limit until you revoke it. An imported
  token is different: its holder already has the plaintext, so the token verifies at once, and
  no `api_token.imported` record exists. A retry of the import returns `already_imported` and
  records nothing. So after such an error, either revoke the token (`list` shows it with
  `source: "import"`; its owner then needs a new one), or keep it and record the import in your
  own log.
- If the sink refuses `api_token.revoked`, the revocation stands and the sink's error goes up.
  `revokeAll` and `accounts.disable` offer every event to the sink before the first error goes
  up.
- `api_token.used` is the one exception to the sink contract (see "Audit events"): it is best
  effort. If the sink refuses it, `verify` still returns `valid`, and identkit passes the error and
  the event to the option `onAuditError(error, event)`; without the option the error is dropped.
  `verify` awaits `onAuditError` and drops what it throws. The reason: the event is recorded on
  the path of every API request, and a sink outage must not fail every request that a token
  authenticates. The authentication decision does not depend on the event, and `lastUsedAt` is
  written before it, so the next verify in the interval records nothing; the refused event is
  lost. Report it from `onAuditError` if you need it.

Import:

- `import(input)` records a token from an earlier system, with `accountId`, `name`, `scopes`,
  `expiresAt` (in the future, at most the longest `allowedExpiryDays` from now), optional
  `createdAt` and `lastUsedAt` (neither in the future, and `lastUsedAt` not before a given
  `createdAt`; a future `lastUsedAt` would stop every `lastUsedAt` write and `api_token.used`
  event until that date), and exactly one of:
  - `token`: the plaintext in the configured format. identkit stores its HMAC, as for a new
    token. Prefer this form.
  - `sha256Digest`: the unkeyed SHA-256 hex digest of the whole token. identkit stores it as a
    legacy digest. This needs `acceptLegacyDigests: true`; without it, `import` throws
    `NotConfiguredError`.
- Results: `imported`, `already_imported` (idempotent), `revoked` (the account held it and it
  was revoked; it stays revoked), `digest_taken` (another account holds it), `expired`,
  `limit_reached`, `no_account` or `account_disabled`. Imports count against
  `maxActiveTokensPerAccount`; raise it for the migration if accounts hold more tokens.
- Imported tokens must have the configured format, or they never verify.
- `name` follows the rules of `create`. A source token whose name is blank after the check for
  blank characters (for example only spaces or Hangul fillers) fails to import with
  `InvalidArgumentError`; give it a name first.
- A legacy digest is weaker than the HMAC: whoever can read the table can test guesses offline
  without a key. With 256-bit random tokens that is no practical attack, but a token from an
  earlier system may have less entropy than its format suggests. Rotate legacy tokens out:
  `list` marks them `legacyDigest: true`; ask the owners to create new tokens, revoke the legacy
  ones after a deadline, then set `acceptLegacyDigests: false`. That stops every legacy token at
  once. identkit does not replace a legacy digest on use.
- A row verifies only with the digest of its own algorithm: a legacy row never matches the HMAC
  of a token, and a keyed row never matches its SHA-256.
- One token, one row. An import with `token` also looks for the legacy digest of that token (also
  when `acceptLegacyDigests` is off now), so it reports `already_imported`, `revoked` or
  `digest_taken` for a token that an earlier import stored as a legacy digest. A revoked copy
  keeps the token revoked. The other direction has a limit: an import with `sha256Digest` cannot
  find a keyed row of the same token, because the HMAC needs the plaintext. If you import one
  token in both forms in that order (or both at once), `verify` refuses it as `ambiguous`,
  whether `acceptLegacyDigests` is on or off, and revoking one copy does not change that: both
  rows stay. Import each token in one form only. A token stored twice stays unusable; its owner
  creates a new one. The two copies can sit on different accounts, and `list(accountId)` shows
  only the copies of that account (`legacyDigest: true` marks a legacy copy). To move a legacy
  token to the HMAC, the owner creates a new token; identkit does not replace a stored digest.

## OAuth authorization server (MCP clients)

`identkit.oauth` is an OAuth 2.1 authorization server for clients such as MCP clients: discovery
documents (RFC 8414, RFC 9728), dynamic client registration (RFC 7591), the authorization code
flow with PKCE (S256 only), refresh token rotation, revocation (RFC 7009) and the access token
check of your protected resource. identkit makes every decision that carries a security
property. Your code routes, reads bodies, renders the consent page and writes responses.

```ts
const identkit = createIdentkit({
  ...options, // a store with oauth (the built-in stores have it) and a sealer
  oauth: {
    issuer: "https://example.com",
    resources: ["https://example.com/mcp"],
    defaultScopes: ["mcp:read"],
    optInScopes: ["mcp:events"],
  },
});
const { oauth } = identkit;

// GET oauth.metadata.authorizationServerPath() and oauth.metadata.protectedResourcePath():
// answer with oauth.metadata.authorizationServer() and oauth.metadata.protectedResource().

// POST /oauth/register (cap the body size before you read it)
const registered = await oauth.register({ body: await readText(request, 8192), addressKey: ip });

// GET /oauth/authorize: sign the person in first, with this URL as the return target.
const begun = await oauth.authorize.begin({
  params: url.searchParams,
  accountId: session.accountId,
});
// "consent": render the page, with the ticket in a hidden field. Else render the error on your
// own page: never redirect it.
renderAuthorizePage(begun);

// POST /oauth/authorize (the consent form)
const decided = approved
  ? await oauth.authorize.approve({ ticket, accountId: session.accountId, optInScopes })
  : await oauth.authorize.deny({ ticket, accountId: session.accountId });
if (decided.status === "redirect") return Response.redirect(decided.location, 303);

// POST /oauth/token and POST /oauth/revoke
const form = new URLSearchParams(await request.text());
const result = await oauth.token({ form, authorization: request.headers.get("authorization") });
return Response.json(result.body, { status: result.httpStatus, headers: result.headers });

// Every request of the protected resource
const bearer = parseBearerToken(request.headers.get("authorization"));
const checked = await oauth.validateAccessToken(bearer ?? "", {
  resource: "https://example.com/mcp",
});
if (checked.status !== "valid") {
  const challenge = oauth.wwwAuthenticate({ tokenPresented: bearer !== null });
  return new Response(null, { status: 401, headers: { "WWW-Authenticate": challenge } });
}
// checked.accountId, checked.clientId, checked.grantId, checked.scopes
```

Without the option `oauth`, every `identkit.oauth` call throws `NotConfiguredError`.
`createIdentkit` throws `NotConfiguredError` if the store has no `oauth` or the option `sealer` is
missing, and `InvalidArgumentError` for an invalid option or a prefix that overlaps
`apiTokens.prefix`.

Routes (the endpoint paths are options; the well-known paths follow from `issuer` and
`resources`):

| Route                                      | Method    | Call                                                  |
| ------------------------------------------ | --------- | ----------------------------------------------------- |
| `metadata.authorizationServerPath()`       | GET       | `metadata.authorizationServer()`                      |
| `metadata.protectedResourcePath(resource)` | GET       | `metadata.protectedResource(resource)`                |
| `/oauth/register`                          | POST      | `register({ body, addressKey? })`                     |
| `/oauth/authorize`                         | GET, POST | `authorize.begin`, then `authorize.approve` or `deny` |
| `/oauth/token`                             | POST      | `token({ form, authorization })`                      |
| `/oauth/revoke`                            | POST      | `revoke({ form, authorization })`                     |

Endpoint calls return `{ httpStatus, body, headers }`. Write `body` as JSON (an empty body if it
is null) with that status and those headers. The headers hold `Cache-Control: no-store` and
`Pragma: no-cache` on every answer, `WWW-Authenticate: Basic realm="..."` on an
`invalid_client` after a Basic attempt, and `Retry-After` on a 429. Error bodies hold an RFC
error code and a fixed English `error_description`, never an echo of the input. identkit
suggests the status; you may change it.

Options (configurable; the defaults are design choices and common MCP client behaviour, not
values from a standard):

| Option                                | Default                                                                | Bounds and notes                                                                                                                                                  |
| ------------------------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `issuer`                              | required                                                               | one static `https:` URL without query, fragment or trailing slash (`http:` only on `localhost` and `127.0.0.1`). Never derive it from a request (RFC 9207 mix-up) |
| `resources`                           | required                                                               | 1 to 8 URLs, same form as `issuer`. The first is the default `resource` of a request                                                                              |
| `resourceName`                        | none                                                                   | `resource_name` in the RFC 9728 document                                                                                                                          |
| `endpoints`                           | `/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/oauth/revoke` | paths, or absolute URLs on the issuer's origin. `register: null` turns registration off                                                                           |
| `defaultScopes`                       | required                                                               | 1 or more; granted on every grant. RFC 6749 scope tokens: visible ASCII without space, `"` and `\`, at most 128                                                   |
| `optInScopes`                         | `[]`                                                                   | granted only if `approve` names them; none may be a default scope                                                                                                 |
| `accessTokenSeconds`                  | 3600                                                                   | 60 to 86400                                                                                                                                                       |
| `refreshTokenSeconds`                 | 2592000 (30 days)                                                      | 3600 to 31536000; capped at the grant's end                                                                                                                       |
| `grantSeconds`                        | 7776000 (90 days)                                                      | the absolute end of a grant; at least `refreshTokenSeconds`                                                                                                       |
| `codeSeconds`                         | 300                                                                    | 30 to 600                                                                                                                                                         |
| `consentSeconds`                      | 600                                                                    | 60 to 3600                                                                                                                                                        |
| `refreshRaceGraceSeconds`             | 30                                                                     | 0 to 120; 0 turns the grace off                                                                                                                                   |
| `maxGrantsPerAccount`                 | 10                                                                     | 1 to 1000; live grants of other clients than the one at hand                                                                                                      |
| `refreshTokens`                       | `"always"`                                                             | `"always"` (every client gets one, as common MCP clients expect) or `"if_registered"` (only clients whose `grant_types` has `refresh_token`)                      |
| `registration.maxPerDay`              | 1000                                                                   | per deployment and UTC day                                                                                                                                        |
| `registration.maxPerAddressPerDay`    | 30                                                                     | per `addressKey` and UTC day; skipped without `addressKey`                                                                                                        |
| `registration.maxBodyBytes`           | 8192                                                                   | 1024 to 65536 UTF-8 bytes                                                                                                                                         |
| `registration.maxRedirectUris`        | 5                                                                      | 1 to 20                                                                                                                                                           |
| `registration.maxRedirectUriLength`   | 512                                                                    | 64 to 2048                                                                                                                                                        |
| `registration.defaultAuthMethod`      | `client_secret_basic`                                                  | the RFC 7591 default; one of `allowedAuthMethods`                                                                                                                 |
| `registration.allowedAuthMethods`     | `none`, `client_secret_basic`, `client_secret_post`                    | 1 or more                                                                                                                                                         |
| `redirectUris.allowIpv6Loopback`      | `false`                                                                | accept `http://[::1]` redirect URIs                                                                                                                               |
| `redirectUris.allowPrivateUseSchemes` | `false`                                                                | accept RFC 8252 schemes such as `com.example.app:/cb`                                                                                                             |
| `clientRetention.unusedDays`          | 30                                                                     | 1 to 3650; see `purge`                                                                                                                                            |
| `clientRetention.idleDays`            | 180                                                                    | 1 to 3650; see `purge`                                                                                                                                            |
| `prefixes`                            | `ikc_`, `ikcs_`, `ikac_`, `ikat_`, `ikrt_`                             | client id, client secret, code, access token, refresh token; as `apiTokens.prefix`; distinct, none a prefix of another or of `apiTokens.prefix`                   |
| `admit`                               | none                                                                   | a policy that can refuse; see "Rules"                                                                                                                             |
| `legacy`                              | none                                                                   | see "Import and legacy tokens"                                                                                                                                    |
| `acceptLegacyClientSecrets`           | `false`                                                                | see "Import and legacy tokens"                                                                                                                                    |
| `onAuditError`                        | none                                                                   | receives a refused `oauth.token_refreshed`; see "Audit and errors"                                                                                                |
| `onStoreError`                        | none                                                                   | receives a failed best-effort store write; see "Audit and errors"                                                                                                 |
| `basicRealm`                          | the issuer's host                                                      | the realm of `WWW-Authenticate: Basic`                                                                                                                            |

Token formats. Every secret is an opaque random string with its own prefix. The store keeps only
its HMAC (the `SecretHasher`, under the purposes `oauth-client-secret`, `oauth-code`,
`oauth-access-token`, `oauth-refresh-ref` and `oauth-refresh-token`), never the secret:

- client id: `ikc_` and 22 base64url characters (16 bytes); not secret;
- client secret: `ikcs_` and 43 characters (32 bytes), for a confidential client; it never
  expires (`client_secret_expires_at: 0`);
- authorization code: `ikac_` and 43 characters;
- access token: `ikat_` and 43 characters, one store row per issued token;
- refresh token: `ikrt_`, a 22-character ref, `.` and a 43-character secret. The ref is fixed per
  grant and finds it in one read; the secret changes on every rotation.

The registration limit per address stores a keyed digest of `addressKey` (purpose
`oauth-registration-address`), never the value. No token is a JWT: a resource server must call
`validateAccessToken`, which also makes every revocation take effect at once. The hasher key
now protects these digests too; identkit does not support rotating it.

Rules:

- Raw input. `authorize.begin`, `token` and `revoke` take the raw parameters and the raw
  `Authorization` value; `register` takes the raw body text. Pass `URLSearchParams`: identkit then
  refuses a parameter sent twice (`invalid_request`). A record cannot show a repeat; its parser
  has picked one value already. `register` refuses a body over `maxBodyBytes`, but cap the read
  yourself before you buffer it: identkit cannot stop an upload it never sees.
- Registration. Redirect URIs must be absolute, without fragment or user info, `https:` (or
  `http:` on `localhost` and `127.0.0.1`, any port), with an ASCII host that equals its parsed
  form: Unicode hosts, punycode labels (`xn--`), percent-encoding in the host, upper case, dot
  segments and written-out default ports are refused. `grant_types` must hold
  `authorization_code` (and `refresh_token` at most), `response_types` must be `["code"]`.
  `client_name` loses control, format, bidi and separator characters and is cut at 100. The day
  limits count atomically; the 429 says `temporarily_unavailable`.
- Authorization. Errors never redirect: `begin` returns `invalid` for your own page (RFC 9700
  4.11.2). The request must name a registered redirect URI, or leave it out if the client has
  exactly one. A loopback registration accepts any port, never another host: `localhost` and
  `127.0.0.1` do not match each other. `code_challenge_method` must be `S256`. `resource`
  (RFC 8707) must be one of `resources`; without it the grant is for the first. The request's
  `scope` only marks opt-in scopes as requested (`requestedOptInScopes`); the consent decides.
  `approve` and `deny` redirect with `iss` (RFC 9207) and the `state` that was sent.
- The consent ticket is sealed with the sealer (context `identkit/oauth/consent/v1`) and bound to
  the account. It is the form's CSRF token too: an attacker can get one only for an own account.
  It is not single use; a second approve issues another code for the same client, which equals
  a second click. Tickets sealed with a key you remove from the sealer's `keys` fail as
  `invalid_ticket`, so remove an old key no earlier than `consentSeconds` after the switch.
- Code exchange. A code works once. The first attempt uses it up, also a failed one, so a wrong
  verifier burns it. A code that comes back after its exchange ends the grant it created
  (`code_reuse`, RFC 6749 4.1.2). The code is bound to its client, its redirect URI (required at
  the token endpoint if the authorization request named it, and equal when sent), its PKCE
  challenge and its resource. An account holds one grant per client: a new exchange replaces the
  earlier grant (`replaced`). `maxGrantsPerAccount` holds also under parallel exchanges.
- Client authentication. A confidential client sends its secret by Basic (form-encoded, RFC 6749
  2.3.1) or in the form (`client_secret_post`), whatever it registered; never both, and never
  none. A public client sends `client_id` in the form and no secret. A public client that sends a
  Basic header, also one with an empty password, is refused `invalid_client`. Every presented
  secret gets its digest before the client lookup, and the compare is constant time. Changing
  `registration.allowedAuthMethods` affects new registrations only.
- Refresh. A refresh rotates the refresh token and issues a new access token. The previous
  refresh token gets `invalid_grant` within `refreshRaceGraceSeconds` of the rotation and ends
  nothing (parallel refreshes of one client). Any other old token of the grant ends it
  (`refresh_reuse`, RFC 9700 4.14.2): it is a copy in other hands. A token of another client
  ends nothing. An expired grant or refresh token ends the grant. A disabled account or a refusal
  by `admit` refuses the refresh and keeps the grant. `scope` may narrow (a subset of the grant),
  never widen (`invalid_scope`); another `resource` is `invalid_target`.
- Revocation ends the grant of an access or refresh token of the calling client (all its tokens
  stop), and answers 200 whatever the token, once the client is authenticated. A token of
  another client ends nothing. A holder of a code or of any refresh token of a grant (also an
  old one) can end the grant: revocation by refresh token matches the ref, and a replayed code
  ends its grant.
- `validateAccessToken(token, { resource? })` is one indexed read with the grant and the account,
  no write and no event. It refuses `malformed`, `unknown` (also every token of an ended grant),
  `expired`, `grant_expired`, `account_disabled`, `wrong_resource` (another resource than asked
  for, or one no longer configured) and `no_allowed_scope`. It returns the token's scopes that
  the options still list: removing a scope from the options removes it from every grant at once.
  A store error goes up; it never counts as valid. A `resource` that is not configured throws
  `InvalidArgumentError`.
- `admit(request)` is called at `begin`, again at `approve`, at the code exchange and at a
  refresh, with `phase`, the account, the client and the scopes. It can only refuse; a result
  that is not a boolean throws `TypeError`. Apply a per-request policy after `validateAccessToken`
  in your own code: identkit calls no hook on that path.
- Scopes are opaque strings. Check them in your code on every request.

Accounts and sessions:

- `accounts.disable`, and the passkey and TOTP cleanups that disable an account, end every grant
  and code of the account (reason `account_disabled`), also when the option `oauth` is not set,
  if the store has `oauth`. `validateAccessToken` and a refresh refuse a disabled account
  anyway. If the end of the grants throws, `accounts.disable` still revokes the sessions, offers
  its events and runs the hook. The error that goes up follows the order under "Personal API
  tokens": the session revocation's, the hook's, the sink's, then the token store's, then the
  grant store's. The hook's `AllSessionsRevokedHookError` carries the grant store's error as
  `grantRevocationError` (next to `tokenRevocationError`), and its message names both. After any
  error, call `accounts.disable` again until it succeeds.
- Grants are separate from sessions: `sessions.revokeAll`, a passkey or TOTP change and
  `oidc.removeLink` end no grant, so a sign-out everywhere does not disconnect MCP clients. If it
  should, call `oauth.revokeAll(accountId)` in your sign-out-everywhere route, or in
  `onAllSessionsRevoked` if every trigger should end grants.
- Deleting an account row directly in the database deletes its grants, their access tokens and
  its codes by foreign key.

Administrative calls take bare ids and trust their caller: `listGrants(accountId)`,
`revokeGrant({ accountId, grantId })`, `revokeAll(accountId)`, `getClient(clientId)`,
`deleteClient(clientId)` (with its grants and codes), `importClient`, `importGrant` and `purge`.

`purge()` deletes expired grants, codes and access tokens, registration counts of earlier days,
and clients by `clientRetention`: never used (no approval, exchange or refresh) and older than
`unusedDays`, or last used more than `idleDays` ago. It never deletes a client that holds a live
grant or code. An approval writes the client's last use (at most twice a day) before the code,
so a client in the middle of a flow is never unused or idle. Run `purge` on a schedule, for
example daily.

Audit and errors:

- Events carry `clientId`, `grantId`, `accountId`, `scopes`, `reason` and `method` where they
  apply, never a token, code, secret, ref, digest of those, client name, redirect URI, `state`,
  code challenge or raw `addressKey`: `oauth.client_registered`, `oauth.client_imported`,
  `oauth.client_deleted` (`administrative`, `unused`, `idle`), `oauth.registration_refused`
  (`daily_limit`, `address_limit`, with `addressDigest`), `oauth.consent_approved`,
  `oauth.consent_denied`, `oauth.grant_created`, `oauth.grant_imported`, `oauth.grant_ended`
  (`revoked_by_client`, `revoked`, `revoked_all`, `client_deleted`, `account_disabled`,
  `replaced`, `code_reuse`, `refresh_reuse`, `expired`), `oauth.token_failed` (`code_unknown`,
  `code_expired`, `client_mismatch`, `redirect_mismatch`, `pkce_failed`, `resource_mismatch`,
  `refresh_unknown`, `refresh_raced`, `refused_by_policy`, `account_disabled`, `grant_limit`)
  and `oauth.token_refreshed`. `validateAccessToken` records nothing.
- A refused `oauth.client_registered` or `oauth.client_imported` deletes the new client, and the
  call throws `OAuthClientRolledBackError` (with `clientId`; a client belongs to no account, so
  it is no `OperationRolledBackError`). If that delete fails, the store's error goes up and the
  client stands without its record; nobody holds its id or secret.
- A refused `oauth.grant_created` deletes the new grant, and `token` throws
  `OperationRolledBackError` (`hookFailed` false); answer 500, the client starts the flow again
  (its code is used up). One exception to "nothing took effect": if the exchange replaced the
  account's earlier grant of the same client, that grant stays ended and its client must connect
  again. Its `oauth.grant_ended` (reason `replaced`) goes to the sink before
  `oauth.grant_created`; if the sink refused that event, the grant ended without its record, and
  the call throws the same error. A refused `oauth.grant_imported` deletes the imported grant
  and throws `OperationRolledBackError` too.
- `oauth.consent_approved` goes to the sink before the code is stored: no code stands without its
  record. A refused `grant_ended`, `client_deleted` or `registration_refused` undoes nothing;
  `deleteClient`, `revokeAll`, `accounts.disable` and `purge` offer every event before the first
  error goes up.
- `oauth.token_refreshed` is best effort, the second exception to the sink contract beside
  `api_token.used`. The rotation is written before it; if a refused event failed the call, the
  client would keep its old refresh token, which is the previous one now, and its next refresh
  after the grace would end the grant. A sink outage would disconnect every client. identkit
  passes the error and the event to `onAuditError` and still returns the tokens.
- `onStoreError(error, { kind, clientId })` receives a failed best-effort store write:
  `client_last_used` (the last-use time after a refresh) and `client_secret_upgrade` (see
  "Import and legacy tokens"). The tokens are issued already, so the call still returns them.
  identkit awaits the handler and drops what it throws.
- A client deleted, or a code replayed, in the moment between the grant insert and
  `oauth.grant_created` ends the new grant before its creation is recorded: the trail shows
  `grant_ended` before `grant_created`, and the exchange answers with tokens that already fail
  `validateAccessToken`. No grant survives.

Import and legacy tokens. Move clients and grants of an earlier system to identkit, and keep
connected clients working:

- `importClient({ id, name?, redirectUris, grantTypes, authMethod, createdAt?, lastUsedAt?,
secret? | secretSha256? })` keeps the id (visible ASCII, 1 to 128 characters). Redirect URIs
  and grant types follow the registration rules. A confidential client needs exactly one of
  `secret` (the plaintext; identkit stores its HMAC) and `secretSha256` (hex of the unkeyed
  SHA-256; needs `acceptLegacyClientSecrets: true`, else `NotConfiguredError`). Results:
  `imported`, `already_imported` (same id and data), `id_taken`.
- With `acceptLegacyClientSecrets`, a SHA-256 secret authenticates, and on its first successful
  use identkit replaces it with the HMAC by compare-and-set (best effort: a failed write goes to
  `onStoreError`, and the next use tries again). This differs from API tokens on purpose: client
  secrets never expire, so without the upgrade a weak digest would stay for good. After the
  upgrade, a second import with `secretSha256` answers `id_taken` (identkit cannot prove the same
  secret without the plaintext); one with `secret` answers `already_imported`. Without the
  option, such a client cannot authenticate.
- `importGrant({ id, accountId, clientId, scopes, resource, createdAt, expiresAt, generation,
refreshedAt?, refreshExpiresAt, refreshSha256 })` keeps the grant id, because the legacy tokens
  name it. Scopes must be default or opt-in scopes, the resource one of `resources`.
  `refreshSha256` is the unkeyed SHA-256 hex of the current refresh token, whose generation is
  `generation`. It never replaces a grant. Results: `imported`, `already_imported`, `id_taken`,
  `account_client_taken`, `limit_reached`, `expired`, `no_account`, `account_disabled`,
  `no_client`. Imported rows show `legacyDigest: true` (clients) and `source: "import"`.
- `legacy.verifyAccessToken(token)` and `legacy.verifyRefreshToken(token)` check the earlier
  system's own tokens: its signature and expiry. They return `{ grantId, audience, expiresAt }`
  or `{ grantId, generation, expiresAt }`, or null to refuse. identkit calls them only for a
  token of at most 4096 characters that starts with none of its prefixes, and only before
  `legacy.until`; set `until` to the latest legacy refresh expiry, so the path ends by itself.
  Then identkit checks the rest as for its own tokens: the grant exists, was imported (a legacy
  token never reaches a grant that identkit created), is live, the account is active, the
  audience is one of `resources` (and the one asked for), and at refresh the client is the
  grant's. A legacy refresh with the grant's generation and stored SHA-256 rotates into an
  identkit refresh token. One generation below within the grace is `invalid_grant` and keeps the
  grant; anything else ends it (`refresh_reuse`). A verifier that throws fails the call; a result
  of another shape throws `TypeError`. Revocation accepts legacy tokens too.
- Codes and consent tickets in flight are not imported: a client in the middle of a flow at the
  switch gets `invalid_grant` or `invalid_ticket` and starts again. Switch at low traffic.
- The unkeyed SHA-256 of a client secret or refresh token lets a database reader test guesses
  offline without a key. With 256-bit random values that is no practical attack.

What stays with you:

- Routing, the sign-in before `authorize.begin`, and the consent page. Escape `client.name` for
  HTML (identkit removes unsafe characters, but escaping is the page's job), send
  `Content-Security-Policy: frame-ancestors 'none'` against clickjacking, and offer opt-in scopes
  unticked.
- CORS. The well-known documents may be open to every origin. For token, register and revoke,
  browser-based MCP clients need CORS; decide it per deployment. identkit sets no CORS header.
- A body size cap before you buffer a request, a rate limit on the token endpoint (identkit
  limits only registrations), and TLS.
- The meaning of each scope on every request of your resource.

## Identity verification port

Implement `IdentityVerificationAdapter` for a vendor: `start`, `parseCallback` (authenticate the
callback, throw if it is not authentic) and `fetchResult`. A result reports `verified` with an
assurance level (`low`, `substantial`, `high`), an evidence reference and a person key, or
`failed`, or `pending`. identkit applies the timeout. `createFakeIdentityVerificationAdapter`
succeeds, fails or never answers, for tests and demos. It is unsafe for production: it verifies
nobody. Without `callbackSecret` it signs callbacks with a random secret per instance.

## Audit events

identkit awaits `audit.emit` for every security-relevant event. If the sink throws, the call
throws, but what identkit wrote before the event stands (two exceptions: `api_token.used` and
`oauth.token_refreshed` are best effort, see "Personal API tokens" and "OAuth authorization
server"): a refused event undoes no revocation and
no factor change (see Sessions; only `OperationRolledBackError` means that nothing took effect).
`accounts.disable` records `account.disabled` only if the account was still active, so a retry
does not record it twice; a refused `account.disabled` is then missing. Events carry ids and
reasons, never a code, token, challenge, key, person key, TOTP secret, sealed secret,
provisioning URI or e-mail address. `addressDigest` is the HMAC of the address, for correlation. Approval events carry `level`; TOTP events carry `factorId`.

OIDC events carry `provider` and, where one exists, `linkId`, never an ID token, code, client
secret, subject or address: `oidc.signed_in`, `oidc.sign_in_failed` (reason), `oidc.binding_refused`
(reason and `addressDigest`), `oidc.link_created`, `oidc.link_imported` and `oidc.link_removed`.

API token events carry `tokenId`, never the token or its digest: `api_token.created`,
`api_token.imported`, `api_token.revoked` and `api_token.used` (see "Personal API tokens").

OAuth events carry `clientId` and, where one exists, `grantId`, never a token, code, secret,
client name, redirect URI or `state`: the `oauth.*` events listed under "OAuth authorization
server (MCP clients)". The types `AuditEventType` and `AuditEvent` (new fields `clientId` and
`grantId`) grow with them: an exhaustive `switch` over `AuditEventType` stops compiling.

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

Migration `0004_oidc_links.sql` (D1: `0002_oidc_links.sql`) adds the table `identkit_oidc_links`.
It changes nothing else, so the previous release runs on the new schema. It cannot read the
session rows that an OIDC sign-in writes, though: their method `oidc` is unknown to it, and it
fails every request of such a session. So deploy this release to every instance, and finish a
gradual deployment, before you turn on the option `oidc`. A rollback to an earlier release after
the first OIDC sign-in fails those sessions until they end or you revoke them. From this release
on, every store drops a session method it does not know when it reads a session (fewer methods,
never more rights), so a later release can add a method without this problem.

A release that drops a method on read also writes the session back without it when it changes
the session (`rotate`, a step-up, a second factor). So during a mixed deployment, a session can
lose a newer method for good: it stays lost after every instance runs the newer release. No
decision of identkit reads the session's methods, but if your code does (for example "only
sessions with `oidc`"), it gets the wrong answer for such a session. This is one more reason to
deploy a release to every instance before you turn on a method that it adds, as for `oidc`.

Migration `0005_api_tokens.sql` (D1: `0003_api_tokens.sql`) adds the table `identkit_api_tokens`.
It changes nothing else, so the previous release runs on the new schema. The previous release
does not know the table: it does not revoke tokens on `accounts.disable`. Tokens of an account
disabled by such an instance still fail `verify`, because `verify` checks the account status.

Upgrade note: apply `0005_api_tokens.sql` (D1: `0003_api_tokens.sql`) before you deploy this
release, also if you do not use API tokens. `accounts.disable` revokes the tokens of the account
in every store that has `apiTokens`, and the built-in stores all have it. Without the table,
every `accounts.disable` disables the account, revokes its sessions and runs
`onAllSessionsRevoked`, and then throws the database error, until the migration runs.

Migration `0006_oauth.sql` (D1: `0004_oauth.sql`) adds the tables `identkit_oauth_clients`,
`identkit_oauth_grants`, `identkit_oauth_access_tokens`, `identkit_oauth_codes` and
`identkit_oauth_registration_counts`. It changes nothing else, so the previous release runs on
the new schema, and a rollback of the code needs no schema rollback. Grants are deleted when they
end, not marked; the foreign keys remove their access tokens, and an account or client delete
removes its grants and codes. The unique index `identkit_oauth_grants_account_client_idx` holds
one grant per account and client; a later release may replace it.

Upgrade note: apply `0006_oauth.sql` (D1: `0004_oauth.sql`) before you deploy this release, also
if you do not use OAuth: migrate first, then deploy. `accounts.disable` ends the OAuth grants of
the account in every store that has `oauth`, and the built-in stores all have it. Without the
tables, every `accounts.disable` disables the account, revokes its sessions and runs
`onAllSessionsRevoked`, and then throws the database error, until the migration runs.

A custom store needs the member `oauth` to use the OAuth server (the full list is the type
`IdentkitStore["oauth"]`). It is optional in the type; `createIdentkit` throws
`NotConfiguredError("store.oauth")` if the option `oauth` is set without it. Each guarded method
states its atomicity in its comment: `consumeCode` returns a code to exactly one of concurrent
calls, `insertGrant` checks the account and the grant limit and replaces the grant of the same
client in one atomic step, `rotateGrant` is a compare-and-set on the generation, and
`reserveRegistration` never lets a count pass its maximum.

A custom store needs the member `apiTokens` (`insert`, `findByDigests`, `listByAccount`,
`markUsed`, `revoke`, `revokeAllForAccount`, `delete`) to use personal API tokens. It is
optional in the type, like `oidcLinks`. `insert` must apply the active-token limit atomically,
and `findByDigests` must return the account status from the same read.

A custom store needs the member `oidcLinks` (`insert(link, { exclusive })`, `findByKey`,
`listByAccount`, `delete`) to use OIDC sign-in. It is optional in the type, so a custom store
from an earlier release still compiles; `createIdentkit` throws `NotConfiguredError` if the
option `oidc` is set and the store has no `oidcLinks`. An exclusive insert must be atomic per
account: two concurrent exclusive inserts for one account leave at most one link.

### D1 store

`createD1Store(db, options?)` from `identkit/d1` takes a Cloudflare D1 binding (`env.DB`). The
parameter type `D1DatabaseLike` is the part of `D1Database` that the store uses, so identkit
needs no Cloudflare types at runtime.

```ts
import { createIdentkit } from "identkit";
import { createD1Store } from "identkit/d1";

// Inside the fetch handler: the binding comes with each request's `env`.
const identkit = createIdentkit({ ...options, store: createD1Store(env.DB) });
```

Read replication: pass the plain binding `env.DB`, which reads from the primary database. A D1
session from `env.DB.withSession()` can read from a read replica that lags behind the primary.
With the default constraint `"first-unconstrained"`, or with a bookmark from an earlier request,
a revoked session can still validate, a disabled account can still read as active, and a new
lockout can read as not yet set. So `createD1Store` refuses a D1 session (an object with
`getBookmark`) and throws a `TypeError`. If you want a session, start it with
`env.DB.withSession("first-primary")` and state that with the option:

```ts
// Inside the fetch handler: a new session and a new store for each request.
const db = env.DB.withSession("first-primary");
const store = createD1Store(db, { sessionConstraint: "first-primary" });
```

Only the first query of a `"first-primary"` session goes to the primary. Later queries of the
session can go to a read replica that is as recent as that first query (Cloudflare,
[D1 read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/),
read 2026-11-27). Inside one request this reads as a request that came a moment earlier. A
session that lives longer does not: if you keep the session or the store at module scope, or
pass it on to a later request, a revoked session can validate after the revocation. So start a
new session and a new store in each request (each Worker invocation), as in the example.

The store cannot read the constraint of a session, so the option is your statement. Never set it
for a session with another constraint, from a bookmark, or from an earlier request. The store
detects a session by its `getBookmark` method. Never wrap a session in a hand-written object
(for logging or metrics) that drops `getBookmark` to pass this check: the store then takes the
session as the plain binding. A wrapper must forward `getBookmark`, or wrap only the plain
binding.

Its schema lives in `migrations-d1/`, separate from the PostgreSQL files. Every table and index
starts with `identkit_`, so the schema can share one D1 database with the tables of your
application. Apply it in one of two ways, and do not mix them for one database, because each
keeps its own record of applied files:

- `await migrateIdentkitD1(env.DB)` from a deployment script or an admin route. It works without
  a file system (the SQL ships as strings in `D1_MIGRATIONS`), runs each file as one `batch()`
  (one transaction), records it in `identkit_migrations` with a SHA-256 checksum of its SQL and
  skips applied files. If the SQL of an applied file changed, it throws. Concurrent runs apply
  each file once. It refuses a file with two statements on one line, because D1 would run both
  unchecked. A record table from an earlier runner without checksums gets the column; a file
  recorded there without a checksum is refused.
- `wrangler d1 migrations apply`. Declare a second binding to the same database with its own
  migrations folder and table:

  ```toml
  [[d1_databases]]
  binding = "IDENTKIT_DB"
  database_name = "app"
  database_id = "<the id of your database>"
  migrations_dir = "node_modules/identkit/migrations-d1"
  migrations_table = "identkit_wrangler_migrations"
  ```

  Then run `wrangler d1 migrations apply IDENTKIT_DB --remote`. You can also copy the files into
  your own migrations folder, in order.

Storage format: every time is an INTEGER of milliseconds since the Unix epoch, so SQLite
compares times as numbers. A boolean is INTEGER 0 or 1. A list (session auth methods, passkey
transports) is a JSON array in TEXT. A public key is a BLOB. Allowed values of enumerations are
checked when a row is read, not by CHECK constraints, because SQLite cannot change a CHECK
without rebuilding the table.

Migration rule: every D1 migration after `0001_initial.sql` is additive. It adds tables,
indexes or columns, and never drops or renames. A new column is nullable or has a default
(`NOT NULL` only with `DEFAULT`). So the previous Worker version runs on the new schema while a
deployment rolls out. A test enforces the rule on the files.

Atomicity: D1 has no interactive transactions. D1 runs the statements of a database one after
another, and each statement and each `batch()` is atomic. Each guarded store call is one
conditional statement (`UPDATE ... WHERE <expected state> RETURNING`, an upsert, or
`DELETE ... RETURNING`), or one `batch()` (`enrollment.issue`). `throttle.reserve` reads the
state, applies `applyThrottle`, and writes with a compare-and-set on every stored field; if a
concurrent call changed the state first, it reads again. After `throttleRetries` lost rounds
(default 16, `D1_DEFAULT_THROTTLE_RETRIES`) it throws `D1ThrottleContentionError`, and the
attempt does not pass. The store contract tests, with their concurrency cases, run against a
local D1 (miniflare).

Query limit: D1 allows 50 queries per Worker invocation on the Workers Free plan and 1000 on
Workers Paid; a `batch()` counts as one query (Cloudflare,
[D1 limits](https://developers.cloudflare.com/d1/platform/limits/), read 2026-11-27). Each round
of `throttle.reserve` is at most two queries (a read and a conditional write), so one `reserve`
makes at most `2 * throttleRetries` queries: 32 with the default. A test counts the queries of
the identkit calls that reserve a throttle (e-mail code sign-in, TOTP enrolment, TOTP second
factor, TOTP step-up, e-mail code step-up, approval by code confirmation) and checks that each
stays within 50 even when `reserve` loses every round but the last. The limit counts every query
of the invocation, also the queries of your application and of other identkit calls in the same
request (for example a `sessions.validate` in middleware). On Workers Free, the heaviest call
under the worst contention leaves only a few queries for them. If the limit is hit anyway, the
query throws and the attempt does not pass. On Workers Paid you can raise `throttleRetries`; on
Workers Free keep the default or lower it.

The purge rule under "Operator duties" applies to D1 too, with times in milliseconds, for
example `window_start < ?1 AND (locked_until IS NULL OR locked_until < ?1)` with `?1` set to
`Date.now() - 30 * 86_400_000`.

## Operator duties

identkit leaves these to the consumer:

- Purge old rows. identkit does not delete them (see "Storage"), revoked and expired API tokens
  included. The OAuth tables are the exception: call `oauth.purge()` on a schedule, for example
  daily; it deletes expired grants, codes and access tokens, old registration counts and unused
  or idle clients, and records the ends. Each `passkeys.startSignIn` and
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
  - `throttle.reset(key)` removes every field of the key; the PostgreSQL and D1 stores delete
    the row.
    A reset that clears only the attempts keeps the consecutive count and the lock length, so a
    success or an unlock stays incomplete.

  A store does not need `lockDuration`: `applyThrottle` computes the lock. The PostgreSQL store
  expects the isolation level READ COMMITTED, the PostgreSQL default. Under REPEATABLE READ or
  SERIALIZABLE, the `lastUsedAt` write of `apiTokens.verify` treats a serialization failure or a
  deadlock (SQLSTATE 40001 or 40P01) as a lost race: no write, no event, and `verify` still
  returns `valid`.

- Limit unauthenticated calls in your HTTP layer: per client and in total, for `requestCode`,
  `startSignIn`, every verify route, every route that calls `apiTokens.verify`, and the OAuth
  token, revocation and authorization routes. identkit limits per address and per account
  only, and for OAuth only registrations. Pass `addressKey` to `oauth.register` (for example the
  IPv4 address or the IPv6 /64) so the per-address limit applies.
- OAuth: set a static `issuer` (your public URL) in production, never one from the request.
  Cap request bodies before you read them. To move from an earlier system, import clients and
  grants at low traffic, set `legacy.until` to the latest legacy refresh expiry, and remove the
  verifiers after it.
- Treat audit events as personal data where the payload is. Approval events carry
  `payloadHash`, a plain SHA-256 of the approved payload. If the payload has low entropy (for
  example an account number and an amount), a reader of the audit log can find it by trying
  values. Put a random id into every payload that you hash.
- Keep `identkit/testing` out of production code. Its fake adapters verify nobody, and its fake
  OIDC provider signs in anyone.
- OIDC: register the exact `redirectUri` at each provider, keep the client secret in a secret
  store and rotate it before the provider's expiry (Entra secrets expire), and add the optional
  claims `email` and `xms_edov` to a Microsoft app registration if addresses should bind. Pass one
  `createJwksCache()` from module scope. Limit `oidc.begin` and the callback route in your HTTP
  layer like every unauthenticated route. Before a switch-over, import the existing links.

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

The D1 tests run against a local D1 database in memory (miniflare, a dev dependency), with no
account and no network:

```sh
pnpm test:d1
```

After a change in `migrations-d1/`, run `pnpm generate:d1-migrations`. A test fails if
`src/d1/migrations-sql.ts` and the files differ.

## Not built

- OpenID Connect provider features: identkit's OAuth server issues no ID tokens and has no
  userinfo endpoint or OpenID discovery. Also not built for it: JWT access tokens, token
  introspection (RFC 7662), `private_key_jwt`, pushed authorization requests (RFC 9126), DPoP,
  the client credentials and device grants, token exchange (RFC 8693) and client ID metadata
  documents. Sign-in through an external provider is built (see "External sign-in (OpenID
  Connect)").
- Delegated access to provider APIs (refresh tokens for Microsoft Graph or Google APIs), SMS codes
  and delegated agent identities. API token scopes are opaque strings, so a later grant for an
  agent can narrow them.
- Replacing a legacy API token digest with the HMAC on use.
- For sign-in through an external provider: OpenID Connect discovery, `private_key_jwt` client
  authentication, `form_post` response mode and the `iss` callback parameter (RFC 9207).
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
