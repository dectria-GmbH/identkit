# identkit

Identity toolkit for TypeScript: accounts, passkeys, OIDC, token issuance and delegated agent identities.

Status: early development, not released. This first increment covers sign-in by e-mail code,
passkeys, sessions, step-up, approval proofs, an identity verification port and storage. OIDC,
token issuance, TOTP, SMS codes and agent identities come later.

identkit is a library, not a server. The core has no HTTP framework dependency: you call it from
your own routes and set cookies yourself.

## Requirements

- Node.js 24 or later, ESM only.
- For the PostgreSQL store: PostgreSQL and [Kysely](https://kysely.dev) 0.29 (optional peer
  dependency).

## Quick start

```ts
import { randomBytes } from "node:crypto";
import { createHmacHasher, createIdentkit, createMemoryStore } from "identkit";

const identkit = createIdentkit({
  config, // see "Configuration": every time and limit value is required
  policy: {
    signInMethods: ["email_otp", "passkey"],
    secondFactor: "passkey_if_enrolled",
    stepUpMethods: ["passkey"],
    createAccountOnFirstSignIn: true,
  },
  store: createMemoryStore(), // or createPostgresStore(db) from "identkit/postgres"
  hasher: createHmacHasher(secretKeyBytes), // at least 32 random bytes, kept secret
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
  `revoke(accountId, id)`, `issueEnrollmentToken(accountId)`.
- `stepUp`: `requestEmailCode(sessionToken)`, `verifyEmailCode(sessionToken, { flowId, code })`,
  `startPasskey(sessionToken)`, `finishPasskey(sessionToken, response)`.
- `sessions`: `validate(token)`, `requireStepUp(token, { methods })`, `rotate(token)`,
  `revoke(token)`, `revokeById(id)`, `revokeAll(accountId, { exceptSessionId })`.
- `approvals`: `start({ sessionToken, payloadHash })`,
  `verify({ sessionToken, payloadHash, response })`.
- `accounts`: `create({ email })`, `get(id)`, `findByEmail(email)`, `disable(id)`.
- `identityVerification`: `start({ accountId, returnUrl })`, `handleCallback(payload)`,
  `refresh(verificationId)`, `get(verificationId)`.

Administrative calls take bare ids and trust their caller. Expose them only to privileged code,
or check ownership yourself before you pass client input: all of `accounts`,
`passkeys.list`, `passkeys.revoke`, `passkeys.issueEnrollmentToken`, `sessions.revokeById`,
`sessions.revokeAll`, `identityVerification.start`, `identityVerification.refresh` and
`identityVerification.get`.

Standalone functions: `verifyApprovalEvidence(proof, verifier)`, `hashPayload(payload)`,
`approvalChallenge(nonce, payloadHash, accountId)`, `normalizeEmail(input)`, `parseConfig(input)`.

Subpath `identkit/postgres`: `createPostgresStore(db)`, `migrateIdentkit(db)`, `MIGRATIONS_DIR`.

Subpath `identkit/testing`: `createFakeClock`, `createRecordingMailSender`,
`createRecordingAuditSink`, `createFakeIdentityVerificationAdapter`,
`createSoftwareAuthenticator`. These are for tests and demos only.

Passkey options and responses use the WebAuthn JSON forms, so a browser can pass them to
`PublicKeyCredential.parseCreationOptionsFromJSON()` and send back `credential.toJSON()`.

## Sign-in policy

The operator chooses the methods. identkit enforces the policy on every call; it does not store
the policy or decide who may change it. Pass a function to apply policy changes at once.

| Field                        | Values                        | Effect                                                                                              |
| ---------------------------- | ----------------------------- | --------------------------------------------------------------------------------------------------- |
| `signInMethods`              | `email_otp`, `passkey`        | Methods that may start a session.                                                                   |
| `secondFactor`               | `none`, `passkey_if_enrolled` | After an e-mail code: full session, or a pending state that needs a passkey if the account has one. |
| `stepUpMethods`              | `email_otp`, `passkey`        | Methods that may satisfy a step-up. `requireStepUp` can narrow the list, never widen it.            |
| `createAccountOnFirstSignIn` | `true`, `false`               | If false, an e-mail code sign-in for an unknown address fails like a wrong code.                    |

OWASP ASVS 5.0.0 requirement 6.3.6 (Level 3) says e-mail is not used as an authentication
mechanism, and NIST SP 800-63B-4 does not accept e-mail as an out-of-band authenticator. An
e-mail code is a proof of control of the address. For sensitive actions, require a passkey
step-up: `sessions.requireStepUp(token, { methods: ["passkey"] })`.

## Configuration

Every time and limit value is required configuration. identkit has no hidden defaults. The
example values below are what the tests use. Values marked "assumption" are not confirmed by a
standard or an owner decision; choose your own from your risk analysis.

| Setting                                  | Example | Bounds enforced                          | Source                                                                                                                   |
| ---------------------------------------- | ------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `emailOtp.codeTtlSeconds`                | 600     | 60 to 600                                | Upper bound: OWASP ASVS 5.0.0 6.5.5 (out-of-band codes at most 10 minutes). Value: assumption at the bound.              |
| `emailOtp.maxAttemptsPerCode`            | 5       | 1 to 10                                  | Assumption                                                                                                               |
| `emailOtp.resendCooldownSeconds`         | 30      | 1 to 3600                                | Assumption                                                                                                               |
| `emailOtp.addressLockout.maxFailures`    | 10      | 1 to 100                                 | Upper bound taken from NIST SP 800-63B-4 (at most 100 consecutive failed attempts per authenticator). Value: assumption. |
| `emailOtp.addressLockout.windowSeconds`  | 900     | 60 to 86400                              | Assumption                                                                                                               |
| `emailOtp.addressLockout.lockSeconds`    | 900     | 60 to 86400                              | Assumption                                                                                                               |
| `emailOtp.addressLockout.maxLockSeconds` | 86400   | 60 to 30 days, at least `lockSeconds`    | Assumption                                                                                                               |
| `sessions.idleTimeoutSeconds`            | 900     | 60 to 86400                              | Assumption (ASVS 7.3.1 asks for a documented inactivity timeout, no value)                                               |
| `sessions.absoluteTimeoutSeconds`        | 43200   | 60 to 30 days, at least the idle timeout | Assumption (ASVS 7.3.2 asks for a documented maximum lifetime, no value)                                                 |
| `sessions.pendingTimeoutSeconds`         | 300     | 30 to 3600                               | Assumption                                                                                                               |
| `stepUp.validitySeconds`                 | 300     | 30 to 3600                               | Assumption                                                                                                               |
| `webauthn.challengeTtlSeconds`           | 300     | 30 to 600                                | Assumption                                                                                                               |
| `identityVerification.timeoutSeconds`    | 1800    | 60 to 7 days                             | Assumption                                                                                                               |
| `enrollment.tokenTtlSeconds`             | 86400   | 60 to 7 days                             | Assumption                                                                                                               |

Fixed values:

| Value                       | Setting                     | Source                                      |
| --------------------------- | --------------------------- | ------------------------------------------- |
| Code length                 | 6 decimal digits            | Design choice                               |
| Token and challenge entropy | 256 bits from `node:crypto` | ASVS 5.0.0 7.2.3 asks for at least 128 bits |
| Hash key length             | at least 32 bytes           | Design choice (HMAC-SHA-256 key)            |

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
- Failed attempts are also counted per address and purpose across flows. After `maxFailures`
  in one window the address locks for `lockSeconds`, for known and unknown addresses alike. Each
  further lock without a success in between lasts twice as long, up to `maxLockSeconds`. A
  success resets the count. So guesses per address shrink over time, but they never reach zero:
  identkit does not disable an address for good after 100 failures, as NIST SP 800-63B-4 asks of
  an authenticator, because anyone who can request codes for an address could then lock its
  owner out for good.
- A person who can request codes for an address can trigger a lock: it trades a denial of
  service for brute-force protection. Escalation makes the brute-force bound stronger and a
  lasting lockout cheaper: once the lock reached `maxLockSeconds`, one burst of failures per
  `maxLockSeconds` keeps the address locked. Set `maxLockSeconds` equal to `lockSeconds` to turn
  escalation off.
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
- Every challenge is single use, bound to its purpose and session, and expires.
- Assertions need user verification, a configured origin and the RP ID. Ceremonies in a
  cross-origin frame are refused. The signature counter must increase unless the authenticator
  always reports zero.
- After a passkey ceremony wrote its result, identkit checks again that the same credential (id,
  account and public key) is still registered and the account is active. A revocation that races
  with a sign-in, second factor, step-up or approval therefore yields no session, step-up or
  proof. A registration applies its grant again after the insert and deletes the new passkey if
  the session ended or another passkey appeared meanwhile.
- Registration, removal and revocation of a passkey revoke sessions before the audit event, so
  a failing audit sink cannot skip the revocation.
- An e-mail sign-in checks the second-factor rule again after it created the session, so a first
  passkey registered at the same moment cannot leave a full session from a code alone.

Approval proofs:

- The challenge is `SHA-256("identkit/approval/v1" || nonce || payloadHash || accountId)`. The
  person signs it with a passkey of the session's account. `verify` recomputes the challenge from
  the payload hash it receives, so a signature for one payload cannot approve another.
- The proof holds the raw assertion and the nonce. `verifyApprovalEvidence` checks it again
  later with a public key you supply: challenge, signature, RP ID, origin and counter. It cannot
  check `verifiedAt`, and it cannot know that `credentialId` belonged to `accountId`: take the
  public key from your own record of that account's credentials.

One account per person:

- An address belongs to at most one account.
- An identity verification result carries a stable person key. identkit stores its HMAC and
  links it to at most one account. A second account for the same person ends as `conflict`.
- A verification reads `verified` only after the person is linked. If the link fails, it reads
  `pending` and the next `refresh` completes it.

## Identity verification port

Implement `IdentityVerificationAdapter` for a vendor: `start`, `parseCallback` (authenticate the
callback, throw if it is not authentic) and `fetchResult`. A result reports `verified` with an
assurance level (`low`, `substantial`, `high`), an evidence reference and a person key, or
`failed`, or `pending`. identkit applies the timeout. `createFakeIdentityVerificationAdapter`
succeeds, fails or never answers, for tests and demos.

## Audit events

identkit awaits `audit.emit` for every security-relevant event. If the sink throws, the operation
fails. Events carry ids and reasons, never a code, token, challenge, key, person key or e-mail
address. `addressDigest` is the HMAC of the address, for correlation.

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

identkit does not delete expired rows. Remove expired codes, challenges and sessions with a
scheduled job if you need to.

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

## Licence

MIT, see [LICENSE](LICENSE).
