// Smoke test that runs inside workerd without nodejs_compat. scripts/check-workerd.mjs bundles
// it with the built `dist` entries and calls it. Passkey ceremonies need an authenticator: the
// AUTHENTICATOR service binding runs the software authenticator on Node, because that test tool
// signs with node:crypto. Everything identkit does runs here. The DB binding is a local D1
// database for the `identkit/d1` checks.
import {
  approvalChallengeAsync,
  checkApprovalEvidence,
  createAesGcmSealer,
  createHmacHasher,
  createIdentkit,
  createMemoryStore,
  hashPayload,
  hashPayloadAsync,
  NodeCryptoUnavailableError,
} from "../../dist/index.js";
import { createD1Store, D1_MIGRATIONS, migrateIdentkitD1 } from "../../dist/d1/index.js";
import {
  createFakeClock,
  createFakeIdentityVerificationAdapter,
  createRecordingAuditSink,
  createRecordingMailSender,
  createTestSealer,
  generateTotpCodeAsync,
} from "../../dist/testing/index.js";
import {
  APPROVAL_CHALLENGES,
  DIGESTS,
  HASH_KEY_HEX,
  PAYLOAD_HASHES,
  SEAL_KEY_K1_HEX,
  SEAL_KEY_OLD_HEX,
  SEALED,
} from "../compat-vectors.ts";
import { basePolicy, config, ORIGIN } from "./smoke-config.js";

function hex(text) {
  const bytes = new Uint8Array(text.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

function check(condition, message) {
  if (!condition) throw new Error(message);
}

function setup(store = createMemoryStore()) {
  const clock = createFakeClock();
  const mail = createRecordingMailSender();
  const policy = { current: basePolicy };
  const ik = createIdentkit({
    config,
    sealer: createTestSealer(),
    isPrivilegedAccount: () => false,
    store,
    hasher: createHmacHasher(crypto.getRandomValues(new Uint8Array(32))),
    mail,
    audit: createRecordingAuditSink(),
    clock,
    policy: () => policy.current,
  });
  async function signIn(email) {
    const requested = await ik.emailSignIn.requestCode({ email });
    check(requested.status === "sent", `code not sent: ${requested.status}`);
    return ik.emailSignIn.verifyCode({ flowId: requested.flowId, code: mail.last()?.code ?? "" });
  }
  return { ik, clock, store, policy, signIn };
}

async function authenticator(env, action, options) {
  const response = await env.AUTHENTICATOR.fetch(`http://authenticator/${action}`, {
    method: "POST",
    body: JSON.stringify(options),
  });
  check(response.ok, `authenticator ${action} failed: ${response.status}`);
  return response.json();
}

const checks = {
  runtime() {
    check(typeof globalThis.process === "undefined", "process is defined");
    check(typeof globalThis.Buffer === "undefined", "Buffer is defined");
  },

  async hasherDigests() {
    const hasher = createHmacHasher(hex(HASH_KEY_HEX));
    for (const [purpose, value, digest] of DIGESTS) {
      check((await hasher.digest(purpose, value)) === digest, `digest ${purpose} ${value}`);
    }
  },

  async sealOpen() {
    const sealer = createAesGcmSealer({
      keys: { k1: hex(SEAL_KEY_K1_HEX), old: hex(SEAL_KEY_OLD_HEX) },
      activeKeyId: "k1",
    });
    for (const [plaintext, context, sealed] of SEALED) {
      check(toHex(await sealer.open(sealed, context)) === plaintext, `open ${sealed}`);
    }
    const fresh = await sealer.seal(hex("0102"), "context");
    check(toHex(await sealer.open(fresh, "context")) === "0102", "seal and open");
  },

  async approvalVectors() {
    for (const [nonce, payloadHash, accountId, challenge] of APPROVAL_CHALLENGES) {
      const actual = await approvalChallengeAsync(nonce, payloadHash, accountId);
      check(actual === challenge, `approval challenge ${nonce}`);
    }
    for (const [payload, digest] of PAYLOAD_HASHES) {
      const input = payload.startsWith("bytes:") ? hex(payload.slice(6)) : payload;
      check((await hashPayloadAsync(input)) === digest, `payload hash ${payload}`);
    }
  },

  syncExportThrows() {
    try {
      hashPayload("x");
    } catch (error) {
      check(error instanceof NodeCryptoUnavailableError, "wrong error class");
      check(String(error.message).includes("hashPayloadAsync"), "message names no sibling");
      return;
    }
    throw new Error("hashPayload did not throw");
  },

  async emailSignInAndSession() {
    const t = setup();
    const result = await t.signIn("person@example.org");
    check(result.status === "signed_in", `sign-in: ${result.status}`);
    const view = await t.ik.sessions.validate(result.token);
    check(view?.accountId === result.account.id, "session does not validate");
  },

  async totpEnrolAndSecondFactor() {
    const t = setup();
    const user = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    check(start.status === "ok", `enrolment: ${start.reason}`);
    const code = await generateTotpCodeAsync({ secret: start.secret, at: t.clock.now() });
    const confirmed = await t.ik.totp.confirmEnrolment(user.token, {
      factorId: start.factorId,
      code,
    });
    check(confirmed.status === "enrolled", `confirm: ${confirmed.status}`);
    t.policy.current = { ...basePolicy, secondFactor: "if_enrolled" };
    t.clock.advanceSeconds(30);
    const pending = await t.signIn("person@example.org");
    check(pending.status === "second_factor_required", `second sign-in: ${pending.status}`);
    const done = await t.ik.totp.verifySecondFactor(pending.pendingToken, {
      code: await generateTotpCodeAsync({ secret: start.secret, at: t.clock.now() }),
    });
    check(done.status === "signed_in", `totp: ${done.status}`);
  },

  async passkeysAndApproval(env) {
    const t = setup();
    await authenticator(env, "reset", {});
    const user = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: user.token });
    check(start.status === "ok", `registration start: ${start.reason}`);
    const registration = await authenticator(env, "register", start.options);
    const finish = await t.ik.passkeys.finishRegistration(
      { sessionToken: user.token },
      registration,
    );
    check(finish.status === "registered", `registration: ${finish.status}`);

    const { options } = await t.ik.passkeys.startSignIn();
    const signIn = await t.ik.passkeys.finishSignIn(await authenticator(env, "assert", options));
    check(signIn.status === "signed_in", `passkey sign-in: ${signIn.status}`);

    const payloadHash = await hashPayloadAsync("release 1");
    const approval = await t.ik.approvals.start({ sessionToken: user.token, payloadHash });
    check(approval.status === "ok" && approval.level === "signature", "approval start");
    const verified = await t.ik.approvals.verify({
      sessionToken: user.token,
      payloadHash,
      response: await authenticator(env, "assert", approval.options),
    });
    check(verified.status === "approved", `approval: ${verified.status}`);
    const credential = await t.store.credentials.findById(finish.credentialId);
    const evidence = await checkApprovalEvidence({
      evidence: verified.evidence,
      verifier: {
        credentialPublicKey: credential.publicKey,
        rpId: config.webauthn.rpId,
        origins: [ORIGIN],
      },
    });
    check(evidence.status === "verified", `evidence: ${evidence.status}`);
  },

  async d1SignInAndRevoke(env) {
    const applied = await migrateIdentkitD1(env.DB);
    check(applied.length === D1_MIGRATIONS.length, `applied ${applied.length} migrations`);
    check((await migrateIdentkitD1(env.DB)).length === 0, "second run applied migrations");
    const t = setup(createD1Store(env.DB));
    const result = await t.signIn("d1-person@example.org");
    check(result.status === "signed_in", `d1 sign-in: ${result.status}`);
    const view = await t.ik.sessions.validate(result.token);
    check(view?.accountId === result.account.id, "d1 session does not validate");
    await t.ik.sessions.revoke(result.token);
    check((await t.ik.sessions.validate(result.token)) === null, "d1 session survives revoke");
  },

  d1RefusesReplicaSession(env) {
    check(typeof env.DB.withSession === "function", "D1 binding has no withSession");
    let refused = false;
    try {
      createD1Store(env.DB.withSession());
    } catch (error) {
      refused = error instanceof TypeError;
    }
    check(refused, "an unconstrained D1 session was accepted");
    createD1Store(env.DB.withSession("first-primary"), { sessionConstraint: "first-primary" });
  },

  async fakeIdentityCallback() {
    const adapter = createFakeIdentityVerificationAdapter({ outcome: "succeed" });
    const { vendorReference } = await adapter.start({ verificationId: "v1" });
    const parsed = await adapter.parseCallback(await adapter.callbackForAsync(vendorReference));
    check(parsed.vendorReference === vendorReference, "callback does not verify");
  },
};

async function smoke(env) {
  const results = [];
  for (const [name, run] of Object.entries(checks)) {
    try {
      await run(env);
      results.push({ name, ok: true });
    } catch (error) {
      results.push({ name, ok: false, error: String(error?.stack ?? error) });
    }
  }
  return results;
}

/** Runs `n` session validations, so the caller can time them. */
async function bench(n) {
  const t = setup();
  const result = await t.signIn("person@example.org");
  let valid = 0;
  for (let i = 0; i < n; i += 1) {
    if (await t.ik.sessions.validate(result.token)) valid += 1;
  }
  return { n, valid };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/bench") {
      return Response.json(await bench(Number(url.searchParams.get("n") ?? "0")));
    }
    return Response.json(await smoke(env));
  },
};
