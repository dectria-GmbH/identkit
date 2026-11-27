import { describe, expect, it } from "vitest";
import { fromBase64Url, toBase64Url, utf8 } from "../src/bytes.js";
import { createJwksCache } from "../src/index.js";
import { findKey, type OidcFetch } from "../src/oidc-jwks.js";
import { createFakeOidcProvider, type FakeOidcProvider } from "../src/testing/index.js";
import {
  ACME,
  GOOGLE,
  googleClaims,
  msClaims,
  oidcSetup,
  OTHER_TENANT,
  TENANT,
} from "./oidc-helpers.js";

function payloadOf(token: string): Record<string, unknown> {
  const part = token.split(".")[1] ?? "";
  return JSON.parse(new TextDecoder().decode(fromBase64Url(part) ?? new Uint8Array()));
}

/** The next ID token keeps its nonce but gets `change` applied to its claims, then re-signed. */
function resignNext(
  fake: FakeOidcProvider,
  change: (claims: Record<string, unknown>) => Record<string, unknown>,
  header?: Record<string, unknown>,
) {
  fake.replaceNextIdToken((token) => fake.signIdToken(change(payloadOf(token)), header));
}

const now = (t: { clock: { now(): Date } }) => Math.floor(t.clock.now().getTime() / 1000);

describe("oidc callback and transaction", () => {
  it("rule: login CSRF - a callback with another flow's state fails before any token request", async () => {
    const t = await oidcSetup();
    const victim = await t.ik.oidc.begin({ provider: "google" });
    const attacker = await t.ik.oidc.begin({ provider: "google" });
    const params = await t.fakes.google.authorize(
      attacker.authorizationUrl,
      googleClaims("a@example.org"),
    );
    expect(await t.ik.oidc.finish({ transaction: victim.transaction, params })).toEqual({
      status: "failed",
      reason: "state_mismatch",
    });
    params.delete("state");
    expect(await t.ik.oidc.finish({ transaction: attacker.transaction, params })).toEqual({
      status: "failed",
      reason: "state_mismatch",
    });
    expect(t.fakes.google.requests().token).toBe(0);
    expect(t.audit.ofType("oidc.sign_in_failed").at(-1)).toMatchObject({
      provider: "google",
      reason: "state_mismatch",
    });
  });

  it("rule: a changed, foreign or expired transaction fails", async () => {
    const t = await oidcSetup();
    const begun = await t.ik.oidc.begin({ provider: "google" });
    const params = await t.fakes.google.authorize(
      begun.authorizationUrl,
      googleClaims("a@example.org"),
    );
    const tail = begun.transaction.at(-2) === "A" ? "B" : "A";
    const changed = `${begun.transaction.slice(0, -2)}${tail}${begun.transaction.at(-1)}`;
    expect(await t.ik.oidc.finish({ transaction: changed, params })).toEqual({
      status: "failed",
      reason: "invalid_transaction",
    });
    const plain = new TextDecoder().decode(
      await t.sealer.open(begun.transaction, "identkit/oidc/transaction/v1"),
    );
    const foreign = await t.sealer.seal(utf8(plain), "some/other/context");
    expect(await t.ik.oidc.finish({ transaction: foreign, params })).toEqual({
      status: "failed",
      reason: "invalid_transaction",
    });
    expect(await t.ik.oidc.finish({ transaction: "", params })).toEqual({
      status: "failed",
      reason: "invalid_transaction",
    });
    t.clock.advanceSeconds(600);
    expect(await t.ik.oidc.finish({ transaction: begun.transaction, params })).toEqual({
      status: "failed",
      reason: "transaction_expired",
    });
  });

  it("rule: a provider error is reported with its code only if it is a plain word", async () => {
    const t = await oidcSetup();
    const begun = await t.ik.oidc.begin({ provider: "microsoft" });
    const state = new URL(begun.authorizationUrl).searchParams.get("state") ?? "";
    expect(
      await t.ik.oidc.finish({
        transaction: begun.transaction,
        params: { state, error: "access_denied", error_description: "user said no" },
      }),
    ).toEqual({ status: "failed", reason: "provider_error", providerError: "access_denied" });
    expect(
      await t.ik.oidc.finish({
        transaction: begun.transaction,
        params: { state, error: "<script>alert(1)</script>" },
      }),
    ).toEqual({ status: "failed", reason: "provider_error" });
    expect(await t.ik.oidc.finish({ transaction: begun.transaction, params: { state } })).toEqual({
      status: "failed",
      reason: "missing_code",
    });
  });

  it("rule: PKCE - the code is exchanged with the verifier of this transaction only", async () => {
    const t = await oidcSetup();
    const begun = await t.ik.oidc.begin({ provider: "google" });
    const url = new URL(begun.authorizationUrl);
    // An attacker who injects a code issued for another code challenge cannot redeem it here.
    url.searchParams.set("code_challenge", toBase64Url(new Uint8Array(32)));
    const params = await t.fakes.google.authorize(url.toString(), googleClaims("a@example.org"));
    expect(await t.ik.oidc.finish({ transaction: begun.transaction, params })).toEqual({
      status: "failed",
      reason: "token_request_failed",
    });
    expect(t.fakes.google.requests().token).toBe(1);
  });

  it("rule: a failing token or key endpoint fails the sign-in", async () => {
    const t = await oidcSetup();
    t.fakes.google.failNext("token");
    expect(await t.signInWith("google", googleClaims("a@example.org"))).toEqual({
      status: "failed",
      reason: "token_request_failed",
    });
    t.fakes.google.failNext("jwks");
    expect(await t.signInWith("google", googleClaims("a@example.org"))).toEqual({
      status: "failed",
      reason: "keys_unavailable",
    });
    expect((await t.signInWith("google", googleClaims("a@example.org"))).status).toBe("signed_in");
  });

  it("rule: a generic provider with client_secret_basic and ES256 signs in", async () => {
    const t = await oidcSetup();
    const result = await t.signInWith("acme", {
      sub: "acme-1",
      email: "a@acme.example",
      email_verified: true,
    });
    if (result.status !== "signed_in") throw new Error(result.status);
    const [link] = await t.ik.oidc.listLinks(result.account.id);
    expect(link).toMatchObject({ provider: "oidc", issuer: ACME.issuer, subject: "acme-1" });
  });
});

describe("oidc ID token verification", () => {
  it("rule: nonce - a token for another nonce is refused", async () => {
    const t = await oidcSetup();
    resignNext(t.fakes.google, (c) => ({ ...c, nonce: "replayed-nonce" }));
    expect(await t.signInWith("google", googleClaims("a@example.org"))).toEqual({
      status: "failed",
      reason: "invalid_id_token",
    });
    resignNext(t.fakes.google, ({ nonce: _nonce, ...c }) => c);
    expect((await t.signInWith("google", googleClaims("a@example.org"))).status).toBe("failed");
  });

  it("rule: audience - aud must name the client, azp must name it when present or with several audiences", async () => {
    const t = await oidcSetup();
    const signIn = () => t.signInWith("google", googleClaims("a@example.org"));
    resignNext(t.fakes.google, (c) => ({ ...c, aud: "another-client" }));
    expect((await signIn()).status).toBe("failed");
    resignNext(t.fakes.google, (c) => ({ ...c, aud: [GOOGLE.clientId, "another-client"] }));
    expect((await signIn()).status).toBe("failed");
    resignNext(t.fakes.google, (c) => ({ ...c, azp: "another-client" }));
    expect((await signIn()).status).toBe("failed");
    // An extra audience is refused unless the operator trusts it, also with azp.
    resignNext(t.fakes.google, (c) => ({
      ...c,
      aud: [GOOGLE.clientId, "another-client"],
      azp: GOOGLE.clientId,
    }));
    expect((await signIn()).status).toBe("failed");

    const trusting = await oidcSetup({ google: { extraAudiences: ["another-client"] } });
    const signInTrusting = () => trusting.signInWith("google", googleClaims("b@example.org"));
    resignNext(trusting.fakes.google, (c) => ({
      ...c,
      aud: [GOOGLE.clientId, "another-client"],
      azp: GOOGLE.clientId,
    }));
    expect((await signInTrusting()).status).toBe("signed_in");
    resignNext(trusting.fakes.google, (c) => ({
      ...c,
      aud: [GOOGLE.clientId, "third-client"],
      azp: GOOGLE.clientId,
    }));
    expect((await signInTrusting()).status).toBe("failed");
    // Without azp, several audiences stay refused.
    resignNext(trusting.fakes.google, (c) => ({ ...c, aud: [GOOGLE.clientId, "another-client"] }));
    expect((await signInTrusting()).status).toBe("failed");
  });

  it("rule: times - exp, iat and nbf apply with the configured clock skew", async () => {
    const t = await oidcSetup();
    const signIn = () => t.signInWith("google", googleClaims("a@example.org"));
    resignNext(t.fakes.google, (c) => ({ ...c, exp: now(t) - 61 }));
    expect((await signIn()).status).toBe("failed");
    resignNext(t.fakes.google, (c) => ({ ...c, exp: now(t) - 59 }));
    expect((await signIn()).status).toBe("signed_in");
    resignNext(t.fakes.google, (c) => ({ ...c, iat: now(t) + 61 }));
    expect((await signIn()).status).toBe("failed");
    resignNext(t.fakes.google, (c) => ({ ...c, nbf: now(t) + 61 }));
    expect((await signIn()).status).toBe("failed");
    resignNext(t.fakes.google, ({ exp: _exp, ...c }) => c);
    expect((await signIn()).status).toBe("failed");
  });

  it("rule: issuer - Microsoft's iss must be the token's own tenant; Google's must be Google", async () => {
    const t = await oidcSetup();
    expect(
      await t.signInWith(
        "microsoft",
        msClaims("a@contoso.example", {
          iss: `https://login.microsoftonline.com/${OTHER_TENANT}/v2.0`,
        }),
      ),
    ).toEqual({ status: "failed", reason: "invalid_id_token" });
    expect(
      await t.signInWith("microsoft", msClaims("a@contoso.example", { tid: "not-a-guid" })),
    ).toEqual({ status: "failed", reason: "invalid_id_token" });
    expect(
      await t.signInWith("microsoft", msClaims("a@contoso.example", { oid: undefined })),
    ).toEqual({ status: "failed", reason: "invalid_id_token" });
    expect(
      await t.signInWith("google", googleClaims("a@example.org", { iss: "https://evil.example" })),
    ).toEqual({ status: "failed", reason: "invalid_id_token" });
    expect(
      (await t.signInWith("microsoft", msClaims("a@contoso.example", { tid: TENANT }))).status,
    ).toBe("signed_in");
  });

  it("rule: signature - a changed, unsigned, HMAC or foreign-key token is refused", async () => {
    const t = await oidcSetup();
    const signIn = () => t.signInWith("google", googleClaims("a@example.org"));
    t.fakes.google.replaceNextIdToken((token) => {
      const [h, , s] = token.split(".");
      const forged = toBase64Url(
        utf8(JSON.stringify({ ...payloadOf(token), sub: "someone-else" })),
      );
      return `${h}.${forged}.${s}`;
    });
    expect((await signIn()).status).toBe("failed");
    t.fakes.google.replaceNextIdToken((token) => {
      const [, p] = token.split(".");
      return `${toBase64Url(utf8(JSON.stringify({ alg: "none" })))}.${p}.`;
    });
    expect((await signIn()).status).toBe("failed");
    t.fakes.google.replaceNextIdToken((token) => {
      const [h, p, s] = token.split(".");
      const header = JSON.parse(
        new TextDecoder().decode(fromBase64Url(h ?? "") ?? new Uint8Array()),
      );
      return `${toBase64Url(utf8(JSON.stringify({ ...header, alg: "HS256" })))}.${p}.${s}`;
    });
    expect((await signIn()).status).toBe("failed");
    resignNext(t.fakes.google, (c) => c, { crit: ["exp"] });
    expect((await signIn()).status).toBe("failed");

    // Signed by another key that claims the provider's key id.
    const other = await createFakeOidcProvider({ kind: "google", ...GOOGLE });
    t.fakes.google.replaceNextIdToken(async (token) => {
      const kid = JSON.parse(
        new TextDecoder().decode(fromBase64Url(token.split(".")[0] ?? "") ?? new Uint8Array()),
      ).kid;
      return other.signIdToken(payloadOf(token), { kid });
    });
    expect((await signIn()).status).toBe("failed");
    expect(
      t.audit.ofType("oidc.sign_in_failed").every((e) => e.reason === "invalid_id_token"),
    ).toBe(true);
    expect((await signIn()).status).toBe("signed_in");
  });
});

describe("oidc key cache", () => {
  it("rule: a rotated key is fetched once; further unknown keys wait for the refetch interval", async () => {
    const t = await oidcSetup();
    const claims = googleClaims("a@example.org");
    const signIn = () => t.signInWith("google", claims);
    expect((await signIn()).status).toBe("signed_in");
    expect(t.fakes.google.requests().jwks).toBe(1);

    await t.fakes.google.rotateKey();
    t.clock.advanceSeconds(60);
    expect((await signIn()).status).toBe("signed_in");
    expect(t.fakes.google.requests().jwks).toBe(2);

    await t.fakes.google.rotateKey();
    expect(await signIn()).toEqual({ status: "failed", reason: "invalid_id_token" });
    expect(t.fakes.google.requests().jwks).toBe(2);
    t.clock.advanceSeconds(60);
    expect((await signIn()).status).toBe("signed_in");
    expect(t.fakes.google.requests().jwks).toBe(3);

    // After the TTL the keys are fetched again, also for a known key id.
    t.clock.advanceSeconds(3600);
    expect((await signIn()).status).toBe("signed_in");
    expect(t.fakes.google.requests().jwks).toBe(4);
  });

  it("rule: subrequest budget - one finish makes at most one token and one key request", async () => {
    const t = await oidcSetup();
    let before = t.fetchLog.length;
    expect((await t.signInWith("microsoft", msClaims("a@contoso.example"))).status).toBe(
      "signed_in",
    );
    expect(t.fetchLog.length - before).toBe(2);
    before = t.fetchLog.length;
    expect((await t.signInWith("microsoft", msClaims("b@contoso.example"))).status).toBe(
      "signed_in",
    );
    expect(t.fetchLog.length - before).toBe(1);
    await t.fakes.microsoft.rotateKey();
    t.clock.advanceSeconds(3600);
    before = t.fetchLog.length;
    expect((await t.signInWith("microsoft", msClaims("c@contoso.example"))).status).toBe(
      "signed_in",
    );
    expect(t.fetchLog.length - before).toBe(2);
  });

  it("rule: a shared cache serves several identkit instances and shares concurrent fetches", async () => {
    const fake = await createFakeOidcProvider({ kind: "google", ...GOOGLE });
    let fetches = 0;
    const fetch: OidcFetch = async (url, init) => {
      fetches += 1;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return fake.fetch(url, init);
    };
    const cache = createJwksCache();
    const token = await fake.signIdToken({ sub: "x" });
    const kid = JSON.parse(
      new TextDecoder().decode(fromBase64Url(token.split(".")[0] ?? "") ?? new Uint8Array()),
    ).kid;
    const lookup = {
      fetch,
      now: () => 0,
      ttlMs: 3_600_000,
      refetchIntervalMs: 60_000,
      timeoutMs: 1000,
    };
    const keys = await Promise.all(
      Array.from({ length: 5 }, () => findKey(cache, fake.jwksUri, { kid, alg: "RS256" }, lookup)),
    );
    expect(keys.every((k) => k !== null)).toBe(true);
    expect(fetches).toBe(1);
    expect(await findKey(cache, fake.jwksUri, { kid, alg: "RS256" }, lookup)).not.toBeNull();
    expect(fetches).toBe(1);
    expect(await findKey(cache, fake.jwksUri, { kid: "unknown", alg: "RS256" }, lookup)).toBeNull();
    expect(fetches).toBe(1);
    cache.clear();
    expect(await findKey(cache, fake.jwksUri, { kid, alg: "RS256" }, lookup)).not.toBeNull();
    expect(fetches).toBe(2);
  });
});
