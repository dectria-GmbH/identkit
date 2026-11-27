import { describe, expect, it } from "vitest";
import {
  createMemoryStore,
  googleProvider,
  InvalidArgumentError,
  MethodNotAllowedError,
  MICROSOFT_CONSUMER_TENANT_ID,
  NotConfiguredError,
  type OidcBindRequest,
} from "../src/index.js";
import { mfaPolicy, setup, testConfig, testOidcConfig } from "./helpers.js";
import {
  googleClaims,
  guid,
  msClaims,
  oidcPolicy,
  oidcSetup,
  OTHER_TENANT,
  REDIRECT_URI,
  TENANT,
} from "./oidc-helpers.js";

describe("oidc sign-in", () => {
  it("flow: begin asks for code with PKCE S256, state and nonce; finish signs in and binds", async () => {
    const t = await oidcSetup();
    const begun = await t.ik.oidc.begin({ provider: "google", loginHint: "person@example.org" });
    const url = new URL(begun.authorizationUrl);
    expect(`${url.origin}${url.pathname}`).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    const q = url.searchParams;
    expect(q.get("response_type")).toBe("code");
    expect(q.get("client_id")).toBe("google-client-id");
    expect(q.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(q.get("scope")).toBe("openid email profile");
    expect(q.get("code_challenge_method")).toBe("S256");
    expect(q.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(q.get("state")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(q.get("nonce")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(q.get("login_hint")).toBe("person@example.org");
    expect(q.has("prompt")).toBe(false);
    // The transaction is sealed: neither state, nonce nor verifier shows in it.
    expect(begun.transaction).not.toContain(q.get("state"));
    expect(begun.transaction).not.toContain(q.get("nonce"));
    expect(begun.expiresAt.getTime() - t.clock.now().getTime()).toBe(600_000);

    const claims = googleClaims("Person@Example.org");
    const params = await t.fakes.google.authorize(begun.authorizationUrl, claims);
    const result = await t.ik.oidc.finish({ transaction: begun.transaction, params });
    if (result.status !== "signed_in") throw new Error(`not signed in: ${result.status}`);
    expect(result.accountCreated).toBe(true);
    expect(result.linkCreated).toBe(true);
    expect(result.account.email).toBe("person@example.org");
    expect(result.session.authMethods).toEqual(["oidc"]);
    expect(result.session.stepUp).toBeNull();
    expect((await t.ik.sessions.validate(result.token))?.accountId).toBe(result.account.id);

    const links = await t.ik.oidc.listLinks(result.account.id);
    expect(links).toEqual([
      expect.objectContaining({
        provider: "google",
        issuer: "https://accounts.google.com",
        subject: claims["sub"],
        tenantId: null,
        source: "sign_in",
      }),
    ]);
    expect(t.audit.ofType("oidc.link_created")).toEqual([
      expect.objectContaining({
        accountId: result.account.id,
        linkId: links[0]?.id,
        provider: "google",
      }),
    ]);
    expect(t.audit.ofType("oidc.signed_in")).toEqual([
      expect.objectContaining({ accountId: result.account.id, sessionId: result.session.id }),
    ]);
    expect(t.audit.ofType("session.created").at(-1)?.method).toBe("oidc");
  });

  it("rule: audit events carry no token, code, subject or address", async () => {
    const t = await oidcSetup();
    const claims = googleClaims("secretive@example.org", { sub: "subject-1234567" });
    const begun = await t.ik.oidc.begin({ provider: "google" });
    const params = await t.fakes.google.authorize(begun.authorizationUrl, claims);
    const result = await t.ik.oidc.finish({ transaction: begun.transaction, params });
    expect(result.status).toBe("signed_in");
    await t.signInWith("google", googleClaims("other@example.org", { email_verified: false }));
    const dump = JSON.stringify(t.audit.events);
    for (const secret of [
      "subject-1234567",
      "secretive@example.org",
      "other@example.org",
      params.get("code") ?? "",
      begun.transaction,
      "google-client-secret",
    ]) {
      expect(dump).not.toContain(secret);
    }
    expect(dump).not.toMatch(/eyJ[A-Za-z0-9_-]+\./);
  });

  it("rule: a second sign-in uses the link and the cached keys", async () => {
    const t = await oidcSetup();
    const claims = googleClaims("person@example.org");
    const first = await t.signInWith("google", claims);
    const second = await t.signInWith("google", { ...claims, email: "renamed@example.org" });
    if (first.status !== "signed_in" || second.status !== "signed_in") throw new Error("no");
    expect(second.account.id).toBe(first.account.id);
    expect(second.linkCreated).toBe(false);
    expect(second.accountCreated).toBe(false);
    expect(t.fakes.google.requests()).toEqual({ token: 2, jwks: 1 });
  });

  it("rule: Microsoft binds by (tid, oid) with a domain-verified address and asks to select an account", async () => {
    const t = await oidcSetup();
    const begun = await t.ik.oidc.begin({ provider: "microsoft" });
    const url = new URL(begun.authorizationUrl);
    expect(`${url.origin}${url.pathname}`).toBe(
      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    );
    expect(url.searchParams.get("prompt")).toBe("select_account");
    expect(url.searchParams.get("scope")).toBe("openid email profile");
    const claims = msClaims("worker@contoso.example");
    const params = await t.fakes.microsoft.authorize(begun.authorizationUrl, claims);
    const result = await t.ik.oidc.finish({ transaction: begun.transaction, params });
    if (result.status !== "signed_in") throw new Error(result.status);
    const [link] = await t.ik.oidc.listLinks(result.account.id);
    expect(link).toMatchObject({
      provider: "microsoft",
      tenantId: TENANT,
      subject: claims["oid"],
      issuer: `https://login.microsoftonline.com/${TENANT}/v2.0`,
    });
  });

  it("rule: the address never links - a second subject with the same address is refused", async () => {
    const t = await oidcSetup();
    const first = await t.signInWith("microsoft", msClaims("worker@contoso.example"));
    expect(first.status).toBe("signed_in");
    // Same address, other object id (for example a guest or a re-created user).
    const second = await t.signInWith("microsoft", msClaims("worker@contoso.example"));
    expect(second).toEqual({ status: "refused", reason: "account_has_link" });
    expect(t.audit.ofType("oidc.binding_refused").at(-1)).toMatchObject({
      reason: "account_has_link",
      provider: "microsoft",
    });
  });

  it("rule: one provider per account by default; linksPerAccount any allows more", async () => {
    const strict = await oidcSetup();
    expect((await strict.signInWith("microsoft", msClaims("both@example.org"))).status).toBe(
      "signed_in",
    );
    expect(await strict.signInWith("google", googleClaims("both@example.org"))).toEqual({
      status: "refused",
      reason: "account_has_link",
    });

    const relaxed = await oidcSetup({ linksPerAccount: "any" });
    const ms = await relaxed.signInWith("microsoft", msClaims("both@example.org"));
    const google = await relaxed.signInWith("google", googleClaims("both@example.org"));
    if (ms.status !== "signed_in" || google.status !== "signed_in") throw new Error("no");
    expect(google.account.id).toBe(ms.account.id);
    expect(await relaxed.ik.oidc.listLinks(ms.account.id)).toHaveLength(2);
  });

  it("rule: the Microsoft consumer tenant never binds, but an imported consumer link signs in", async () => {
    const t = await oidcSetup();
    const consumer = msClaims("person@outlook.example", {
      tid: MICROSOFT_CONSUMER_TENANT_ID,
      xms_edov: true,
    });
    expect(await t.signInWith("microsoft", consumer)).toEqual({
      status: "refused",
      reason: "consumer_tenant",
    });
    expect(t.audit.ofType("oidc.binding_refused").at(-1)?.reason).toBe("consumer_tenant");

    const account = await t.ik.accounts.create({ email: "person@outlook.example" });
    if (account.status !== "created") throw new Error("no account");
    const imported = await t.ik.oidc.importLink({
      accountId: account.account.id,
      provider: "microsoft",
      tenantId: MICROSOFT_CONSUMER_TENANT_ID.toUpperCase(),
      objectId: String(consumer["oid"]),
    });
    expect(imported.status).toBe("imported");
    const result = await t.signInWith("microsoft", consumer);
    if (result.status !== "signed_in") throw new Error(result.status);
    expect(result.account.id).toBe(account.account.id);
  });

  it("rule: Microsoft without xms_edov binds only with upnAsAddress, by preferred_username", async () => {
    const strict = await oidcSetup();
    const claims = msClaims("unused@contoso.example", {
      xms_edov: undefined,
      preferred_username: "upn.person@contoso.example",
    });
    expect(await strict.signInWith("microsoft", claims)).toEqual({
      status: "refused",
      reason: "unverified_address",
    });
    expect(
      await strict.signInWith("microsoft", { ...claims, oid: guid(), xms_edov: false }),
    ).toEqual({ status: "refused", reason: "unverified_address" });

    const upn = await oidcSetup({ microsoft: { upnAsAddress: true } });
    const result = await upn.signInWith("microsoft", claims);
    if (result.status !== "signed_in") throw new Error(result.status);
    expect(result.account.email).toBe("upn.person@contoso.example");
  });

  it("rule: allowedTenants and a tenant authority restrict who signs in at all", async () => {
    const t = await oidcSetup({ microsoft: { allowedTenants: [TENANT.toUpperCase()] } });
    expect((await t.signInWith("microsoft", msClaims("a@contoso.example"))).status).toBe(
      "signed_in",
    );
    expect(
      await t.signInWith("microsoft", msClaims("b@fabrikam.example", { tid: OTHER_TENANT })),
    ).toEqual({ status: "refused", reason: "organization_not_allowed" });
    expect(t.audit.ofType("oidc.sign_in_failed").at(-1)?.reason).toBe("organization_not_allowed");

    const orgs = await oidcSetup({ microsoftTenant: "organizations" });
    expect(
      await orgs.signInWith(
        "microsoft",
        msClaims("p@outlook.example", { tid: MICROSOFT_CONSUMER_TENANT_ID }),
      ),
    ).toEqual({ status: "refused", reason: "organization_not_allowed" });
  });

  it("rule: Google binds only a verified address; hostedDomains restricts", async () => {
    const t = await oidcSetup({ google: { hostedDomains: ["example.org"] } });
    expect(
      await t.signInWith(
        "google",
        googleClaims("p@example.org", { email_verified: false, hd: "example.org" }),
      ),
    ).toEqual({ status: "refused", reason: "unverified_address" });
    expect(await t.signInWith("google", googleClaims("p@example.org"))).toEqual({
      status: "refused",
      reason: "organization_not_allowed",
    });
    expect(
      (await t.signInWith("google", googleClaims("p@example.org", { hd: "example.org" }))).status,
    ).toBe("signed_in");
  });

  it("rule: a first sign-in binds to the existing account of the address", async () => {
    const t = await oidcSetup();
    const byCode = await t.signIn("existing@example.org");
    const result = await t.signInWith("google", googleClaims("existing@example.org"));
    if (result.status !== "signed_in") throw new Error(result.status);
    expect(result.account.id).toBe(byCode.account.id);
    expect(result.accountCreated).toBe(false);
    expect(result.linkCreated).toBe(true);
  });

  it("rule: no account for the address follows createAccountOnFirstSignIn", async () => {
    const t = await oidcSetup({ policy: { ...oidcPolicy, createAccountOnFirstSignIn: false } });
    expect(await t.signInWith("google", googleClaims("nobody@example.org"))).toEqual({
      status: "refused",
      reason: "no_account",
    });
    expect(await t.ik.accounts.findByEmail("nobody@example.org")).toBeNull();
    expect(t.audit.ofType("oidc.binding_refused").at(-1)).toMatchObject({
      reason: "no_account",
      addressDigest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
  });

  it("rule: the policy must list oidc", async () => {
    const t = await oidcSetup();
    const begun = await t.ik.oidc.begin({ provider: "google" });
    t.policy.current = mfaPolicy;
    await expect(t.ik.oidc.begin({ provider: "google" })).rejects.toBeInstanceOf(
      MethodNotAllowedError,
    );
    const params = await t.fakes.google.authorize(
      begun.authorizationUrl,
      googleClaims("x@example.org"),
    );
    await expect(
      t.ik.oidc.finish({ transaction: begun.transaction, params }),
    ).rejects.toBeInstanceOf(MethodNotAllowedError);
  });

  it("rule: mayBind can refuse a binding, sees the request, and is not asked for a linked subject", async () => {
    const requests: OidcBindRequest[] = [];
    let allow = false;
    const t = await oidcSetup({
      mayBind: (request) => {
        requests.push(request);
        return allow;
      },
    });
    const claims = msClaims("hooked@contoso.example");
    expect(await t.signInWith("microsoft", claims)).toEqual({
      status: "refused",
      reason: "refused_by_hook",
    });
    expect(requests).toEqual([
      {
        provider: "microsoft",
        kind: "microsoft",
        issuer: `https://login.microsoftonline.com/${TENANT}/v2.0`,
        subject: claims["oid"],
        tenantId: TENANT,
        email: "hooked@contoso.example",
        account: null,
      },
    ]);
    expect(await t.ik.accounts.findByEmail("hooked@contoso.example")).toBeNull();
    allow = true;
    expect((await t.signInWith("microsoft", claims)).status).toBe("signed_in");
    expect((await t.signInWith("microsoft", claims)).status).toBe("signed_in");
    expect(requests).toHaveLength(2);
  });

  it("rule: mayBind cannot override identkit's rules, and must return a boolean", async () => {
    const t = await oidcSetup({ mayBind: () => true });
    expect(
      await t.signInWith("google", googleClaims("x@example.org", { email_verified: false })),
    ).toEqual({ status: "refused", reason: "unverified_address" });
    const odd = await oidcSetup({ mayBind: (() => "yes") as unknown as () => boolean });
    await expect(odd.signInWith("google", googleClaims("y@example.org"))).rejects.toThrow(
      /boolean/,
    );
  });

  it("rule: a disabled account does not sign in through its link", async () => {
    const t = await oidcSetup();
    const claims = googleClaims("gone@example.org");
    const first = await t.signInWith("google", claims);
    if (first.status !== "signed_in") throw new Error(first.status);
    await t.ik.accounts.disable(first.account.id);
    expect(await t.signInWith("google", claims)).toEqual({
      status: "refused",
      reason: "account_disabled",
    });
  });

  it("rule: removeLink revokes the account's sessions; the subject can bind again", async () => {
    const t = await oidcSetup();
    const claims = googleClaims("reset@example.org");
    const first = await t.signInWith("google", claims);
    if (first.status !== "signed_in") throw new Error(first.status);
    const [link] = await t.ik.oidc.listLinks(first.account.id);
    if (!link) throw new Error("no link");
    expect(await t.ik.oidc.removeLink("other-account", link.id)).toBe(false);
    expect(await t.ik.oidc.removeLink(first.account.id, link.id)).toBe(true);
    expect(await t.ik.sessions.validate(first.token)).toBeNull();
    expect(t.audit.ofType("oidc.link_removed")).toEqual([
      expect.objectContaining({ accountId: first.account.id, linkId: link.id }),
    ]);
    expect(await t.ik.oidc.removeLink(first.account.id, link.id)).toBe(false);
    const again = await t.signInWith("google", claims);
    if (again.status !== "signed_in") throw new Error(again.status);
    expect(again.linkCreated).toBe(true);
    expect(again.account.id).toBe(first.account.id);
  });

  it("rule: the second factor rule of e-mail codes applies", async () => {
    const t = await oidcSetup({ privilegedEmails: ["admin@example.org"] });
    expect(await t.signInWith("google", googleClaims("admin@example.org"))).toEqual({
      status: "second_factor_unavailable",
      reason: "enrolment_required",
    });

    // An OIDC session has no step-up, so the factor is enrolled from an e-mail code session.
    const byCode = await t.signIn("mfa@example.org");
    const { secret } = await t.enrolTotp(byCode.token);
    const claims = googleClaims("mfa@example.org");
    t.policy.current = { ...mfaPolicy, signInMethods: ["email_otp", "passkey", "oidc"] };
    t.clock.advanceSeconds(30);
    const pending = await t.signInWith("google", claims);
    if (pending.status !== "second_factor_required") throw new Error(pending.status);
    expect(pending.methods).toEqual(["totp"]);
    const done = await t.ik.totp.verifySecondFactor(pending.pendingToken, {
      code: t.totpCode(secret),
    });
    if (done.status !== "signed_in") throw new Error(done.status);
    expect(done.session.authMethods).toEqual(["oidc", "totp"]);
  });

  it("rule: concurrent first sign-ins of one subject leave one link and one account", async () => {
    const t = await oidcSetup();
    const claims = googleClaims("race@example.org");
    const results = await Promise.all(
      Array.from({ length: 4 }, () => t.signInWith("google", claims)),
    );
    const ids = new Set(results.map((r) => (r.status === "signed_in" ? r.account.id : r.status)));
    expect([...ids]).toHaveLength(1);
    expect(results.filter((r) => r.status === "signed_in" && r.linkCreated)).toHaveLength(1);
    const [id] = ids;
    expect(await t.ik.oidc.listLinks(String(id))).toHaveLength(1);
  });
});

describe("oidc import", () => {
  it("rule: import is idempotent and keeps one subject on one account", async () => {
    const t = await oidcSetup();
    const a = await t.ik.accounts.create({ email: "a@example.org" });
    const b = await t.ik.accounts.create({ email: "b@example.org" });
    if (a.status !== "created" || b.status !== "created") throw new Error("no accounts");
    const objectId = guid();
    const input = {
      accountId: a.account.id,
      provider: "microsoft" as const,
      tenantId: TENANT,
      objectId: objectId.toUpperCase(),
    };
    const first = await t.ik.oidc.importLink(input);
    if (first.status !== "imported") throw new Error(first.status);
    expect(first.link).toMatchObject({ subject: objectId, tenantId: TENANT, source: "import" });
    expect(await t.ik.oidc.importLink(input)).toEqual({
      status: "already_linked",
      link: first.link,
    });
    expect(await t.ik.oidc.importLink({ ...input, accountId: b.account.id })).toEqual({
      status: "linked_elsewhere",
    });
    expect(
      await t.ik.oidc.importLink({ accountId: a.account.id, provider: "google", subject: "123" }),
    ).toEqual({ status: "account_has_link" });
    expect(
      await t.ik.oidc.importLink({ accountId: "missing", provider: "google", subject: "123" }),
    ).toEqual({ status: "no_account" });
    expect(t.audit.ofType("oidc.link_imported")).toHaveLength(1);
    expect(t.audit.ofType("oidc.link_imported")[0]).toMatchObject({
      accountId: a.account.id,
      provider: "microsoft",
    });
  });

  it("rule: an imported subject signs in to its account, whatever its token says of the address", async () => {
    const t = await oidcSetup();
    const legacy = await t.ik.accounts.create({ email: "legacy@example.org" });
    if (legacy.status !== "created") throw new Error("no account");
    await t.ik.oidc.importLink({
      accountId: legacy.account.id,
      provider: "google",
      subject: "google-sub-1",
    });
    const result = await t.signInWith(
      "google",
      googleClaims("changed@example.org", { sub: "google-sub-1", email_verified: false }),
    );
    if (result.status !== "signed_in") throw new Error(result.status);
    expect(result.account.id).toBe(legacy.account.id);
    expect(result.linkCreated).toBe(false);
  });

  it("rule: import refuses malformed input", async () => {
    const t = await oidcSetup();
    await expect(
      t.ik.oidc.importLink({
        accountId: "a",
        provider: "microsoft",
        tenantId: "not-a-guid",
        objectId: guid(),
      }),
    ).rejects.toBeInstanceOf(InvalidArgumentError);
    await expect(
      t.ik.oidc.importLink({
        accountId: "a",
        provider: "oidc",
        issuer: "http://x.example",
        subject: "s",
      }),
    ).rejects.toBeInstanceOf(InvalidArgumentError);
    await expect(
      t.ik.oidc.importLink({ accountId: "a", provider: "google", subject: "" }),
    ).rejects.toBeInstanceOf(InvalidArgumentError);
  });
});

const provider = () =>
  googleProvider({ clientId: "c", clientSecret: "s", redirectUri: REDIRECT_URI });

describe("oidc configuration", () => {
  const withOidc = { ...testConfig, oidc: testOidcConfig };

  it("rule: without the oidc option every call throws NotConfiguredError", async () => {
    const t = setup();
    await expect(t.ik.oidc.begin({ provider: "google" })).rejects.toBeInstanceOf(
      NotConfiguredError,
    );
    await expect(t.ik.oidc.listLinks("a")).rejects.toBeInstanceOf(NotConfiguredError);
  });

  it("rule: the oidc option needs the config section, a sealer and a store with links", () => {
    expect(() => setup({ oidc: { providers: [provider()] } })).toThrow(/config\.oidc/);
    const store = createMemoryStore();
    const { oidcLinks: _dropped, ...withoutLinks } = store;
    expect(() =>
      setup({ config: withOidc, store: withoutLinks, oidc: { providers: [provider()] } }),
    ).toThrow(/store\.oidcLinks/);
    expect(() =>
      setup({ config: withOidc, oidc: { providers: [provider(), provider()] } }),
    ).toThrow(/duplicate provider id/);
    expect(() =>
      setup({
        config: withOidc,
        oidc: { providers: [{ ...provider() }] },
      }),
    ).toThrow(InvalidArgumentError);
  });

  it("rule: provider factories refuse unsafe URLs and bad tenants", () => {
    expect(() =>
      googleProvider({ clientId: "c", clientSecret: "s", redirectUri: "http://portal.example/cb" }),
    ).toThrow(InvalidArgumentError);
    expect(() =>
      googleProvider({ clientId: "c", clientSecret: "s", redirectUri: "http://localhost:3000/cb" }),
    ).not.toThrow();
    expect(() =>
      googleProvider({ clientId: "c", clientSecret: "", redirectUri: REDIRECT_URI }),
    ).toThrow(InvalidArgumentError);
    expect(() =>
      googleProvider({
        clientId: "c",
        clientSecret: "s",
        redirectUri: REDIRECT_URI,
        scopes: ["email"],
      }),
    ).toThrow(/openid/);
  });

  it("rule: the provider object does not carry the client secret", () => {
    const p = googleProvider({
      clientId: "c",
      clientSecret: "very-secret-value",
      redirectUri: REDIRECT_URI,
    });
    expect(JSON.stringify(p)).not.toContain("very-secret-value");
    expect(Object.isFrozen(p)).toBe(true);
  });

  it("rule: begin refuses an unknown provider", async () => {
    const t = await oidcSetup();
    await expect(t.ik.oidc.begin({ provider: "nope" })).rejects.toBeInstanceOf(
      InvalidArgumentError,
    );
  });
});
