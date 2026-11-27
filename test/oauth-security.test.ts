/**
 * The security review list of the OAuth server: one `it` per row, named by its number. Each test
 * fails when the defence of its row is turned off at its call site.
 */
import { describe, expect, it } from "vitest";
import { createOAuthTestClient, createPkcePair } from "../src/testing/index.js";
import { ISSUER, oauthSetup, registration } from "./oauth-helpers.js";

/** An authorization request of a test client, with changes. */
async function authorizeParams(clientId: string, overrides: Record<string, string> = {}) {
  const { challenge } = await createPkcePair();
  return new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: "http://127.0.0.1/callback",
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "st",
    ...overrides,
  });
}

/** A setup with a public test client and an account. */
async function connected(setupOptions: Parameters<typeof oauthSetup>[0] = {}) {
  const setup = oauthSetup(setupOptions);
  const client = await createOAuthTestClient(setup.ik.oauth);
  const accountId = await setup.account();
  return { ...setup, client, accountId };
}

/** Registers a client with these redirect URIs and returns the result. */
async function registerWith(
  ik: ReturnType<typeof oauthSetup>["ik"],
  redirectUris: unknown[],
  addressKey?: string,
) {
  return ik.oauth.register({
    body: registration({ redirect_uris: redirectUris }),
    ...(addressKey === undefined ? {} : { addressKey }),
  });
}

describe("oauth security review list", () => {
  it("row 6: authorization errors never redirect", async () => {
    const { ik, client, accountId } = await connected();
    const cases = [
      { client_id: "ikc_unknownunknownunknown" },
      { redirect_uri: "https://evil.example/cb" },
      { response_type: "token" },
      { code_challenge_method: "plain" },
      { resource: "https://evil.example/mcp" },
    ];
    for (const overrides of cases) {
      const begun = await ik.oauth.authorize.begin({
        params: await authorizeParams(client.clientId, overrides),
        accountId,
      });
      expect(begun.status).toBe("invalid");
      expect(begun).not.toHaveProperty("location");
      expect(JSON.stringify(begun)).not.toContain("evil.example");
    }
  });

  it("row 7: redirect URI tricks at registration are refused", async () => {
    const { ik } = oauthSetup();
    const refused = [
      "https://exаmple.com/cb", // Cyrillic a
      "https://xn--exmple-cua.com/cb\u0000",
      "https://example.com@evil.example/cb",
      "https://user:pass@example.com/cb",
      "https://example.com/cb#x",
      "https://example.com/cb#",
      "http://example.com/cb",
      "http://127.0.0.1.evil.example/cb",
      "http://localhost.evil.example/cb",
      "http://[::1]/cb",
      "http://2130706433/cb",
      "http://0x7f.0.0.1/cb",
      "javascript:alert(1)",
      "data:text/html,hello",
      "file:///etc/passwd",
      "com.example.app:/cb",
      "https://example.com/a/../b",
      "https://example.com/a/./b",
      "https://EXAMPLE.com/cb",
      "HTTPS://example.com/cb",
      "https://example.com:443/cb",
      "http://127.0.0.1:80/cb",
      "https://ex%61mple.com/cb",
      "https://example.com/c b",
      "https://example.com/cb\n",
      " https://example.com/cb",
      "https://example.com\\@evil.example/cb",
      "https://example.com./cb",
      "https:///cb",
      "https://",
      "//example.com/cb",
      "/cb",
      "cb",
      "",
      `https://example.com/${"a".repeat(512)}`,
      "https://exa_mple.com/cb",
      "https://exämple.com/cb",
      "https://[2001:db8::1]/cb",
    ];
    for (const uri of refused) {
      const result = await registerWith(ik, [uri]);
      expect({ uri, status: result.httpStatus, error: result.body?.["error"] }).toEqual({
        uri,
        status: 400,
        error: "invalid_redirect_uri",
      });
    }
    const accepted = [
      "https://example.com/cb",
      "https://example.com",
      "https://example.com/cb?tenant=a",
      "https://app.example.com:8443/oauth/callback",
      "http://127.0.0.1/cb",
      "http://127.0.0.1:33418/callback",
      "http://localhost:5000/cb",
    ];
    for (const uri of accepted) {
      expect({ uri, status: (await registerWith(ik, [uri])).httpStatus }).toEqual({
        uri,
        status: 201,
      });
    }
    // The IPv6 loopback and private-use schemes only when the operator allows them.
    const open = oauthSetup({
      oauth: { redirectUris: { allowIpv6Loopback: true, allowPrivateUseSchemes: true } },
    }).ik;
    expect((await registerWith(open, ["http://[::1]:7000/cb"])).httpStatus).toBe(201);
    expect((await registerWith(open, ["com.example.app:/cb"])).httpStatus).toBe(201);
    expect((await registerWith(open, ["javascript:alert(1)"])).httpStatus).toBe(400);
  });

  it("row 8: a loopback redirect URI ignores only the port; host, scheme, path and query must match", async () => {
    const { ik, client, accountId } = await connected();
    // Registered: http://127.0.0.1/callback
    const status = async (redirectUri: string) =>
      (
        await ik.oauth.authorize.begin({
          params: await authorizeParams(client.clientId, { redirect_uri: redirectUri }),
          accountId,
        })
      ).status;
    expect(await status("http://127.0.0.1/callback")).toBe("consent");
    expect(await status("http://127.0.0.1:5000/callback")).toBe("consent");
    expect(await status("http://127.0.0.1:65535/callback")).toBe("consent");
    expect(await status("http://localhost:5000/callback")).toBe("invalid");
    expect(await status("http://localhost/callback")).toBe("invalid");
    expect(await status("http://127.0.0.1:5000/callback?x=1")).toBe("invalid");
    expect(await status("http://127.0.0.1:5000/callback/")).toBe("invalid");
    expect(await status("http://127.0.0.1:5000/Callback")).toBe("invalid");
    expect(await status("https://127.0.0.1:5000/callback")).toBe("invalid");
    expect(await status("http://127.0.0.1:5000/callback#x")).toBe("invalid");
    expect(await status("http://127.0.0.2:5000/callback")).toBe("invalid");
    // A port written on a non-loopback registration must match exactly.
    const web = await createOAuthTestClient(ik.oauth, {
      redirectUri: "https://app.example.com:8443/cb",
    });
    const webStatus = async (redirectUri: string) =>
      (
        await ik.oauth.authorize.begin({
          params: await authorizeParams(web.clientId, { redirect_uri: redirectUri }),
          accountId,
        })
      ).status;
    expect(await webStatus("https://app.example.com:8443/cb")).toBe("consent");
    expect(await webStatus("https://app.example.com:9443/cb")).toBe("invalid");
    expect(await webStatus("https://app.example.com/cb")).toBe("invalid");
  });

  it("row 9: every authorization response carries the static issuer as iss", async () => {
    const { ik, client, accountId } = await connected();
    expect(ik.oauth.metadata.authorizationServer()).toMatchObject({
      issuer: ISSUER,
      authorization_response_iss_parameter_supported: true,
    });
    const approvedFlow = await client.authorize(accountId);
    expect(approvedFlow.location.searchParams.get("iss")).toBe(ISSUER);
    const begun = await ik.oauth.authorize.begin({
      params: await authorizeParams(client.clientId),
      accountId,
    });
    if (begun.status !== "consent") throw new Error(begun.status);
    const denied = await ik.oauth.authorize.deny({ ticket: begun.ticket, accountId });
    if (denied.status !== "redirect") throw new Error(denied.status);
    expect(new URL(denied.location).searchParams.get("iss")).toBe(ISSUER);
  });

  it("row 14: registrations per address and per day are capped, the address first", async () => {
    const { ik, audit } = oauthSetup({
      oauth: { registration: { maxPerAddressPerDay: 3, maxPerDay: 5 } },
    });
    for (let i = 0; i < 3; i += 1) {
      expect((await registerWith(ik, ["http://127.0.0.1/cb"], "198.51.100.1")).httpStatus).toBe(
        201,
      );
    }
    const blocked = await registerWith(ik, ["http://127.0.0.1/cb"], "198.51.100.1");
    expect(blocked.httpStatus).toBe(429);
    expect(blocked.body?.["error"]).toBe("temporarily_unavailable");
    expect(Number(blocked.headers["Retry-After"])).toBeGreaterThan(0);
    // The refused address used none of the deployment's registrations.
    expect((await registerWith(ik, ["http://127.0.0.1/cb"], "198.51.100.2")).httpStatus).toBe(201);
    expect((await registerWith(ik, ["http://127.0.0.1/cb"])).httpStatus).toBe(201);
    const daily = await registerWith(ik, ["http://127.0.0.1/cb"], "198.51.100.3");
    expect(daily.httpStatus).toBe(429);
    const refusals = audit.ofType("oauth.registration_refused");
    expect(refusals.map((e) => e.reason)).toEqual(["address_limit", "daily_limit"]);
    // A keyed digest of the address key, never the key itself.
    expect(refusals[0]?.addressDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(audit.events)).not.toContain("198.51.100");
  });

  it("row 21: a consent ticket works only for its own account and only unchanged", async () => {
    const { ik, client, accountId, account } = await connected();
    const begun = await ik.oauth.authorize.begin({
      params: await authorizeParams(client.clientId),
      accountId,
    });
    if (begun.status !== "consent") throw new Error(begun.status);
    const attacker = await account();
    for (const decide of [
      (input: { ticket: string; accountId: string }) => ik.oauth.authorize.approve(input),
      (input: { ticket: string; accountId: string }) => ik.oauth.authorize.deny(input),
    ]) {
      expect(await decide({ ticket: begun.ticket, accountId: attacker })).toMatchObject({
        status: "invalid",
        error: "account_mismatch",
      });
    }
    const parts = begun.ticket.split(".");
    const body = parts[3] ?? "";
    const flipped = `${body.slice(0, -2)}${body.at(-2) === "A" ? "B" : "A"}${body.at(-1)}`;
    const tampered = [...parts.slice(0, 3), flipped, ...parts.slice(4)].join(".");
    expect(await ik.oauth.authorize.approve({ ticket: tampered, accountId })).toMatchObject({
      status: "invalid",
      error: "invalid_ticket",
    });
    expect(
      await ik.oauth.authorize.approve({ ticket: begun.ticket.slice(0, -1), accountId }),
    ).toMatchObject({ status: "invalid", error: "invalid_ticket" });
    // The untouched ticket still works for its account.
    expect((await ik.oauth.authorize.approve({ ticket: begun.ticket, accountId })).status).toBe(
      "redirect",
    );
  });

  it("row 22: a value sealed for another purpose never opens as a consent ticket", async () => {
    const { ik, client, accountId, sealer } = await connected();
    const begun = await ik.oauth.authorize.begin({
      params: await authorizeParams(client.clientId),
      accountId,
    });
    if (begun.status !== "consent") throw new Error(begun.status);
    // The same content, sealed with the same key for the OIDC transaction context.
    const content = await sealer.open(begun.ticket, "identkit/oauth/consent/v1");
    const foreign = await sealer.seal(content, "identkit/oidc/transaction/v1");
    for (const decide of [
      (input: { ticket: string; accountId: string }) => ik.oauth.authorize.approve(input),
      (input: { ticket: string; accountId: string }) => ik.oauth.authorize.deny(input),
    ]) {
      expect(await decide({ ticket: foreign, accountId })).toMatchObject({
        status: "invalid",
        error: "invalid_ticket",
      });
    }
  });

  it("row 26: a hostile client_name loses control, bidi and separator characters and is cut at 100", async () => {
    const { ik, audit } = oauthSetup();
    const hostile = `‮evil​\u0007${"x".repeat(200)} `;
    const result = await ik.oauth.register({ body: registration({ client_name: hostile }) });
    const name = String(result.body?.["client_name"]);
    expect(name).toBe(`evil${"x".repeat(96)}`);
    expect(Array.from(name)).toHaveLength(100);
    const view = await ik.oauth.getClient(String(result.body?.["client_id"]));
    expect(view?.name).toBe(name);
    // A name of nothing visible is no name.
    const blank = await ik.oauth.register({ body: registration({ client_name: "‮ ㅤ" }) });
    expect(blank.body).not.toHaveProperty("client_name");
    // The name never reaches an audit event.
    expect(JSON.stringify(audit.events)).not.toContain("evil");
  });
});
