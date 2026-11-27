/**
 * The security review list of the OAuth server: one `it` per row, named by its number. Each test
 * fails when the defence of its row is turned off at its call site.
 */
import { describe, expect, it } from "vitest";
import { oauthSetup, registration } from "./oauth-helpers.js";

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
