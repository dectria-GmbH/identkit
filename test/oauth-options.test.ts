import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createHmacHasher,
  createIdentkit,
  createMemoryStore,
  InvalidArgumentError,
  NotConfiguredError,
  type OAuthOptions,
} from "../src/index.js";
import {
  createFakeClock,
  createRecordingAuditSink,
  createRecordingMailSender,
  createTestSealer,
} from "../src/testing/index.js";
import { emailFirstPolicy, testConfig } from "./helpers.js";
import { baseOAuthOptions, ISSUER, oauthSetup, RESOURCE } from "./oauth-helpers.js";

function build(options: {
  oauth?: unknown;
  sealer?: boolean;
  store?: ReturnType<typeof createMemoryStore>;
  apiTokens?: { prefix: string; allowedScopes: string[] };
}) {
  return createIdentkit({
    config: testConfig,
    policy: emailFirstPolicy,
    isPrivilegedAccount: () => false,
    store: options.store ?? createMemoryStore(),
    hasher: createHmacHasher(new Uint8Array(randomBytes(32))),
    ...(options.sealer === false ? {} : { sealer: createTestSealer() }),
    mail: createRecordingMailSender(),
    audit: createRecordingAuditSink(),
    clock: createFakeClock(),
    // Untyped on purpose: the tests pass invalid options.
    ...(options.oauth === undefined ? {} : { oauth: options.oauth as OAuthOptions }),
    ...(options.apiTokens ? { apiTokens: options.apiTokens } : {}),
  });
}

describe("oauth options", () => {
  it("without the option, every call throws NotConfiguredError", async () => {
    const ik = build({});
    expect(() => ik.oauth.metadata.authorizationServer()).toThrow(NotConfiguredError);
    expect(() => ik.oauth.wwwAuthenticate({ tokenPresented: false })).toThrow(NotConfiguredError);
    await expect(ik.oauth.register({ body: "{}" })).rejects.toThrow(NotConfiguredError);
    await expect(ik.oauth.getClient("x")).rejects.toThrow(NotConfiguredError);
  });

  it("needs a sealer and a store with oauth, checked at construction", () => {
    expect(() => build({ oauth: baseOAuthOptions, sealer: false })).toThrow(
      new NotConfiguredError("sealer"),
    );
    const { oauth: _omitted, ...withoutOAuth } = createMemoryStore();
    expect(() =>
      build({
        oauth: baseOAuthOptions,
        store: withoutOAuth,
      }),
    ).toThrow(new NotConfiguredError("store.oauth"));
  });

  const invalid: [string, Partial<Record<keyof OAuthOptions, unknown>>, RegExp][] = [
    ["http issuer off loopback", { issuer: "http://example.com" }, /issuer must use https/],
    [
      "issuer with a trailing slash",
      { issuer: "https://example.com/" },
      /issuer must be in normalized/,
    ],
    ["issuer with a query", { issuer: "https://example.com?x=1" }, /issuer must have no query/],
    ["issuer with a fragment", { issuer: "https://example.com#x" }, /issuer must have no fragment/],
    ["issuer in upper case", { issuer: "https://EXAMPLE.com" }, /issuer must be in normalized/],
    ["no resource", { resources: [] }, /resources/],
    ["a repeated resource", { resources: [RESOURCE, RESOURCE] }, /must not repeat/],
    [
      "nine resources",
      { resources: Array.from({ length: 9 }, (_, i) => `${ISSUER}/r${i}`) },
      /resources/,
    ],
    ["no default scope", { defaultScopes: [] }, /defaultScopes/],
    ["a scope with a quote", { defaultScopes: ['mcp:"read'] }, /scope must be visible ASCII/],
    ["a scope with a space", { defaultScopes: ["mcp read"] }, /scope must be visible ASCII/],
    [
      "an opt-in scope that is a default",
      { optInScopes: ["mcp:read"] },
      /must not repeat a default/,
    ],
    [
      "a short grant",
      { grantSeconds: 3600, refreshTokenSeconds: 7200 },
      /grantSeconds must be at least/,
    ],
    ["a long access token", { accessTokenSeconds: 86_401 }, /accessTokenSeconds/],
    ["a grace above 120", { refreshRaceGraceSeconds: 121 }, /refreshRaceGraceSeconds/],
    [
      "a default method that is not allowed",
      { registration: { defaultAuthMethod: "client_secret_post", allowedAuthMethods: ["none"] } },
      /defaultAuthMethod must be one of/,
    ],
    ["overlapping prefixes", { prefixes: { accessToken: "ikc_x" } }, /prefixes must differ/],
    ["equal prefixes", { prefixes: { code: "ikat_" } }, /prefixes must differ/],
    [
      "an endpoint on another origin",
      { endpoints: { token: "https://other.example/t" } },
      /endpoints.token must be on/,
    ],
    ["an unknown option", { unknown: true } as never, /Unrecognized key/],
    ["a non-function admit", { admit: true }, /admit must be a function/],
    ["a realm with a quote", { basicRealm: 'a"b' }, /basicRealm/],
  ];
  it.each(invalid)("refuses %s with InvalidArgumentError", (_, change, message) => {
    expect(() => build({ oauth: { ...baseOAuthOptions, ...change } })).toThrow(
      InvalidArgumentError,
    );
    expect(() => build({ oauth: { ...baseOAuthOptions, ...change } })).toThrow(message);
  });

  it("refuses a prefix that overlaps the API token prefix, both ways", () => {
    const apiTokens = { prefix: "ika", allowedScopes: ["read"] };
    expect(() => build({ oauth: baseOAuthOptions, apiTokens })).toThrow(
      /prefixes must not overlap apiTokens.prefix/,
    );
    expect(() =>
      build({
        oauth: baseOAuthOptions,
        apiTokens: { prefix: "ikat_extra", allowedScopes: ["read"] },
      }),
    ).toThrow(InvalidArgumentError);
    expect(() =>
      build({ oauth: baseOAuthOptions, apiTokens: { prefix: "pat_", allowedScopes: ["read"] } }),
    ).not.toThrow();
  });

  it("accepts http on loopback for development", () => {
    expect(() =>
      build({
        oauth: {
          ...baseOAuthOptions,
          issuer: "http://localhost:8787",
          resources: ["http://localhost:8787/mcp"],
        },
      }),
    ).not.toThrow();
  });
});

describe("oauth metadata", () => {
  it("serves the authorization server document with the defaults", () => {
    const { ik } = oauthSetup();
    expect(ik.oauth.metadata.authorizationServer()).toEqual({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/oauth/authorize`,
      token_endpoint: `${ISSUER}/oauth/token`,
      registration_endpoint: `${ISSUER}/oauth/register`,
      revocation_endpoint: `${ISSUER}/oauth/revoke`,
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
      revocation_endpoint_auth_methods_supported: [
        "none",
        "client_secret_basic",
        "client_secret_post",
      ],
      scopes_supported: ["mcp:read", "mcp:events"],
      authorization_response_iss_parameter_supported: true,
    });
    expect(ik.oauth.metadata.authorizationServerPath()).toBe(
      "/.well-known/oauth-authorization-server",
    );
  });

  it("puts an issuer path after the well-known name, and leaves registration out when it is off", async () => {
    const { ik } = oauthSetup({
      oauth: {
        issuer: "https://example.com/tenant",
        resources: ["https://example.com/tenant/mcp"],
        endpoints: { register: null, token: "https://example.com/t" },
      },
    });
    const doc = ik.oauth.metadata.authorizationServer();
    expect(doc).not.toHaveProperty("registration_endpoint");
    expect(doc["token_endpoint"]).toBe("https://example.com/t");
    expect(ik.oauth.metadata.authorizationServerPath()).toBe(
      "/.well-known/oauth-authorization-server/tenant",
    );
    await expect(ik.oauth.register({ body: "{}" })).rejects.toThrow(NotConfiguredError);
  });

  it("serves a protected resource document per resource", () => {
    const { ik } = oauthSetup();
    expect(ik.oauth.metadata.protectedResource()).toEqual({
      resource: RESOURCE,
      authorization_servers: [ISSUER],
      scopes_supported: ["mcp:read", "mcp:events"],
      bearer_methods_supported: ["header"],
      resource_name: "Example",
    });
    expect(ik.oauth.metadata.protectedResource(ISSUER)["resource"]).toBe(ISSUER);
    expect(ik.oauth.metadata.protectedResourcePath()).toBe(
      "/.well-known/oauth-protected-resource/mcp",
    );
    expect(ik.oauth.metadata.protectedResourcePath(ISSUER)).toBe(
      "/.well-known/oauth-protected-resource",
    );
    expect(() => ik.oauth.metadata.protectedResource("https://other.example")).toThrow(
      InvalidArgumentError,
    );
  });

  it("builds WWW-Authenticate for a missing, a refused and an underprivileged token", () => {
    const { ik } = oauthSetup();
    const metadata = `resource_metadata="${ISSUER}/.well-known/oauth-protected-resource/mcp"`;
    expect(ik.oauth.wwwAuthenticate({ tokenPresented: false })).toBe(
      `Bearer ${metadata}, scope="mcp:read"`,
    );
    expect(ik.oauth.wwwAuthenticate({ tokenPresented: true })).toBe(
      `Bearer ${metadata}, scope="mcp:read", error="invalid_token"`,
    );
    expect(
      ik.oauth.wwwAuthenticate({
        tokenPresented: true,
        error: "insufficient_scope",
        scope: ["mcp:read", "mcp:events"],
      }),
    ).toBe(`Bearer ${metadata}, scope="mcp:read mcp:events", error="insufficient_scope"`);
    expect(() => ik.oauth.wwwAuthenticate({ tokenPresented: true, scope: ['a"b'] })).toThrow(
      InvalidArgumentError,
    );
  });
});
