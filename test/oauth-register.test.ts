import { describe, expect, it } from "vitest";
import {
  InvalidArgumentError,
  OAuthClientRolledBackError,
  OperationRolledBackError,
} from "../src/index.js";
import { oauthSetup, registration } from "./oauth-helpers.js";

const CLIENT_ID = /^ikc_[A-Za-z0-9_-]{22}$/;
const CLIENT_SECRET = /^ikcs_[A-Za-z0-9_-]{43}$/;

describe("oauth dynamic client registration", () => {
  it("registers a confidential client by default and returns its secret once", async () => {
    const { ik, store, clock, audit } = oauthSetup();
    const result = await ik.oauth.register({
      body: registration({ redirect_uris: ["https://app.example.com/cb"] }),
      addressKey: "203.0.113.7",
    });
    expect(result.httpStatus).toBe(201);
    expect(result.headers).toMatchObject({ "Cache-Control": "no-store", Pragma: "no-cache" });
    const body = result.body ?? {};
    expect(body).toEqual({
      client_id: expect.stringMatching(CLIENT_ID),
      client_id_issued_at: Math.floor(clock.now().getTime() / 1000),
      client_secret: expect.stringMatching(CLIENT_SECRET),
      client_secret_expires_at: 0,
      redirect_uris: ["https://app.example.com/cb"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic",
      client_name: "Example client",
    });
    const clientId = String(body["client_id"]);
    const stored = await store.oauth?.findClient(clientId);
    // Only a keyed digest is stored, never the secret.
    expect(stored?.secretDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(stored)).not.toContain(String(body["client_secret"]));
    expect(audit.ofType("oauth.client_registered")).toEqual([
      expect.objectContaining({ clientId, method: "client_secret_basic" }),
    ]);
    expect(await ik.oauth.getClient(clientId)).toEqual({
      id: clientId,
      name: "Example client",
      redirectUris: ["https://app.example.com/cb"],
      grantTypes: ["authorization_code"],
      authMethod: "client_secret_basic",
      source: "dynamic",
      createdAt: clock.now(),
      lastUsedAt: null,
      legacyDigest: false,
    });
  });

  it("registers a public client without a secret, with the grant types it names", async () => {
    const { ik } = oauthSetup();
    const result = await ik.oauth.register({
      body: registration({
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        client_name: undefined,
      }),
    });
    expect(result.httpStatus).toBe(201);
    expect(result.body).not.toHaveProperty("client_secret");
    expect(result.body).not.toHaveProperty("client_name");
    expect(result.body?.["grant_types"]).toEqual(["authorization_code", "refresh_token"]);
    expect(result.body?.["token_endpoint_auth_method"]).toBe("none");
  });

  const refused: [string, string, string][] = [
    ["invalid JSON", "{", "invalid_client_metadata"],
    ["a JSON array", "[]", "invalid_client_metadata"],
    ["no redirect URIs", JSON.stringify({}), "invalid_redirect_uri"],
    ["an empty list", registration({ redirect_uris: [] }), "invalid_redirect_uri"],
    [
      "six redirect URIs",
      registration({
        redirect_uris: Array.from({ length: 6 }, (_, i) => `https://e.example.com/${i}`),
      }),
      "invalid_redirect_uri",
    ],
    [
      "a repeated redirect URI",
      registration({ redirect_uris: ["https://e.example.com/a", "https://e.example.com/a"] }),
      "invalid_redirect_uri",
    ],
    [
      "a redirect URI that is no string",
      registration({ redirect_uris: [5] }),
      "invalid_redirect_uri",
    ],
    [
      "an unknown auth method",
      registration({ token_endpoint_auth_method: "private_key_jwt" }),
      "invalid_client_metadata",
    ],
    ["the implicit grant", registration({ grant_types: ["implicit"] }), "invalid_client_metadata"],
    [
      "only refresh_token",
      registration({ grant_types: ["refresh_token"] }),
      "invalid_client_metadata",
    ],
    [
      "a token response type",
      registration({ response_types: ["token"] }),
      "invalid_client_metadata",
    ],
    ["a name that is no string", registration({ client_name: 5 }), "invalid_client_metadata"],
  ];
  it.each(refused)("refuses %s", async (_, body, error) => {
    const { ik, store } = oauthSetup();
    const result = await ik.oauth.register({ body });
    expect(result.httpStatus).toBe(400);
    expect(result.body).toEqual({ error, error_description: expect.any(String) });
    // An invalid request reserves no registration.
    expect(
      await store.oauth?.reserveRegistration({
        keys: [{ key: "deployment", max: 1 }],
        windowStart: new Date("2030-01-01T00:00:00.000Z"),
      }),
    ).toBe("reserved");
  });

  it("refuses a body above maxBodyBytes, counted in UTF-8 bytes", async () => {
    const { ik } = oauthSetup({ oauth: { registration: { maxBodyBytes: 1024 } } });
    const body = registration({ client_name: "ä".repeat(500) });
    // Below the cap in characters, above it in bytes.
    expect(body.length).toBeLessThan(1024);
    const result = await ik.oauth.register({ body });
    expect(result.httpStatus).toBe(400);
    expect(result.body?.["error"]).toBe("invalid_client_metadata");
  });

  it("refuses an auth method that the operator did not allow", async () => {
    const { ik } = oauthSetup({
      oauth: { registration: { allowedAuthMethods: ["none"], defaultAuthMethod: "none" } },
    });
    const basic = await ik.oauth.register({
      body: registration({ token_endpoint_auth_method: "client_secret_basic" }),
    });
    expect(basic.body?.["error"]).toBe("invalid_client_metadata");
    expect((await ik.oauth.register({ body: registration() })).httpStatus).toBe(201);
  });

  it("throws InvalidArgumentError for a call of the wrong shape", async () => {
    const { ik } = oauthSetup();
    await expect(ik.oauth.register({ body: 5 } as never)).rejects.toThrow(InvalidArgumentError);
    await expect(ik.oauth.register({ body: "{}", addressKey: "" })).rejects.toThrow(
      InvalidArgumentError,
    );
  });

  it("deletes the client again if the sink refuses its event", async () => {
    const { ik, store, audit } = oauthSetup();
    const emit = audit.emit.bind(audit);
    audit.emit = (event) => {
      if (event.type === "oauth.client_registered") throw new Error("sink down");
      return emit(event);
    };
    let clientId = "";
    const oauthStore = store.oauth;
    if (!oauthStore) throw new Error("no oauth store");
    const insert = oauthStore.insertClient.bind(oauthStore);
    oauthStore.insertClient = async (client) => {
      clientId = client.id;
      return insert(client);
    };
    const thrown: unknown = await ik.oauth.register({ body: registration() }).catch((e) => e);
    expect(thrown).toBeInstanceOf(OAuthClientRolledBackError);
    expect(thrown).not.toBeInstanceOf(OperationRolledBackError);
    expect(thrown).toMatchObject({
      code: "oauth_client_rolled_back",
      clientId: expect.stringMatching(/^ikc_/),
      cause: new Error("sink down"),
    });
    expect((thrown as OAuthClientRolledBackError).clientId).toBe(clientId);
    expect(clientId).not.toBe("");
    expect(await ik.oauth.getClient(clientId)).toBeNull();
  });

  it("deletes a client administratively and records it", async () => {
    const { ik, audit } = oauthSetup();
    const result = await ik.oauth.register({ body: registration() });
    const clientId = String(result.body?.["client_id"]);
    expect(await ik.oauth.deleteClient(clientId)).toBe(true);
    expect(await ik.oauth.deleteClient(clientId)).toBe(false);
    expect(await ik.oauth.getClient(clientId)).toBeNull();
    expect(audit.ofType("oauth.client_deleted")).toEqual([
      expect.objectContaining({ clientId, reason: "administrative" }),
    ]);
  });
});
