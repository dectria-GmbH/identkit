import { describe, expect, it } from "vitest";
import { fromBase64Url, toBase64Url } from "../src/bytes.js";
import { providerFetch, ProviderRequestError, readJson, type OidcFetch } from "../src/oidc-jwks.js";
import { importJwk } from "../src/oidc-jwt.js";

async function rsaJwk(): Promise<{ kty: string; n: string; e: string }> {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  if (!jwk.n || !jwk.e) throw new Error("no key");
  return { kty: "RSA", n: jwk.n, e: jwk.e };
}

/** A body stream without content-length, as a chunked response sends it. */
function streamed(text: string): Response {
  const bytes = new TextEncoder().encode(text);
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (let i = 0; i < bytes.length; i += 1000) controller.enqueue(bytes.slice(i, i + 1000));
      controller.close();
    },
  });
  return new Response(body, { status: 200 });
}

describe("oidc provider requests", () => {
  it("rule: no redirects - a redirect from a provider fails and is never followed", async () => {
    const seen: RequestInit[] = [];
    const fetcher: OidcFetch = async (_url, init) => {
      seen.push(init);
      return new Response(null, {
        status: 307,
        headers: { location: "https://elsewhere.example/token" },
      });
    };
    const error = await providerFetch(
      fetcher,
      "https://idp.example/token",
      { method: "POST", body: "client_secret=s" },
      1000,
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ProviderRequestError);
    expect((error as ProviderRequestError).reason).toBe("redirect refused");
    expect(seen).toHaveLength(1);
    expect(seen[0]?.redirect).toBe("manual");
  });

  it("rule: the size limit counts bytes, also without content-length", async () => {
    // 200 characters, 600 bytes in UTF-8.
    const wide = JSON.stringify({ v: "€".repeat(200) });
    await expect(readJson(streamed(wide), 300)).rejects.toThrow("response too large");
    expect((await readJson(streamed(wide), 1000)).body).toEqual({ v: "€".repeat(200) });
    await expect(readJson(streamed(JSON.stringify({ v: "x".repeat(5000) })), 1000)).rejects.toThrow(
      "response too large",
    );
  });
});

describe("oidc key import", () => {
  it("rule: an RSA key needs the exponent 65537 and at least 2048 bits", async () => {
    const jwk = await rsaJwk();
    expect(await importJwk(jwk)).not.toBeNull();
    // e = 1 and e = 3.
    expect(await importJwk({ ...jwk, e: toBase64Url(new Uint8Array([1])) })).toBeNull();
    expect(await importJwk({ ...jwk, e: toBase64Url(new Uint8Array([3])) })).toBeNull();
    // 256 bytes, but the top byte is 0x01: 2041 bits.
    const n = fromBase64Url(jwk.n);
    if (!n) throw new Error("no modulus");
    const short = Uint8Array.from(n);
    short[0] = 1;
    expect(await importJwk({ ...jwk, n: toBase64Url(short) })).toBeNull();
    // A leading zero byte does not count.
    expect(await importJwk({ ...jwk, n: toBase64Url(Uint8Array.of(0, ...n)) })).not.toBeNull();
  });
});
