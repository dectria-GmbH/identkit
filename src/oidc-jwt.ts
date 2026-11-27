import { fromBase64Url, utf8, type WebCryptoKey } from "./bytes.js";

/** Signature algorithms identkit accepts for ID tokens. No `none`, no shared-secret HMAC. */
export type IdTokenAlgorithm = "RS256" | "ES256";

export const ID_TOKEN_ALGORITHMS: readonly IdTokenAlgorithm[] = ["RS256", "ES256"];

/** Upper bound for an ID token. Real ones have a few kilobytes. */
const MAX_TOKEN_LENGTH = 16_384;

/** Least RSA modulus, in bytes (2048 bits). */
const MIN_RSA_MODULUS_BYTES = 256;

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** The ASCII bytes of `<header>.<payload>`, which the signature covers. */
  signingInput: Uint8Array<ArrayBuffer>;
  signature: Uint8Array<ArrayBuffer>;
}

/** True for a plain JSON object (not null, not an array). */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function jsonObject(bytes: Uint8Array | null): Record<string, unknown> | null {
  if (!bytes) return null;
  try {
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return isRecord(value) ? value : null;
  } catch {
    return null;
  }
}

/** Splits and decodes a compact JWS. Returns null for anything that is not one. */
export function decodeJwt(token: string): DecodedJwt | null {
  if (typeof token !== "string" || token.length > MAX_TOKEN_LENGTH) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h = "", p = "", s = ""] = parts;
  const header = jsonObject(fromBase64Url(h));
  const payload = jsonObject(fromBase64Url(p));
  const signature = fromBase64Url(s);
  if (!header || !payload || !signature || signature.byteLength === 0) return null;
  return { header, payload, signingInput: utf8(`${h}.${p}`), signature };
}

/** Checks the signature of a decoded JWS with a key imported by `importJwk`. */
export async function verifyJwtSignature(
  alg: IdTokenAlgorithm,
  key: WebCryptoKey,
  jwt: DecodedJwt,
): Promise<boolean> {
  try {
    if (alg === "RS256") {
      return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, jwt.signature, jwt.signingInput);
    }
    // JWS carries an ECDSA signature as r || s, the form Web Crypto expects.
    if (jwt.signature.byteLength !== 64) return false;
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      jwt.signature,
      jwt.signingInput,
    );
  } catch {
    return false;
  }
}

export interface VerificationKey {
  kid: string | null;
  alg: IdTokenAlgorithm;
  key: WebCryptoKey;
}

const str = (value: unknown): string | null => (typeof value === "string" ? value : null);

/**
 * Imports one entry of a JWKS as a verification key, or returns null if it is not a signing key
 * of an accepted algorithm. Only the key material is passed to Web Crypto, never other members.
 */
export async function importJwk(jwk: unknown): Promise<VerificationKey | null> {
  if (!isRecord(jwk)) return null;
  const entry = jwk;
  if (entry["use"] !== undefined && entry["use"] !== "sig") return null;
  const ops = entry["key_ops"];
  if (ops !== undefined && !(Array.isArray(ops) && ops.includes("verify"))) return null;
  const kid = entry["kid"] === undefined ? null : str(entry["kid"]);
  if (entry["kid"] !== undefined && kid === null) return null;
  const declared = entry["alg"];
  try {
    if (entry["kty"] === "RSA" && (declared === undefined || declared === "RS256")) {
      const n = str(entry["n"]);
      const e = str(entry["e"]);
      const modulus = n === null ? null : fromBase64Url(n);
      if (!n || !e || !modulus) return null;
      // A leading zero byte does not count towards the modulus length.
      const length = modulus[0] === 0 ? modulus.byteLength - 1 : modulus.byteLength;
      if (length < MIN_RSA_MODULUS_BYTES) return null;
      const key = await crypto.subtle.importKey(
        "jwk",
        { kty: "RSA", n, e },
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );
      return { kid, alg: "RS256", key };
    }
    if (
      entry["kty"] === "EC" &&
      entry["crv"] === "P-256" &&
      (declared === undefined || declared === "ES256")
    ) {
      const x = str(entry["x"]);
      const y = str(entry["y"]);
      if (!x || !y) return null;
      const key = await crypto.subtle.importKey(
        "jwk",
        { kty: "EC", crv: "P-256", x, y },
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      return { kid, alg: "ES256", key };
    }
  } catch {
    return null;
  }
  return null;
}
