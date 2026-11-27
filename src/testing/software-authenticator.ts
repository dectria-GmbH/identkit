import { concatBytes, fromBase64Url, randomBytes, toBase64Url, utf8 } from "../bytes.js";
import { nodeCrypto, type NodeCrypto, type NodeKeyObject } from "../node-crypto.js";
import type {
  AuthenticationResponseJSON,
  PasskeyCreationOptions,
  PasskeyRequestOptions,
  RegistrationResponseJSON,
} from "../webauthn.js";

/** Minimal CBOR encoder for the shapes WebAuthn uses: integers, byte and text strings, maps. */
type CborValue = number | string | Uint8Array | Map<CborValue, CborValue>;

function head(major: number, length: number): Uint8Array {
  if (length < 24) return Uint8Array.of((major << 5) | length);
  if (length < 0x100) return Uint8Array.of((major << 5) | 24, length);
  if (length < 0x10000) return Uint8Array.of((major << 5) | 25, length >>> 8, length & 0xff);
  const b = new Uint8Array(5);
  b[0] = (major << 5) | 26;
  new DataView(b.buffer).setUint32(1, length);
  return b;
}

function encodeCbor(value: CborValue): Uint8Array {
  if (typeof value === "number") {
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  }
  if (typeof value === "string") {
    const bytes = utf8(value);
    return concatBytes(head(3, bytes.byteLength), bytes);
  }
  if (value instanceof Uint8Array) {
    return concatBytes(head(2, value.byteLength), value);
  }
  const parts: Uint8Array[] = [head(5, value.size)];
  for (const [k, v] of value) parts.push(encodeCbor(k), encodeCbor(v));
  return concatBytes(...parts);
}

const sha256 = (node: NodeCrypto, data: Uint8Array | string) =>
  node.createHash("sha256").update(data).digest();

function clientData(type: string, challenge: string, origin: string, crossOrigin = false): string {
  return toBase64Url(utf8(JSON.stringify({ type, challenge, origin, crossOrigin })));
}

function base64UrlBytes(text: string | undefined): Uint8Array {
  const bytes = fromBase64Url(text ?? "");
  if (!bytes) throw new Error("invalid base64url");
  return bytes;
}

const node = () => nodeCrypto("createSoftwareAuthenticator", "a Node runtime for passkey tests");

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

interface StoredKey {
  privateKey: NodeKeyObject;
  userHandle: string;
  counter: number;
}

export interface AssertOverrides {
  origin?: string;
  rpId?: string;
  /** Counter to report instead of the next one. */
  counter?: number;
  userVerified?: boolean;
  credentialId?: string;
  userHandle?: string | null;
  /** Challenge to sign instead of the one in the options. */
  challenge?: string;
  type?: string;
  crossOrigin?: boolean;
}

export interface SoftwareAuthenticatorOptions {
  /** Origin the simulated browser reports. */
  origin: string;
  /**
   * Amount added to the signature counter per assertion. 0 simulates an authenticator
   * without a counter, as many synced passkeys are.
   */
  counterStep?: number;
}

/**
 * A software WebAuthn authenticator with P-256 keys and `none` attestation, for tests and
 * demos. It is not a security device: keys live in process memory.
 *
 * Node only: `register` and `assert` sign synchronously with `node:crypto`. Elsewhere they
 * throw `NodeCryptoUnavailableError`.
 */
export interface SoftwareAuthenticator {
  register(
    options: PasskeyCreationOptions,
    overrides?: { origin?: string; userVerified?: boolean; fmt?: string },
  ): RegistrationResponseJSON;
  assert(options: PasskeyRequestOptions, overrides?: AssertOverrides): AuthenticationResponseJSON;
  credentialIds(): string[];
}

export function createSoftwareAuthenticator(
  options: SoftwareAuthenticatorOptions,
): SoftwareAuthenticator {
  const keys = new Map<string, StoredKey>();
  const step = options.counterStep ?? 1;

  return {
    register(creation, overrides = {}) {
      const rpId = creation.rp.id;
      if (!rpId) throw new Error("options without rp.id");
      const crypto = node();
      const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
      const jwk = publicKey.export({ format: "jwk" });
      const credentialId = randomBytes(16);
      const id = toBase64Url(credentialId);
      keys.set(id, { privateKey, userHandle: creation.user.id, counter: 0 });

      const coseKey = encodeCbor(
        new Map<CborValue, CborValue>([
          [1, 2],
          [3, -7],
          [-1, 1],
          [-2, base64UrlBytes(jwk.x)],
          [-3, base64UrlBytes(jwk.y)],
        ]),
      );
      const flags = FLAG_UP | FLAG_AT | (overrides.userVerified === false ? 0 : FLAG_UV);
      const authData = concatBytes(
        sha256(crypto, rpId),
        Uint8Array.of(flags),
        new Uint8Array(4),
        new Uint8Array(16),
        Uint8Array.of(credentialId.byteLength >>> 8, credentialId.byteLength & 0xff),
        credentialId,
        coseKey,
      );
      const attestationObject = encodeCbor(
        new Map<CborValue, CborValue>([
          ["fmt", overrides.fmt ?? "none"],
          ["attStmt", new Map()],
          ["authData", authData],
        ]),
      );
      return {
        id,
        rawId: id,
        type: "public-key",
        response: {
          clientDataJSON: clientData(
            "webauthn.create",
            creation.challenge,
            overrides.origin ?? options.origin,
          ),
          attestationObject: toBase64Url(attestationObject),
          transports: ["internal"],
        },
        clientExtensionResults: {},
      };
    },

    assert(request, overrides = {}) {
      const allowed = request.allowCredentials?.map((c) => c.id) ?? [...keys.keys()];
      const id = overrides.credentialId ?? allowed.find((candidate) => keys.has(candidate));
      if (!id) throw new Error("no matching credential");
      const key = keys.get(id);
      if (!key) throw new Error("unknown credential");
      const rpId = overrides.rpId ?? request.rpId;
      if (!rpId) throw new Error("options without rpId");

      const crypto = node();
      key.counter = overrides.counter ?? key.counter + step;
      if (!Number.isInteger(key.counter) || key.counter < 0 || key.counter > 0xffffffff) {
        throw new RangeError("counter must be an unsigned 32-bit integer");
      }
      const counter = new Uint8Array(4);
      new DataView(counter.buffer).setUint32(0, key.counter);
      const flags = FLAG_UP | (overrides.userVerified === false ? 0 : FLAG_UV);
      const authData = concatBytes(sha256(crypto, rpId), Uint8Array.of(flags), counter);
      const clientDataJSON = clientData(
        overrides.type ?? "webauthn.get",
        overrides.challenge ?? request.challenge,
        overrides.origin ?? options.origin,
        overrides.crossOrigin ?? false,
      );
      const signature = crypto.sign(
        "sha256",
        concatBytes(authData, sha256(crypto, base64UrlBytes(clientDataJSON))),
        key.privateKey,
      );
      const userHandle =
        overrides.userHandle === null ? undefined : (overrides.userHandle ?? key.userHandle);
      return {
        id,
        rawId: id,
        type: "public-key",
        response: {
          clientDataJSON,
          authenticatorData: toBase64Url(authData),
          signature: toBase64Url(signature),
          ...(userHandle !== undefined ? { userHandle } : {}),
        },
        clientExtensionResults: {},
      };
    },

    credentialIds: () => [...keys.keys()],
  };
}
