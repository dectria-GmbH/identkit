import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import type {
  AuthenticationResponseJSON,
  PasskeyCreationOptions,
  PasskeyRequestOptions,
  RegistrationResponseJSON,
} from "../webauthn.js";

/** Minimal CBOR encoder for the shapes WebAuthn uses: integers, byte and text strings, maps. */
type CborValue = number | string | Uint8Array | Map<CborValue, CborValue>;

function head(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 0x100) return Buffer.from([(major << 5) | 24, length]);
  if (length < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(length, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(length, 1);
  return b;
}

function encodeCbor(value: CborValue): Buffer {
  if (typeof value === "number") {
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  }
  if (typeof value === "string") {
    const bytes = Buffer.from(value, "utf8");
    return Buffer.concat([head(3, bytes.byteLength), bytes]);
  }
  if (value instanceof Uint8Array) {
    return Buffer.concat([head(2, value.byteLength), Buffer.from(value)]);
  }
  const parts: Buffer[] = [head(5, value.size)];
  for (const [k, v] of value) parts.push(encodeCbor(k), encodeCbor(v));
  return Buffer.concat(parts);
}

const sha256 = (data: Uint8Array | string) => createHash("sha256").update(data).digest();

function clientData(type: string, challenge: string, origin: string, crossOrigin = false): string {
  return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin }), "utf8").toString(
    "base64url",
  );
}

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

interface StoredKey {
  privateKey: KeyObject;
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
      const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const jwk = publicKey.export({ format: "jwk" });
      const credentialId = randomBytes(16);
      const id = credentialId.toString("base64url");
      keys.set(id, { privateKey, userHandle: creation.user.id, counter: 0 });

      const coseKey = encodeCbor(
        new Map<CborValue, CborValue>([
          [1, 2],
          [3, -7],
          [-1, 1],
          [-2, Buffer.from(String(jwk.x), "base64url")],
          [-3, Buffer.from(String(jwk.y), "base64url")],
        ]),
      );
      const flags = FLAG_UP | FLAG_AT | (overrides.userVerified === false ? 0 : FLAG_UV);
      const length = Buffer.alloc(2);
      length.writeUInt16BE(credentialId.byteLength);
      const authData = Buffer.concat([
        sha256(rpId),
        Buffer.from([flags]),
        Buffer.alloc(4),
        Buffer.alloc(16),
        length,
        credentialId,
        coseKey,
      ]);
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
          attestationObject: attestationObject.toString("base64url"),
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

      key.counter = overrides.counter ?? key.counter + step;
      const counter = Buffer.alloc(4);
      counter.writeUInt32BE(key.counter);
      const flags = FLAG_UP | (overrides.userVerified === false ? 0 : FLAG_UV);
      const authData = Buffer.concat([sha256(rpId), Buffer.from([flags]), counter]);
      const clientDataJSON = clientData(
        overrides.type ?? "webauthn.get",
        overrides.challenge ?? request.challenge,
        overrides.origin ?? options.origin,
        overrides.crossOrigin ?? false,
      );
      const signature = sign(
        "sha256",
        Buffer.concat([authData, sha256(Buffer.from(clientDataJSON, "base64url"))]),
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
          authenticatorData: authData.toString("base64url"),
          signature: signature.toString("base64url"),
          ...(userHandle !== undefined ? { userHandle } : {}),
        },
        clientExtensionResults: {},
      };
    },

    credentialIds: () => [...keys.keys()],
  };
}
