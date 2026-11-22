/**
 * The only module that talks to the WebAuthn library. Everything else in identkit uses the
 * types and functions here, so the library can be replaced without touching the flows.
 */
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { decodeAttestationObject, isoBase64URL } from "@simplewebauthn/server/helpers";

export type Base64Url = string;

export interface PasskeyCreationOptions {
  rp: { id?: string; name: string };
  user: { id: Base64Url; name: string; displayName: string };
  challenge: Base64Url;
  pubKeyCredParams: { type: string; alg: number }[];
  timeout?: number;
  excludeCredentials?: { id: Base64Url; type: string; transports?: string[] }[];
  authenticatorSelection?: {
    authenticatorAttachment?: string;
    requireResidentKey?: boolean;
    residentKey?: string;
    userVerification?: string;
  };
  attestation?: string;
  extensions?: object;
}

export interface PasskeyRequestOptions {
  challenge: Base64Url;
  timeout?: number;
  rpId?: string;
  allowCredentials?: { id: Base64Url; type: string; transports?: string[] }[];
  userVerification?: string;
  extensions?: object;
}

/** JSON form of a registration credential, as `PublicKeyCredential.toJSON()` returns it. */
export interface RegistrationResponseJSON {
  id: Base64Url;
  rawId: Base64Url;
  type: "public-key";
  response: {
    clientDataJSON: Base64Url;
    attestationObject: Base64Url;
    authenticatorData?: Base64Url;
    transports?: string[];
    publicKeyAlgorithm?: number;
    publicKey?: Base64Url;
  };
  authenticatorAttachment?: string;
  clientExtensionResults: Record<string, unknown>;
}

/** JSON form of an assertion credential, as `PublicKeyCredential.toJSON()` returns it. */
export interface AuthenticationResponseJSON {
  id: Base64Url;
  rawId: Base64Url;
  type: "public-key";
  response: {
    clientDataJSON: Base64Url;
    authenticatorData: Base64Url;
    signature: Base64Url;
    userHandle?: Base64Url;
  };
  authenticatorAttachment?: string;
  clientExtensionResults: Record<string, unknown>;
}

export interface RelyingParty {
  rpId: string;
  rpName: string;
  origins: string[];
}

export interface VerifiedRegistration {
  credentialId: Base64Url;
  publicKey: Uint8Array;
  counter: number;
  transports: string[];
  deviceType: "singleDevice" | "multiDevice";
  backedUp: boolean;
}

export interface VerifiedAssertion {
  newCounter: number;
  userVerified: boolean;
  origin: string;
}

/** Reads one string field from the client data without trusting anything else in it. */
export function readClientField(
  clientDataJSON: unknown,
  field: "challenge" | "origin",
): string | null {
  if (typeof clientDataJSON !== "string" || clientDataJSON.length > 4096) return null;
  try {
    const parsed: unknown = JSON.parse(isoBase64URL.toUTF8String(clientDataJSON));
    if (parsed && typeof parsed === "object" && field in parsed) {
      const value: unknown = Reflect.get(parsed, field);
      return typeof value === "string" && value.length <= 256 ? value : null;
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * True unless the client data says the ceremony ran in a cross-origin frame. identkit does
 * not support embedding, so such a response is refused.
 */
export function isSameOriginCeremony(clientDataJSON: unknown): boolean {
  if (typeof clientDataJSON !== "string" || clientDataJSON.length > 4096) return false;
  try {
    const parsed: unknown = JSON.parse(isoBase64URL.toUTF8String(clientDataJSON));
    if (!parsed || typeof parsed !== "object") return false;
    return !Reflect.get(parsed, "crossOrigin") && !("topOrigin" in parsed);
  } catch {
    return false;
  }
}

/** Reads the challenge from the client data without trusting anything else in it. */
export function readClientChallenge(clientDataJSON: unknown): string | null {
  return readClientField(clientDataJSON, "challenge");
}

/**
 * Copies the fields that verification needs into the library's input shape. Extension
 * outputs are dropped: identkit requests no extension whose result it uses.
 */
function toLibraryRegistration(response: RegistrationResponseJSON) {
  return {
    id: response.id,
    rawId: response.rawId,
    type: response.type,
    response: { ...response.response },
    clientExtensionResults: {},
  };
}

function toLibraryAssertion(response: AuthenticationResponseJSON) {
  return {
    id: response.id,
    rawId: response.rawId,
    type: response.type,
    response: { ...response.response },
    clientExtensionResults: {},
  };
}

export async function registrationOptions(input: {
  rp: RelyingParty;
  userId: Base64Url;
  userName: string;
  challenge: Base64Url;
  timeoutSeconds: number;
  exclude: { id: Base64Url; transports: string[] }[];
}): Promise<PasskeyCreationOptions> {
  const options = await generateRegistrationOptions({
    rpName: input.rp.rpName,
    rpID: input.rp.rpId,
    userID: isoBase64URL.toBuffer(input.userId),
    userName: input.userName,
    userDisplayName: input.userName,
    // Bytes, not a string: the library would encode a string challenge a second time.
    challenge: isoBase64URL.toBuffer(input.challenge),
    timeout: input.timeoutSeconds * 1000,
    attestationType: "none",
    excludeCredentials: input.exclude,
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
  });
  if (options.challenge !== input.challenge) throw new Error("challenge encoding mismatch");
  return options;
}

export async function authenticationOptions(input: {
  rp: RelyingParty;
  challenge: Base64Url;
  timeoutSeconds: number;
  allow: { id: Base64Url; transports: string[] }[];
}): Promise<PasskeyRequestOptions> {
  const options = await generateAuthenticationOptions({
    rpID: input.rp.rpId,
    challenge: isoBase64URL.toBuffer(input.challenge),
    timeout: input.timeoutSeconds * 1000,
    userVerification: "required",
    ...(input.allow.length > 0 ? { allowCredentials: input.allow } : {}),
  });
  if (options.challenge !== input.challenge) throw new Error("challenge encoding mismatch");
  return options;
}

/**
 * Verifies a registration. Accepts only the `none` attestation format: identkit asks for
 * no attestation, and refusing other formats keeps certificate chain code out of reach.
 */
export async function verifyRegistration(input: {
  rp: RelyingParty;
  response: RegistrationResponseJSON;
  expectedChallenge: Base64Url;
}): Promise<VerifiedRegistration> {
  const attestation = decodeAttestationObject(
    isoBase64URL.toBuffer(input.response.response.attestationObject),
  );
  const fmt = attestation.get("fmt");
  if (fmt !== "none") throw new Error("unsupported attestation format");
  if (!isSameOriginCeremony(input.response.response.clientDataJSON)) {
    throw new Error("cross-origin ceremony");
  }

  const result = await verifyRegistrationResponse({
    response: toLibraryRegistration(input.response),
    expectedChallenge: input.expectedChallenge,
    expectedOrigin: input.rp.origins,
    expectedRPID: input.rp.rpId,
    requireUserPresence: true,
    requireUserVerification: true,
  });
  if (!result.verified) throw new Error("registration not verified");
  const info = result.registrationInfo;
  return {
    credentialId: info.credential.id,
    publicKey: new Uint8Array(info.credential.publicKey),
    counter: info.credential.counter,
    transports: info.credential.transports ?? input.response.response.transports ?? [],
    deviceType: info.credentialDeviceType,
    backedUp: info.credentialBackedUp,
  };
}

/**
 * Verifies an assertion signature, challenge, origin, RP ID and user verification. The
 * signature counter is NOT checked here: the caller owns the counter rule.
 */
export async function verifyAssertion(input: {
  rp: RelyingParty;
  response: AuthenticationResponseJSON;
  expectedChallenge: Base64Url;
  credential: { id: Base64Url; publicKey: Uint8Array; transports: string[] };
}): Promise<VerifiedAssertion> {
  if (!isSameOriginCeremony(input.response.response.clientDataJSON)) {
    throw new Error("cross-origin ceremony");
  }
  const result = await verifyAuthenticationResponse({
    response: toLibraryAssertion(input.response),
    expectedChallenge: input.expectedChallenge,
    expectedOrigin: input.rp.origins,
    expectedRPID: input.rp.rpId,
    credential: {
      id: input.credential.id,
      publicKey: new Uint8Array(input.credential.publicKey),
      // Counter 0 turns the library's counter check off; see `checkCounter`.
      counter: 0,
      transports: input.credential.transports,
    },
    requireUserVerification: true,
  });
  if (!result.verified) throw new Error("assertion not verified");
  if (!result.authenticationInfo.userVerified) throw new Error("user not verified");
  return {
    newCounter: result.authenticationInfo.newCounter,
    userVerified: result.authenticationInfo.userVerified,
    origin: result.authenticationInfo.origin,
  };
}

/**
 * Signature counter rule (WebAuthn Level 3, section 7.2, step 22). If either the stored or
 * the new counter is non-zero, the new counter must be greater than the stored one.
 * Authenticators that always report 0 pass, because they do not implement a counter.
 */
export function checkCounter(stored: number, next: number): boolean {
  if (stored === 0 && next === 0) return true;
  return next > stored;
}
