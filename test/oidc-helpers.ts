import {
  googleProvider,
  microsoftProvider,
  oidcProvider,
  type GoogleProviderOptions,
  type MicrosoftProviderOptions,
  type OidcOptions,
  type AllSessionsRevokedHook,
  type SignInPolicy,
} from "../src/index.js";
import type { OidcFetch } from "../src/oidc-jwks.js";
import type { IdentkitStore } from "../src/storage/types.js";
import { createFakeOidcProvider, type FakeClaims } from "../src/testing/index.js";
import { emailFirstPolicy, setup, testConfig, testOidcConfig } from "./helpers.js";

export const REDIRECT_URI = "https://portal.example/auth/callback";
export const MS = { clientId: "ms-client-id", clientSecret: "ms-client-secret" };
export const GOOGLE = { clientId: "google-client-id", clientSecret: "google-client-secret" };
export const ACME = {
  clientId: "acme-client-id",
  clientSecret: "acme:secret/with+chars",
  issuer: "https://idp.acme.example",
};
export const TENANT = "11111111-2222-4333-8444-555555555555";
export const OTHER_TENANT = "66666666-7777-4888-9999-000000000000";

export const oidcPolicy: SignInPolicy = {
  ...emailFirstPolicy,
  signInMethods: ["email_otp", "passkey", "oidc"],
};

let seq = 0;
/** A fresh GUID-shaped id, distinct per call. */
export function guid(): string {
  seq += 1;
  const tail = seq.toString(16).padStart(12, "0");
  return `aaaaaaaa-bbbb-4ccc-8ddd-${tail}`;
}

/** Claims of a Microsoft work account with a domain-verified address. */
export function msClaims(email: string, overrides: FakeClaims = {}): FakeClaims {
  return {
    tid: TENANT,
    oid: guid(),
    sub: `pairwise-${seq}`,
    email,
    xms_edov: true,
    preferred_username: email,
    name: "Test Person",
    ...overrides,
  };
}

export function googleClaims(email: string, overrides: FakeClaims = {}): FakeClaims {
  seq += 1;
  return { sub: `10${seq}`, email, email_verified: true, ...overrides };
}

export interface OidcSetupOptions {
  store?: IdentkitStore;
  policy?: SignInPolicy;
  linksPerAccount?: "one" | "any";
  mayBind?: OidcOptions["mayBind"];
  microsoft?: Partial<MicrosoftProviderOptions>;
  /** The Microsoft authority, for the fake and the provider. Default `common`. */
  microsoftTenant?: string;
  google?: Partial<GoogleProviderOptions>;
  privilegedEmails?: string[];
  oidcConfig?: Partial<typeof testOidcConfig>;
  sharedFetchLog?: string[];
  onAllSessionsRevoked?: AllSessionsRevokedHook;
}

export async function oidcSetup(options: OidcSetupOptions = {}) {
  let clockSource: { now(): Date } | null = null;
  const clock = {
    now: () => (clockSource ? clockSource.now() : new Date("2030-01-01T00:00:00.000Z")),
  };
  const fakes = {
    microsoft: await createFakeOidcProvider({
      kind: "microsoft",
      ...MS,
      clock,
      tenant: options.microsoftTenant ?? "common",
    }),
    google: await createFakeOidcProvider({ kind: "google", ...GOOGLE, clock }),
    acme: await createFakeOidcProvider({
      kind: "oidc",
      ...ACME,
      algorithm: "ES256",
      clock,
    }),
  };
  const fetchLog: string[] = [];
  const fetch: OidcFetch = async (url, init) => {
    fetchLog.push(url);
    for (const fake of Object.values(fakes)) {
      const response = await fake.fetch(url, init);
      if (response.status !== 404) return response;
    }
    return new Response("{}", { status: 404 });
  };
  const providers = [
    microsoftProvider({
      ...MS,
      redirectUri: REDIRECT_URI,
      tenant: options.microsoftTenant ?? "common",
      ...options.microsoft,
    }),
    googleProvider({ ...GOOGLE, redirectUri: REDIRECT_URI, ...options.google }),
    oidcProvider({
      id: "acme",
      ...ACME,
      redirectUri: REDIRECT_URI,
      authorizationEndpoint: fakes.acme.authorizationEndpoint,
      tokenEndpoint: fakes.acme.tokenEndpoint,
      jwksUri: fakes.acme.jwksUri,
      algorithms: ["ES256"],
    }),
  ];
  const t = setup({
    ...(options.store ? { store: options.store } : {}),
    ...(options.privilegedEmails ? { privilegedEmails: options.privilegedEmails } : {}),
    ...(options.onAllSessionsRevoked ? { onAllSessionsRevoked: options.onAllSessionsRevoked } : {}),
    policy: options.policy ?? oidcPolicy,
    config: { ...testConfig, oidc: { ...testOidcConfig, ...options.oidcConfig } },
    oidc: {
      providers,
      fetch,
      ...(options.linksPerAccount ? { linksPerAccount: options.linksPerAccount } : {}),
      ...(options.mayBind ? { mayBind: options.mayBind } : {}),
    },
  });
  clockSource = t.clock;

  /** Begin, the user at the provider, and finish, as a browser would run them. */
  async function signInWith(provider: keyof typeof fakes, claims: FakeClaims) {
    const begun = await t.ik.oidc.begin({ provider });
    const params = await fakes[provider].authorize(begun.authorizationUrl, claims);
    return t.ik.oidc.finish({ transaction: begun.transaction, params });
  }

  return { ...t, fakes, providers, fetchLog, signInWith };
}
