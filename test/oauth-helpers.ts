import { randomBytes } from "node:crypto";
import {
  createHmacHasher,
  createIdentkit,
  createMemoryStore,
  type IdentkitStore,
  type OAuthOptions,
} from "../src/index.js";
import type { SecretHasher } from "../src/crypto.js";
import {
  createFakeClock,
  createRecordingAuditSink,
  createRecordingMailSender,
  createTestSealer,
} from "../src/testing/index.js";
import { emailFirstPolicy, testConfig } from "./helpers.js";

export const ISSUER = "https://example.com";
export const RESOURCE = "https://example.com/mcp";

/** The options most tests use: two resources, one default and one opt-in scope. */
export const baseOAuthOptions: OAuthOptions = {
  issuer: ISSUER,
  resources: [RESOURCE, ISSUER],
  resourceName: "Example",
  defaultScopes: ["mcp:read"],
  optInScopes: ["mcp:events"],
};

export interface OAuthSetupOptions {
  oauth?: Partial<OAuthOptions>;
  store?: IdentkitStore;
  hasher?: SecretHasher;
  apiTokens?: { prefix: string; allowedScopes: string[] };
}

/** identkit with the OAuth server over a memory store. */
export function oauthSetup(options: OAuthSetupOptions = {}) {
  const store = options.store ?? createMemoryStore();
  const clock = createFakeClock();
  const audit = createRecordingAuditSink();
  const hasher = options.hasher ?? createHmacHasher(new Uint8Array(randomBytes(32)));
  const sealer = createTestSealer();
  const ik = createIdentkit({
    config: testConfig,
    policy: emailFirstPolicy,
    isPrivilegedAccount: () => false,
    store,
    hasher,
    sealer,
    mail: createRecordingMailSender(),
    audit,
    clock,
    oauth: { ...baseOAuthOptions, ...options.oauth },
    ...(options.apiTokens ? { apiTokens: options.apiTokens } : {}),
  });
  async function account(email = `p-${Math.random().toString(36).slice(2)}@example.org`) {
    const created = await ik.accounts.create({ email });
    if (created.status !== "created") throw new Error(created.status);
    return created.account.id;
  }
  return { ik, store, clock, audit, hasher, sealer, account };
}

/** A registration body. */
export function registration(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    redirect_uris: ["http://127.0.0.1/callback"],
    client_name: "Example client",
    ...overrides,
  });
}
