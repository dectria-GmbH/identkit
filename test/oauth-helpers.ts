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
  createOAuthTestClient,
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

/**
 * Security row 28: deleting an account row in the database removes its grants, their access
 * tokens and its codes by foreign key. `deleteAccount` runs the raw SQL delete; `count` counts
 * the rows of a table whose column equals the value. Returns the counts after the delete.
 */
export async function oauthRowsAfterAccountDelete(
  store: IdentkitStore,
  deleteAccount: (accountId: string) => Promise<void>,
  count: (table: string, column: string, value: string) => Promise<number>,
) {
  const t = oauthSetup({ store });
  const client = await createOAuthTestClient(t.ik.oauth);
  const accountId = await t.account();
  await client.connect(accountId);
  await client.authorize(accountId);
  const [grant] = await t.ik.oauth.listGrants(accountId);
  if (!grant) throw new Error("no grant");
  const before = {
    grants: await count("identkit_oauth_grants", "account_id", accountId),
    accessTokens: await count("identkit_oauth_access_tokens", "grant_id", grant.id),
    codes: await count("identkit_oauth_codes", "account_id", accountId),
  };
  await deleteAccount(accountId);
  const after = {
    grants: await count("identkit_oauth_grants", "account_id", accountId),
    accessTokens: await count("identkit_oauth_access_tokens", "grant_id", grant.id),
    codes: await count("identkit_oauth_codes", "account_id", accountId),
  };
  return { before, after, client: await t.ik.oauth.getClient(client.clientId) };
}
