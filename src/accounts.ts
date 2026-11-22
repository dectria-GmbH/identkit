import type { Context } from "./context.js";
import { randomBytes } from "node:crypto";
import { randomId } from "./crypto.js";
import { normalizeEmail } from "./email.js";
import type { AccountRecord } from "./storage/types.js";

export interface AccountView {
  id: string;
  email: string;
  status: AccountRecord["status"];
  createdAt: Date;
  identityVerified: boolean;
  assuranceLevel: AccountRecord["assuranceLevel"];
}

export type CreateAccountResult =
  { status: "created"; account: AccountView } | { status: "email_taken" };

/**
 * Administrative account operations. These calls trust their caller: expose them only to
 * privileged code paths, never to an unauthenticated client.
 */
export interface Accounts {
  /**
   * Creates an account for an address. An address belongs to at most one account, and a
   * verified person to at most one account, so this never yields a second account for the
   * same address.
   */
  create(input: { email: string }): Promise<CreateAccountResult>;
  get(accountId: string): Promise<AccountView | null>;
  findByEmail(email: string): Promise<AccountView | null>;
  /** Disables the account and revokes all its sessions. */
  disable(accountId: string): Promise<void>;
}

export function toAccountView(record: AccountRecord): AccountView {
  return {
    id: record.id,
    email: record.email,
    status: record.status,
    createdAt: record.createdAt,
    identityVerified: record.personKeyDigest !== null,
    assuranceLevel: record.assuranceLevel,
  };
}

export function newAccountRecord(email: string, createdAt: Date): AccountRecord {
  return {
    id: randomId(),
    email,
    webauthnUserId: randomBytes(32).toString("base64url"),
    status: "active",
    createdAt,
    personKeyDigest: null,
    assuranceLevel: null,
    identityVerifiedAt: null,
  };
}

export function createAccounts(
  ctx: Context,
  revokeAll: (accountId: string) => Promise<number>,
): Accounts {
  const { store, clock } = ctx;
  return {
    async create(input) {
      const email = normalizeEmail(input.email);
      const record = newAccountRecord(email, clock.now());
      const result = await store.accounts.insert(record);
      if (result === "email_taken") return { status: "email_taken" };
      await ctx.emit({ type: "account.created", accountId: record.id, reason: "administrative" });
      return { status: "created", account: toAccountView(record) };
    },
    async get(accountId) {
      const record = await store.accounts.findById(accountId);
      return record ? toAccountView(record) : null;
    },
    async findByEmail(email) {
      const record = await store.accounts.findByEmail(normalizeEmail(email));
      return record ? toAccountView(record) : null;
    },
    async disable(accountId) {
      const record = await store.accounts.findById(accountId);
      if (!record) return;
      await store.accounts.setStatus(accountId, "disabled");
      await revokeAll(accountId);
      await ctx.emit({ type: "account.disabled", accountId });
    },
  };
}
