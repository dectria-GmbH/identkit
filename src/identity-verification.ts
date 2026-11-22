import { addSeconds } from "./clock.js";
import type { Context } from "./context.js";
import { randomId } from "./crypto.js";
import { NotConfiguredError } from "./errors.js";
import type { AssuranceLevel, VerificationRecord, VerificationStatus } from "./storage/types.js";

/** Result that an identity verification vendor reports for one verification. */
export type VendorResult =
  | { status: "pending" }
  | {
      status: "verified";
      assuranceLevel: AssuranceLevel;
      /** The vendor's reference to its evidence (report id). Not the evidence itself. */
      evidenceReference: string;
      /**
       * A stable key for the verified person, the same for every verification of that
       * person, for example a keyed hash of document data. identkit stores only its keyed
       * hash and uses it to keep one account per person.
       */
      personKey: string;
    }
  | { status: "failed"; reason: string };

/**
 * Port to a remote identity verification vendor. An implementation authenticates the
 * vendor's callbacks itself (signature, mutual TLS) and throws if a callback is not
 * authentic.
 */
export interface IdentityVerificationAdapter {
  start(input: {
    verificationId: string;
    returnUrl?: string;
  }): Promise<{ vendorReference: string; redirectUrl?: string }>;
  /** Authenticates a vendor callback and returns the verification it is about. */
  parseCallback(payload: unknown): Promise<{ vendorReference: string }>;
  fetchResult(vendorReference: string): Promise<VendorResult>;
}

export interface VerificationView {
  id: string;
  accountId: string;
  /** `verified` only once the person is linked; a success still being linked reads `pending`. */
  status: Exclude<VerificationStatus, "processing">;
  assuranceLevel: AssuranceLevel | null;
  evidenceReference: string | null;
  failureReason: string | null;
  createdAt: Date;
  expiresAt: Date;
  completedAt: Date | null;
}

export interface IdentityVerification {
  start(input: {
    accountId: string;
    returnUrl?: string;
  }): Promise<{ verificationId: string; redirectUrl?: string; expiresAt: Date }>;
  /** Handles a vendor callback: authenticates it through the adapter, then refreshes. */
  handleCallback(payload: unknown): Promise<VerificationView>;
  /**
   * Asks the vendor for the current result, and applies the timeout. `refresh` and `get` take
   * a bare id: check that the caller owns the verification before you pass client input.
   */
  refresh(verificationId: string): Promise<VerificationView | null>;
  get(verificationId: string): Promise<VerificationView | null>;
}

/** Vendor reasons are free text; audit events get them only if they look like a code. */
function auditReason(reason: string): string {
  return /^[a-z0-9_]{1,64}$/.test(reason) ? reason : "vendor_reason";
}

const view = (record: VerificationRecord): VerificationView => ({
  id: record.id,
  accountId: record.accountId,
  status: record.status === "processing" ? "pending" : record.status,
  assuranceLevel: record.assuranceLevel,
  evidenceReference: record.evidenceReference,
  failureReason: record.failureReason,
  createdAt: record.createdAt,
  expiresAt: record.expiresAt,
  completedAt: record.completedAt,
});

export function createIdentityVerification(ctx: Context): IdentityVerification {
  const { store, clock, config, hasher } = ctx;

  const adapter = (): IdentityVerificationAdapter => {
    if (!ctx.identityVerification) throw new NotConfiguredError("identity verification adapter");
    return ctx.identityVerification;
  };

  async function finish(
    record: VerificationRecord,
    update: Parameters<typeof store.verifications.complete>[1],
  ): Promise<VerificationRecord> {
    const changed = await store.verifications.complete(record.id, update);
    const current = (await store.verifications.findById(record.id)) ?? record;
    if (!changed) return current;
    const type =
      update.status === "verified"
        ? "identity_verification.completed"
        : update.status === "expired"
          ? "identity_verification.expired"
          : update.status === "conflict"
            ? "identity_verification.person_conflict"
            : "identity_verification.failed";
    await ctx.emit({
      type,
      accountId: record.accountId,
      verificationId: record.id,
      ...(update.failureReason ? { reason: auditReason(update.failureReason) } : {}),
    });
    return current;
  }

  /** Links the person and moves a `processing` verification to its final state. */
  async function linkAndFinalize(
    record: VerificationRecord,
    result: Extract<VendorResult, { status: "verified" }>,
    now: Date,
  ): Promise<VerificationRecord> {
    const personKeyDigest = await hasher.digest("person-key", result.personKey);
    const linked = await store.accounts.linkPerson(
      record.accountId,
      personKeyDigest,
      result.assuranceLevel,
      now,
    );
    const conflict = linked === "person_linked_elsewhere" || linked === "account_has_other_person";
    const changed = await store.verifications.finalize(record.id, {
      status: conflict ? "conflict" : "verified",
      assuranceLevel: result.assuranceLevel,
      evidenceReference: result.evidenceReference,
      failureReason: conflict ? linked : null,
      completedAt: now,
    });
    if (changed) {
      await ctx.emit({
        type: conflict
          ? "identity_verification.person_conflict"
          : "identity_verification.completed",
        accountId: record.accountId,
        verificationId: record.id,
        ...(conflict ? { reason: linked } : {}),
      });
    }
    return (await store.verifications.findById(record.id)) ?? record;
  }

  async function refreshRecord(record: VerificationRecord): Promise<VerificationRecord> {
    if (record.status !== "pending" && record.status !== "processing") return record;
    const now = clock.now();

    if (record.status === "processing") {
      // An earlier call claimed a success but did not finish, for example after a store error.
      if (!record.vendorReference) return record;
      const retry = await adapter().fetchResult(record.vendorReference);
      if (retry.status === "verified") return linkAndFinalize(record, retry, now);
      await store.verifications.finalize(record.id, {
        status: "failed",
        assuranceLevel: null,
        evidenceReference: null,
        failureReason: "vendor_result_changed",
        completedAt: now,
      });
      return (await store.verifications.findById(record.id)) ?? record;
    }

    const final = { completedAt: now };
    if (now.getTime() >= record.expiresAt.getTime()) {
      return finish(record, {
        ...final,
        status: "expired",
        assuranceLevel: null,
        evidenceReference: null,
        failureReason: "timeout",
      });
    }
    if (!record.vendorReference) return record;
    const result = await adapter().fetchResult(record.vendorReference);
    if (result.status === "pending") return record;
    if (result.status === "failed") {
      return finish(record, {
        ...final,
        status: "failed",
        assuranceLevel: null,
        evidenceReference: null,
        failureReason: result.reason.slice(0, 200),
      });
    }
    // Claim the result first, so a concurrent timeout and a link cannot both happen. Until
    // the link is done, the verification reads as pending.
    if (!(await store.verifications.claim(record.id))) {
      return (await store.verifications.findById(record.id)) ?? record;
    }
    return linkAndFinalize(record, result, now);
  }

  return {
    async start(input) {
      const account = await store.accounts.findById(input.accountId);
      if (!account || account.status !== "active") throw new Error("account not found");
      const now = clock.now();
      const record: VerificationRecord = {
        id: randomId(),
        accountId: account.id,
        vendorReference: null,
        status: "pending",
        assuranceLevel: null,
        evidenceReference: null,
        failureReason: null,
        createdAt: now,
        expiresAt: addSeconds(now, config.identityVerification.timeoutSeconds),
        completedAt: null,
      };
      await store.verifications.insert(record);
      const started = await adapter().start({
        verificationId: record.id,
        ...(input.returnUrl ? { returnUrl: input.returnUrl } : {}),
      });
      await store.verifications.setVendorReference(record.id, started.vendorReference);
      await ctx.emit({
        type: "identity_verification.started",
        accountId: account.id,
        verificationId: record.id,
      });
      return {
        verificationId: record.id,
        expiresAt: record.expiresAt,
        ...(started.redirectUrl ? { redirectUrl: started.redirectUrl } : {}),
      };
    },

    async handleCallback(payload) {
      const { vendorReference } = await adapter().parseCallback(payload);
      const record = await store.verifications.findByVendorReference(vendorReference);
      if (!record) throw new Error("unknown verification");
      return view(await refreshRecord(record));
    },

    async refresh(verificationId) {
      const record = await store.verifications.findById(verificationId);
      return record ? view(await refreshRecord(record)) : null;
    },

    async get(verificationId) {
      const record = await store.verifications.findById(verificationId);
      return record ? view(record) : null;
    },
  };
}
