import { z } from "zod";
import { sha256, toHex, utf8 } from "./bytes.js";
import { addSeconds } from "./clock.js";
import type { Context } from "./context.js";
import { digestsEqual, randomId, randomToken } from "./crypto.js";
import type { AuditEvent } from "./audit.js";
import { InvalidArgumentError, NotConfiguredError, OperationRolledBackError } from "./errors.js";
import type {
  ApiTokenDigestAlgorithm,
  ApiTokenRecord,
  ApiTokenSource,
  IdentkitStore,
} from "./storage/types.js";

const DAY_SECONDS = 86_400;
/** Characters after the prefix: base64url of 32 random bytes. */
const TOKEN_BODY = /^[A-Za-z0-9_-]{43}$/;
const TOKEN_BODY_LENGTH = 43;
const SHA256_HEX = /^[0-9a-f]{64}$/;
/**
 * At most 64 characters. None of them is a control character, a format character (Cf: bidi
 * controls such as U+202E, zero-width characters), a lone surrogate, or a line or paragraph
 * separator: an admin UI must show the name as it reads.
 */
const NAME = /^[^\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]{1,64}$/u;

const unique = (values: readonly unknown[]) => new Set(values).size === values.length;

/**
 * Options of `createIdentkit({ apiTokens })`. Every value but `prefix` and `allowedScopes` has a
 * default; see the README section "Personal API tokens".
 */
export const apiTokenOptionsSchema = z
  .object({
    /**
     * Starts every token, for example `pat_`. A letter, then letters, digits or `_`, at most 32
     * characters. A distinct prefix lets secret scanners find leaked tokens.
     */
    prefix: z
      .string()
      .regex(/^[A-Za-z][A-Za-z0-9_]{0,31}$/, "prefix must be a letter, then [A-Za-z0-9_]"),
    /**
     * The scopes a token may carry. Opaque strings for identkit: 1 to 128 visible ASCII
     * characters, no space. `verify` returns only the stored scopes that are still listed.
     */
    allowedScopes: z
      .array(z.string().regex(/^[\x21-\x7e]{1,128}$/, "scope must be visible ASCII, no space"))
      .min(1)
      .refine(unique, { message: "allowedScopes must not repeat a scope" }),
    /** Lifetimes that `create` accepts, in days. Default 7, 30 and 90. */
    allowedExpiryDays: z
      .array(z.number().int().min(1).max(3650))
      .min(1)
      .refine(unique, { message: "allowedExpiryDays must not repeat a value" })
      .default([7, 30, 90]),
    /** Tokens per account that are neither revoked nor expired. Default 5. */
    maxActiveTokensPerAccount: z.number().int().min(1).max(1000).default(5),
    /** `verify` writes `lastUsedAt` at most once per this many seconds. Default 3600. */
    lastUsedIntervalSeconds: z.number().int().min(0).max(DAY_SECONDS).default(3600),
    /**
     * Accept imported tokens whose digest is an unkeyed SHA-256 (see `import`). Default false.
     * Such digests are weaker; turn this off once the imported tokens are rotated out.
     */
    acceptLegacyDigests: z.boolean().default(false),
    /**
     * Receives the error when the audit sink refuses `api_token.used`, with the event. `verify`
     * still returns `valid`: that event is best effort. Without this option the error is
     * dropped. `verify` awaits the call and drops what it throws; keep it quick.
     */
    onAuditError: z
      .custom<ApiTokenAuditErrorHandler>((value) => typeof value === "function", {
        message: "onAuditError must be a function",
      })
      .optional(),
  })
  .strict();

/** See the option `onAuditError`. */
export type ApiTokenAuditErrorHandler = (error: unknown, event: AuditEvent) => void | Promise<void>;

export type ApiTokenOptions = z.input<typeof apiTokenOptionsSchema>;
type ApiTokenSettings = z.output<typeof apiTokenOptionsSchema>;

/** What a consumer sees of a token. Never contains the token or its digest. */
export interface ApiTokenView {
  id: string;
  accountId: string;
  name: string;
  /** As stored, in the order given at creation. */
  scopes: string[];
  createdAt: Date;
  expiresAt: Date;
  /** The last use that `verify` recorded; it records at most one per interval. */
  lastUsedAt: Date | null;
  source: ApiTokenSource;
  /** True for an imported token whose digest is an unkeyed SHA-256. Rotate it out. */
  legacyDigest: boolean;
}

export type CreateApiTokenResult =
  /** `token` is the plaintext. It is returned once and never stored; show it to the owner now. */
  | { status: "created"; token: string; apiToken: ApiTokenView }
  /** The account has `maxActiveTokensPerAccount` active tokens. Nothing was stored. */
  | { status: "limit_reached" }
  | { status: "no_account" }
  | { status: "account_disabled" };

/**
 * `malformed`: not a string of the configured format; identkit made no digest and no read.
 * `unknown`: no token has this digest. `ambiguous`: more than one stored token matches (an
 * import stored one token twice, as a legacy digest and as a keyed digest); identkit refuses
 * rather than pick one. `no_allowed_scope`: none of the token's scopes is in the current
 * `allowedScopes`.
 */
export type ApiTokenRefusal =
  | "malformed"
  | "unknown"
  | "ambiguous"
  | "revoked"
  | "expired"
  | "account_disabled"
  | "no_allowed_scope";

export type VerifyApiTokenResult =
  | {
      status: "valid";
      accountId: string;
      tokenId: string;
      /**
       * The token's scopes that the current `allowedScopes` still lists, in stored order.
       * Opaque strings: your code decides what each one allows, and may narrow them further,
       * for example to the intersection with a delegated grant.
       */
      scopes: string[];
      expiresAt: Date;
    }
  | { status: "refused"; reason: ApiTokenRefusal };

interface ImportBase {
  accountId: string;
  name: string;
  scopes: string[];
  /** Must be in the future and at most the longest `allowedExpiryDays` from now. */
  expiresAt: Date;
  /** Default: now. Must not be in the future. */
  createdAt?: Date;
  /** Must not be in the future, nor before `createdAt` if that is given. */
  lastUsedAt?: Date | null;
}

/**
 * An existing token. With `token` (the plaintext, in the configured format), identkit stores the
 * keyed HMAC, as for a new token. With `sha256Digest` (lowercase or uppercase hex of the
 * unkeyed SHA-256 of the whole token), it stores that weaker digest; this needs the option
 * `acceptLegacyDigests`.
 */
export type ImportApiTokenInput =
  | (ImportBase & { token: string; sha256Digest?: never })
  | (ImportBase & { sha256Digest: string; token?: never });

export type ImportApiTokenResult =
  | { status: "imported"; apiToken: ApiTokenView }
  /** The account holds this token already and it is not revoked. Nothing changed. */
  | { status: "already_imported"; apiToken: ApiTokenView }
  /** The account held this token and it was revoked. It stays revoked. */
  | { status: "revoked" }
  /** Another account holds a token with this digest. Nothing changed. */
  | { status: "digest_taken" }
  | { status: "expired" }
  | { status: "limit_reached" }
  | { status: "no_account" }
  | { status: "account_disabled" };

/**
 * Personal API tokens. Every call takes a bare account id and trusts its caller: check the
 * person (a session, and a step-up for `create`) before you pass an id from a request.
 * `verify` is the only call meant for unauthenticated input.
 */
export interface ApiTokens {
  create(input: {
    accountId: string;
    name: string;
    scopes: string[];
    expiresInDays: number;
  }): Promise<CreateApiTokenResult>;
  /**
   * Checks a token. One read, and at most one write for `lastUsedAt`. A refused
   * `api_token.used` does not fail it (see the option `onAuditError`).
   */
  verify(token: string): Promise<VerifyApiTokenResult>;
  /** The tokens of the account that are not revoked, expired ones included, oldest first. */
  list(accountId: string): Promise<ApiTokenView[]>;
  /** Returns true if this call revoked the token. */
  revoke(input: { accountId: string; tokenId: string }): Promise<boolean>;
  /** Revokes every token of the account. Returns how many this call revoked. */
  revokeAll(accountId: string): Promise<number>;
  /** Administrative: records a token from an earlier system. Idempotent. */
  import(input: ImportApiTokenInput): Promise<ImportApiTokenResult>;
}

type TokenStore = NonNullable<IdentkitStore["apiTokens"]>;

/** The service behind `identkit.apiTokens` when the `apiTokens` option is missing. */
const notConfigured = () => Promise.reject(new NotConfiguredError("apiTokens"));

export function unconfiguredApiTokens(): ApiTokens {
  return {
    create: notConfigured,
    verify: notConfigured,
    list: notConfigured,
    revoke: notConfigured,
    revokeAll: notConfigured,
    import: notConfigured,
  };
}

/**
 * The token from an `Authorization` header value of the form `Bearer <token>` (RFC 6750,
 * section 2.1; the scheme is case-insensitive), or null. It does not check the token's format;
 * `apiTokens.verify` does.
 */
export function parseBearerToken(header: string | null | undefined): string | null {
  if (typeof header !== "string") return null;
  const match = /^Bearer +([A-Za-z0-9\-._~+/]+=*)$/i.exec(header.trim());
  return match?.[1] ?? null;
}

function parseOptions(options: unknown): ApiTokenSettings {
  const parsed = apiTokenOptionsSchema.safeParse(options);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new InvalidArgumentError(
      `apiTokens: ${issue ? `${issue.path.join(".")} ${issue.message}` : "invalid options"}`,
    );
  }
  return parsed.data;
}

function toView(record: ApiTokenRecord): ApiTokenView {
  return {
    id: record.id,
    accountId: record.accountId,
    name: record.name,
    scopes: [...record.scopes],
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    lastUsedAt: record.lastUsedAt,
    source: record.source,
    legacyDigest: record.digestAlgorithm === "sha256",
  };
}

function requireId(value: unknown, what: string): string {
  if (typeof value !== "string" || value === "") {
    throw new InvalidArgumentError(`${what} must be a non-empty string`);
  }
  return value;
}

function requireDate(value: unknown, what: string): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new InvalidArgumentError(`${what} must be a valid Date`);
  }
  return value;
}

function checkName(value: unknown): string {
  if (typeof value !== "string" || !NAME.test(value)) {
    throw new InvalidArgumentError(
      "name must have 1 to 64 characters and no control, format or separator characters",
    );
  }
  return value;
}

/** The legacy digest: unkeyed SHA-256 hex of the whole token. */
async function legacyDigest(token: string): Promise<string> {
  return toHex(await sha256(utf8(token)));
}

/**
 * Revokes every token of the account if the store has API tokens, also when the `apiTokens`
 * option is not set (tokens from an earlier configuration must end too). Returns their ids.
 */
export async function revokeAllApiTokens(
  ctx: Context,
  accountId: string,
  reason: string,
): Promise<string[]> {
  const store = ctx.store.apiTokens;
  if (!store) return [];
  return store.revokeAllForAccount(accountId, ctx.clock.now(), reason);
}

/**
 * Records `api_token.revoked` for each id. A throwing sink does not skip the other events; the
 * first error goes up after all of them.
 */
export async function emitApiTokensRevoked(
  ctx: Context,
  accountId: string,
  tokenIds: readonly string[],
  reason: string,
): Promise<void> {
  let failure: { error: unknown } | null = null;
  for (const tokenId of tokenIds) {
    try {
      await ctx.emit({ type: "api_token.revoked", accountId, tokenId, reason });
    } catch (error) {
      failure ??= { error };
    }
  }
  if (failure) throw failure.error;
}

/** Checks the `apiTokens` option and the store. Throws before any call is made. */
export function createApiTokens(ctx: Context, options: ApiTokenOptions): ApiTokens {
  const settings = parseOptions(options);
  const maybeStore = ctx.store.apiTokens;
  if (!maybeStore) throw new NotConfiguredError("store.apiTokens");
  const store: TokenStore = maybeStore;
  const { clock, hasher } = ctx;
  const allowedScopes = new Set(settings.allowedScopes);
  const maxExpiryDays = Math.max(...settings.allowedExpiryDays);

  const keyedDigest = (token: string) => hasher.digest("api-token", token);

  function isTokenShaped(value: unknown): value is string {
    return (
      typeof value === "string" &&
      value.length === settings.prefix.length + TOKEN_BODY_LENGTH &&
      value.startsWith(settings.prefix) &&
      TOKEN_BODY.test(value.slice(settings.prefix.length))
    );
  }

  function checkScopes(value: unknown): string[] {
    if (!Array.isArray(value) || value.length === 0) {
      throw new InvalidArgumentError("scopes must be a non-empty array");
    }
    const scopes: string[] = [];
    for (const scope of value) {
      if (typeof scope !== "string" || !allowedScopes.has(scope)) {
        throw new InvalidArgumentError("scopes must come from allowedScopes");
      }
      scopes.push(scope);
    }
    if (!unique(scopes)) throw new InvalidArgumentError("scopes must not repeat a scope");
    return scopes;
  }

  /**
   * Records the event of a new token. If the sink refuses it, the token goes again and the call
   * throws `OperationRolledBackError`: no token stands without its audit record. If the store
   * fails on that delete, its error goes up instead, and the token stands.
   */
  async function emitOrRollBack(
    record: ApiTokenRecord,
    event: Parameters<Context["emit"]>[0],
  ): Promise<void> {
    try {
      await ctx.emit(event);
    } catch (error) {
      await store.delete(record.id, record.accountId);
      throw new OperationRolledBackError(record.accountId, { cause: error, hookFailed: false });
    }
  }

  /**
   * Records `api_token.used`, best effort: the one exception to the sink contract. The
   * authentication decision does not depend on the event, and `lastUsedAt` is written already;
   * a refusal must not fail every request that a token authenticates while the sink is down.
   */
  async function emitUsed(event: AuditEvent): Promise<void> {
    try {
      await ctx.emit(event);
    } catch (error) {
      try {
        await settings.onAuditError?.(error, event);
      } catch {
        // Dropped: the handler is a report channel, not a gate.
      }
    }
  }

  /** The account must exist and be active. */
  async function accountState(accountId: string) {
    const account = await ctx.store.accounts.findById(accountId);
    if (!account) return "no_account" as const;
    return account.status === "active" ? null : ("account_disabled" as const);
  }

  return {
    async create(input) {
      if (typeof input !== "object" || input === null) {
        throw new InvalidArgumentError("create needs an input object");
      }
      const accountId = requireId(input.accountId, "accountId");
      const name = checkName(input.name);
      const scopes = checkScopes(input.scopes);
      const days: unknown = input.expiresInDays;
      if (typeof days !== "number" || !settings.allowedExpiryDays.includes(days)) {
        throw new InvalidArgumentError(
          `expiresInDays must be one of ${settings.allowedExpiryDays.join(", ")}`,
        );
      }
      const refused = await accountState(accountId);
      if (refused) return { status: refused };
      const now = clock.now();
      const token = `${settings.prefix}${randomToken()}`;
      const record: ApiTokenRecord = {
        id: randomId(),
        accountId,
        name,
        scopes,
        digest: await keyedDigest(token),
        digestAlgorithm: "hmac-sha256",
        source: "created",
        createdAt: now,
        expiresAt: addSeconds(now, days * DAY_SECONDS),
        lastUsedAt: null,
        revokedAt: null,
        revokeReason: null,
      };
      const inserted = await store.insert(record, {
        maxActive: settings.maxActiveTokensPerAccount,
        at: now,
      });
      if (inserted === "limit_reached") return { status: "limit_reached" };
      // 256 random bits: a digest that exists means a broken random source or store.
      if (inserted !== "inserted") throw new Error("api token digest exists");
      await emitOrRollBack(record, {
        type: "api_token.created",
        accountId,
        tokenId: record.id,
        scopes: [...scopes],
      });
      return { status: "created", token, apiToken: toView(record) };
    },

    async verify(token) {
      if (!isTokenShaped(token)) return { status: "refused", reason: "malformed" };
      const keyed = await keyedDigest(token);
      const legacy = settings.acceptLegacyDigests ? await legacyDigest(token) : null;
      const found = await store.findByDigests(legacy === null ? [keyed] : [keyed, legacy]);
      // The read matched by digest; compare again in constant time, each row against the
      // digest of its own algorithm, so a row can match only the way it was stored.
      const matches = found.filter(({ record }) => {
        const algorithm: ApiTokenDigestAlgorithm = record.digestAlgorithm;
        if (algorithm === "hmac-sha256") return digestsEqual(record.digest, keyed);
        return legacy !== null && digestsEqual(record.digest, legacy);
      });
      const [match, ...others] = matches;
      if (!match) return { status: "refused", reason: "unknown" };
      // One token stored twice (a legacy and a keyed import): the rows can differ in account,
      // scopes and state, and a store returns them in no defined order. Fail closed.
      if (others.length > 0) return { status: "refused", reason: "ambiguous" };
      const { record, accountStatus } = match;
      const now = clock.now();
      if (record.revokedAt !== null) return { status: "refused", reason: "revoked" };
      if (now.getTime() >= record.expiresAt.getTime()) {
        return { status: "refused", reason: "expired" };
      }
      if (accountStatus !== "active") return { status: "refused", reason: "account_disabled" };
      // Fewer rights, never more: a scope the operator no longer allows is dropped.
      const scopes = record.scopes.filter((scope) => allowedScopes.has(scope));
      if (scopes.length === 0) return { status: "refused", reason: "no_allowed_scope" };
      const notAfter = addSeconds(now, -settings.lastUsedIntervalSeconds);
      if (record.lastUsedAt === null || record.lastUsedAt.getTime() <= notAfter.getTime()) {
        if (await store.markUsed(record.id, now, notAfter)) {
          await emitUsed({
            type: "api_token.used",
            at: now,
            accountId: record.accountId,
            tokenId: record.id,
          });
        }
      }
      return {
        status: "valid",
        accountId: record.accountId,
        tokenId: record.id,
        scopes,
        expiresAt: record.expiresAt,
      };
    },

    async list(accountId) {
      requireId(accountId, "accountId");
      return (await store.listByAccount(accountId)).map(toView);
    },

    async revoke(input) {
      if (typeof input !== "object" || input === null) {
        throw new InvalidArgumentError("revoke needs { accountId, tokenId }");
      }
      const accountId = requireId(input.accountId, "accountId");
      const tokenId = requireId(input.tokenId, "tokenId");
      const revoked = await store.revoke(tokenId, accountId, clock.now(), "revoked");
      // The event after the write: a refused event undoes no revocation.
      if (revoked) {
        await ctx.emit({ type: "api_token.revoked", accountId, tokenId, reason: "revoked" });
      }
      return revoked;
    },

    async revokeAll(accountId) {
      requireId(accountId, "accountId");
      const ids = await store.revokeAllForAccount(accountId, clock.now(), "revoked_all");
      await emitApiTokensRevoked(ctx, accountId, ids, "revoked_all");
      return ids.length;
    },

    async import(input) {
      if (typeof input !== "object" || input === null) {
        throw new InvalidArgumentError("import needs an input object");
      }
      const accountId = requireId(input.accountId, "accountId");
      const name = checkName(input.name);
      const scopes = checkScopes(input.scopes);
      const expiresAt = requireDate(input.expiresAt, "expiresAt");
      const now = clock.now();
      const createdAt =
        input.createdAt === undefined ? now : requireDate(input.createdAt, "createdAt");
      const lastUsedAt =
        input.lastUsedAt === undefined || input.lastUsedAt === null
          ? null
          : requireDate(input.lastUsedAt, "lastUsedAt");
      // A date in the future is a data error of the source system. A future lastUsedAt would
      // also suppress every lastUsedAt write and api_token.used event until that date.
      if (createdAt.getTime() > now.getTime()) {
        throw new InvalidArgumentError("createdAt must not be in the future");
      }
      if (lastUsedAt !== null && lastUsedAt.getTime() > now.getTime()) {
        throw new InvalidArgumentError("lastUsedAt must not be in the future");
      }
      // Only against a given createdAt: the default (now) is not a date of the source system.
      if (
        input.createdAt !== undefined &&
        lastUsedAt !== null &&
        lastUsedAt.getTime() < createdAt.getTime()
      ) {
        throw new InvalidArgumentError("lastUsedAt must not be before createdAt");
      }
      if (expiresAt.getTime() > addSeconds(now, maxExpiryDays * DAY_SECONDS).getTime()) {
        throw new InvalidArgumentError(
          `expiresAt must be at most ${maxExpiryDays} days from now (allowedExpiryDays)`,
        );
      }
      const hasToken = input.token !== undefined;
      const hasDigest = input.sha256Digest !== undefined;
      if (hasToken === hasDigest) {
        throw new InvalidArgumentError("import needs exactly one of token and sha256Digest");
      }
      let digest: string;
      let digestAlgorithm: ApiTokenDigestAlgorithm;
      // Every digest under which this token may be stored already. With the plaintext, that
      // includes its legacy digest, also when acceptLegacyDigests is off now: a legacy row from
      // an earlier import is the same token. With a legacy digest only, identkit cannot find a
      // keyed row of the same token (no plaintext); `verify` then refuses it as `ambiguous`.
      let sameToken: string[];
      if (hasToken) {
        if (!isTokenShaped(input.token)) {
          throw new InvalidArgumentError("token does not have the configured format");
        }
        digest = await keyedDigest(input.token);
        digestAlgorithm = "hmac-sha256";
        sameToken = [digest, await legacyDigest(input.token)];
      } else {
        if (!settings.acceptLegacyDigests) {
          throw new NotConfiguredError("apiTokens.acceptLegacyDigests");
        }
        const hex = typeof input.sha256Digest === "string" ? input.sha256Digest.toLowerCase() : "";
        if (!SHA256_HEX.test(hex)) {
          throw new InvalidArgumentError("sha256Digest must be 64 hex characters");
        }
        digest = hex;
        digestAlgorithm = "sha256";
        sameToken = [digest];
      }

      const refused = await accountState(accountId);
      if (refused) return { status: refused };
      const settle = async (): Promise<ImportApiTokenResult | null> => {
        const existing = (await store.findByDigests(sameToken)).filter(({ record }) =>
          sameToken.includes(record.digest),
        );
        if (existing.length === 0) return null;
        if (existing.some(({ record }) => record.accountId !== accountId)) {
          return { status: "digest_taken" };
        }
        // A revoked copy keeps the token revoked, whatever the other copy says.
        const live = existing.filter(({ record }) => record.revokedAt === null);
        const [only] = live;
        if (!only || live.length !== existing.length) return { status: "revoked" };
        return { status: "already_imported", apiToken: toView(only.record) };
      };
      const before = await settle();
      if (before) return before;
      if (expiresAt.getTime() <= now.getTime()) return { status: "expired" };
      const record: ApiTokenRecord = {
        id: randomId(),
        accountId,
        name,
        scopes,
        digest,
        digestAlgorithm,
        source: "import",
        createdAt,
        expiresAt,
        lastUsedAt,
        revokedAt: null,
        revokeReason: null,
      };
      const inserted = await store.insert(record, {
        maxActive: settings.maxActiveTokensPerAccount,
        at: now,
      });
      if (inserted === "limit_reached") return { status: "limit_reached" };
      if (inserted === "digest_taken") return (await settle()) ?? { status: "digest_taken" };
      await emitOrRollBack(record, {
        type: "api_token.imported",
        accountId,
        tokenId: record.id,
        scopes: [...scopes],
        method: digestAlgorithm,
      });
      return { status: "imported", apiToken: toView(record) };
    },
  };
}
