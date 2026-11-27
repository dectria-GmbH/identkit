import { sha256, toHex, utf8 } from "../bytes.js";
import { digestsEqual } from "../crypto.js";
import {
  InvalidArgumentError,
  NotConfiguredError,
  OAuthClientRolledBackError,
  OperationRolledBackError,
} from "../errors.js";
import type {
  OAuthClientAuthMethod,
  OAuthClientRecord,
  OAuthGrantRecord,
} from "../storage/types.js";
import { MAX_SECRET_LENGTH } from "./client-auth.js";
import {
  CLIENT_ID,
  requireId,
  sanitizeClientName,
  toClientView,
  type OAuthInternals,
} from "./common.js";
import type { OAuthClientView } from "./options.js";
import { parseRedirectUri } from "./redirect-uris.js";

const AUTH_METHODS = new Set<OAuthClientAuthMethod>([
  "none",
  "client_secret_basic",
  "client_secret_post",
]);
const GRANT_TYPES = new Set(["authorization_code", "refresh_token"]);
const SHA256_HEX = /^[0-9a-f]{64}$/;
/** A grant id that identkit may store: visible ASCII, 1 to 128 characters. */
const GRANT_ID = CLIENT_ID;

/**
 * A client of an earlier system. The id is kept as given (visible ASCII, 1 to 128 characters).
 * A confidential client needs exactly one of `secret` (the plaintext; identkit stores its keyed
 * digest) and `secretSha256` (lowercase or uppercase hex of the unkeyed SHA-256 of the secret;
 * needs the option `acceptLegacyClientSecrets`). A public client (`authMethod: "none"`) needs
 * neither. Redirect URIs pass the same rules as at registration.
 */
export interface ImportOAuthClientInput {
  id: string;
  name?: string | null;
  redirectUris: string[];
  /** Must hold `authorization_code`, and `refresh_token` at most. */
  grantTypes: string[];
  authMethod: OAuthClientAuthMethod;
  /** Default: now. Must not be in the future. */
  createdAt?: Date;
  /** Must not be in the future, nor before `createdAt` if that is given. */
  lastUsedAt?: Date | null;
  secret?: string;
  secretSha256?: string;
}

export type ImportOAuthClientResult =
  | { status: "imported"; client: OAuthClientView }
  /** A client with this id and the same data exists. Nothing changed. */
  | { status: "already_imported"; client: OAuthClientView }
  /** A client with this id and other data exists, or identkit cannot tell. Nothing changed. */
  | { status: "id_taken" }
  /**
   * An imported client with this id was deleted (`deleteClient` or `purge`). It stays deleted:
   * nothing changed.
   */
  | { status: "revoked" };

/**
 * A grant of an earlier system, with the state of its refresh token. The grant id is kept as
 * given, because the legacy tokens name it. `refreshSha256` is the lowercase or uppercase hex
 * of the unkeyed SHA-256 of the current refresh token, whose generation is `generation`.
 */
export interface ImportOAuthGrantInput {
  id: string;
  accountId: string;
  clientId: string;
  /** Each one of the option's default or opt-in scopes, each once. */
  scopes: string[];
  /** One of the option `resources`. */
  resource: string;
  /** Must not be in the future. */
  createdAt: Date;
  /** The absolute end of the grant. */
  expiresAt: Date;
  /** The generation of the current refresh token, 1 or more. */
  generation: number;
  /** The last rotation, if any. Not before `createdAt`, not in the future. */
  refreshedAt?: Date | null;
  /** The end of the current refresh token; at most `expiresAt`. */
  refreshExpiresAt: Date;
  refreshSha256: string;
}

export type ImportOAuthGrantResult =
  | { status: "imported" }
  /** A grant with this id, account, client, scopes and resource exists. Nothing changed. */
  | { status: "already_imported" }
  /** A grant with this id and other data exists. Nothing changed. */
  | { status: "id_taken" }
  /** The account holds a grant of this client already. Nothing changed. */
  | { status: "account_client_taken" }
  /**
   * An imported grant with this id ended (revoked, replaced, reused token, expired, account
   * disabled, client deleted or purged). It stays ended, and its earlier refresh token stays
   * dead: nothing changed.
   */
  | { status: "revoked" }
  | { status: "limit_reached" }
  | { status: "expired" }
  | { status: "no_account" }
  | { status: "account_disabled" }
  | { status: "no_client" };

function requireDate(value: unknown, what: string): Date {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new InvalidArgumentError(`${what} must be a valid Date`);
  }
  return value;
}

function stringList(value: unknown, what: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new InvalidArgumentError(`${what} must be an array of strings`);
  }
  if (new Set(value).size !== value.length) {
    throw new InvalidArgumentError(`${what} must not repeat a value`);
  }
  return [...value];
}

const sameList = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every((value, i) => value === b[i]);

const legacyHex = async (value: string) => toHex(await sha256(utf8(value)));

/** `oauth.importClient` and `oauth.importGrant`: administrative, idempotent. */
export function createImport(internals: OAuthInternals) {
  const { ctx, settings, store } = internals;
  const { clock, hasher } = ctx;
  const knownScopes = new Set(settings.knownScopes);

  /** True if the stored client holds the same data and the same secret as the input. */
  async function sameClient(
    stored: OAuthClientRecord,
    wanted: Omit<OAuthClientRecord, "createdAt" | "lastUsedAt" | "secretDigest">,
    secret: { plain: string } | { sha256: string } | null,
  ): Promise<boolean> {
    if (
      stored.source !== "import" ||
      stored.authMethod !== wanted.authMethod ||
      stored.name !== wanted.name ||
      !sameList(stored.grantTypes, wanted.grantTypes) ||
      !sameList(stored.redirectUris, wanted.redirectUris)
    ) {
      return false;
    }
    if (secret === null) return stored.secretDigest === null;
    if (stored.secretDigest === null) return false;
    if ("plain" in secret) {
      // Either form: a SHA-256 import that identkit upgraded holds the keyed digest now.
      return stored.secretDigestAlgorithm === "hmac-sha256"
        ? digestsEqual(
            stored.secretDigest,
            await hasher.digest("oauth-client-secret", secret.plain),
          )
        : digestsEqual(stored.secretDigest, await legacyHex(secret.plain));
    }
    // Without the plaintext, an upgraded digest cannot be compared: identkit cannot tell.
    return (
      stored.secretDigestAlgorithm === "sha256" && digestsEqual(stored.secretDigest, secret.sha256)
    );
  }

  return {
    async importClient(input: ImportOAuthClientInput): Promise<ImportOAuthClientResult> {
      if (typeof input !== "object" || input === null) {
        throw new InvalidArgumentError("importClient needs an input object");
      }
      const id = requireId(input.id, "id");
      if (!CLIENT_ID.test(id)) {
        throw new InvalidArgumentError("id must be 1 to 128 visible ASCII characters");
      }
      const authMethod = input.authMethod;
      if (!AUTH_METHODS.has(authMethod)) {
        throw new InvalidArgumentError(
          "authMethod must be none, client_secret_basic or client_secret_post",
        );
      }
      const redirectUris = stringList(input.redirectUris, "redirectUris");
      const { registration, redirectUris: uriRules } = settings;
      const rules = {
        maxLength: registration.maxRedirectUriLength,
        allowIpv6Loopback: uriRules.allowIpv6Loopback,
        allowPrivateUseSchemes: uriRules.allowPrivateUseSchemes,
      };
      if (
        redirectUris.length === 0 ||
        redirectUris.length > registration.maxRedirectUris ||
        !redirectUris.every((uri) => parseRedirectUri(uri, rules))
      ) {
        throw new InvalidArgumentError(
          "redirectUris must hold 1 to registration.maxRedirectUris URIs that pass the registration rules",
        );
      }
      const grantTypes = stringList(input.grantTypes, "grantTypes");
      if (
        !grantTypes.includes("authorization_code") ||
        !grantTypes.every((g) => GRANT_TYPES.has(g))
      ) {
        throw new InvalidArgumentError(
          "grantTypes must hold authorization_code, and refresh_token at most",
        );
      }
      const rawName = input.name ?? null;
      if (rawName !== null && typeof rawName !== "string") {
        throw new InvalidArgumentError("name must be a string or null");
      }
      const name = rawName === null ? null : sanitizeClientName(rawName);
      const now = clock.now();
      const createdAt =
        input.createdAt === undefined ? now : requireDate(input.createdAt, "createdAt");
      const lastUsedAt =
        input.lastUsedAt === undefined || input.lastUsedAt === null
          ? null
          : requireDate(input.lastUsedAt, "lastUsedAt");
      if (createdAt.getTime() > now.getTime()) {
        throw new InvalidArgumentError("createdAt must not be in the future");
      }
      if (lastUsedAt !== null && lastUsedAt.getTime() > now.getTime()) {
        throw new InvalidArgumentError("lastUsedAt must not be in the future");
      }
      if (
        input.createdAt !== undefined &&
        lastUsedAt !== null &&
        lastUsedAt.getTime() < createdAt.getTime()
      ) {
        throw new InvalidArgumentError("lastUsedAt must not be before createdAt");
      }

      const hasSecret = input.secret !== undefined;
      const hasSha256 = input.secretSha256 !== undefined;
      let secret: { plain: string } | { sha256: string } | null = null;
      if (authMethod === "none") {
        if (hasSecret || hasSha256) {
          throw new InvalidArgumentError("a public client (authMethod none) has no secret");
        }
      } else {
        if (hasSecret === hasSha256) {
          throw new InvalidArgumentError(
            "a confidential client needs exactly one of secret and secretSha256",
          );
        }
        if (hasSecret) {
          const plain = input.secret;
          if (typeof plain !== "string" || plain === "" || plain.length > MAX_SECRET_LENGTH) {
            throw new InvalidArgumentError(`secret must be 1 to ${MAX_SECRET_LENGTH} characters`);
          }
          secret = { plain };
        } else {
          if (!settings.acceptLegacyClientSecrets) {
            throw new NotConfiguredError("oauth.acceptLegacyClientSecrets");
          }
          const hex =
            typeof input.secretSha256 === "string" ? input.secretSha256.toLowerCase() : "";
          if (!SHA256_HEX.test(hex)) {
            throw new InvalidArgumentError("secretSha256 must be 64 hex characters");
          }
          secret = { sha256: hex };
        }
      }

      const algorithm = secret === null ? null : "plain" in secret ? "hmac-sha256" : "sha256";
      const record: OAuthClientRecord = {
        id,
        secretDigest:
          secret === null
            ? null
            : "plain" in secret
              ? await hasher.digest("oauth-client-secret", secret.plain)
              : secret.sha256,
        secretDigestAlgorithm: algorithm,
        authMethod,
        grantTypes,
        redirectUris,
        name,
        source: "import",
        createdAt,
        lastUsedAt,
      };
      const existing = await store.findClient(id);
      if (existing) {
        return (await sameClient(existing, record, secret))
          ? { status: "already_imported", client: toClientView(existing) }
          : { status: "id_taken" };
      }
      // A deleted imported client never comes back. The insert checks the tombstone once more,
      // atomically with a concurrent delete.
      if (await store.findImportTombstone("client", id)) return { status: "revoked" };
      const inserted = await store.insertClient(record);
      if (inserted === "revoked") return { status: "revoked" };
      if (inserted !== "inserted") {
        // Inserted by a concurrent call between the read and the insert.
        const raced = await store.findClient(id);
        return raced && (await sameClient(raced, record, secret))
          ? { status: "already_imported", client: toClientView(raced) }
          : { status: "id_taken" };
      }
      try {
        await ctx.emit({
          type: "oauth.client_imported",
          clientId: id,
          method: authMethod,
          reason: algorithm ?? "none",
        });
      } catch (error) {
        // No client stands without its audit record. The delete writes no tombstone: for the
        // audit trail the import did not happen, so a retry may import it. If the delete fails,
        // its error goes up and the client stands without its record.
        await store.rollBackImport("client", id);
        throw new OAuthClientRolledBackError(id, { cause: error });
      }
      return { status: "imported", client: toClientView(record) };
    },

    async importGrant(input: ImportOAuthGrantInput): Promise<ImportOAuthGrantResult> {
      if (typeof input !== "object" || input === null) {
        throw new InvalidArgumentError("importGrant needs an input object");
      }
      const id = requireId(input.id, "id");
      if (!GRANT_ID.test(id)) {
        throw new InvalidArgumentError("id must be 1 to 128 visible ASCII characters");
      }
      const accountId = requireId(input.accountId, "accountId");
      const clientId = requireId(input.clientId, "clientId");
      const scopes = stringList(input.scopes, "scopes");
      if (scopes.length === 0 || !scopes.every((s) => knownScopes.has(s))) {
        throw new InvalidArgumentError("scopes must name default or opt-in scopes, at least one");
      }
      if (typeof input.resource !== "string" || !settings.resources.includes(input.resource)) {
        throw new InvalidArgumentError("resource must be one of the configured resources");
      }
      const resource = input.resource;
      if (!Number.isSafeInteger(input.generation) || input.generation < 1) {
        throw new InvalidArgumentError("generation must be an integer of 1 or more");
      }
      const now = clock.now();
      const createdAt = requireDate(input.createdAt, "createdAt");
      const expiresAt = requireDate(input.expiresAt, "expiresAt");
      const refreshExpiresAt = requireDate(input.refreshExpiresAt, "refreshExpiresAt");
      const refreshedAt =
        input.refreshedAt === undefined || input.refreshedAt === null
          ? null
          : requireDate(input.refreshedAt, "refreshedAt");
      if (createdAt.getTime() > now.getTime()) {
        throw new InvalidArgumentError("createdAt must not be in the future");
      }
      if (expiresAt.getTime() <= createdAt.getTime()) {
        throw new InvalidArgumentError("expiresAt must be after createdAt");
      }
      if (refreshExpiresAt.getTime() > expiresAt.getTime()) {
        throw new InvalidArgumentError("refreshExpiresAt must not be after expiresAt");
      }
      if (
        refreshedAt !== null &&
        (refreshedAt.getTime() > now.getTime() || refreshedAt.getTime() < createdAt.getTime())
      ) {
        throw new InvalidArgumentError("refreshedAt must be between createdAt and now");
      }
      const hex = typeof input.refreshSha256 === "string" ? input.refreshSha256.toLowerCase() : "";
      if (!SHA256_HEX.test(hex)) {
        throw new InvalidArgumentError("refreshSha256 must be 64 hex characters");
      }

      /** The result for a grant with this id that exists already, or that ended since. */
      const existingResult = async (): Promise<ImportOAuthGrantResult> => {
        const found = await store.findGrant(id);
        if (!found && (await store.findImportTombstone("grant", id))) return { status: "revoked" };
        const grant = found?.grant;
        // The same grant, also after identkit rotated it since the import.
        return grant &&
          grant.source === "import" &&
          grant.accountId === accountId &&
          grant.clientId === clientId &&
          grant.resource === resource &&
          sameList(grant.scopes, scopes)
          ? { status: "already_imported" }
          : { status: "id_taken" };
      };
      if (await store.findGrant(id)) return existingResult();
      // An ended imported grant never comes back: its legacy refresh token would work again.
      // The store checks the tombstone once more, atomically with a concurrent end.
      if (await store.findImportTombstone("grant", id)) return { status: "revoked" };
      const account = await ctx.store.accounts.findById(accountId);
      if (!account) return { status: "no_account" };
      if (account.status !== "active") return { status: "account_disabled" };
      if (!(await store.findClient(clientId))) return { status: "no_client" };
      if (expiresAt.getTime() <= now.getTime()) return { status: "expired" };

      const grant: OAuthGrantRecord = {
        id,
        accountId,
        clientId,
        scopes,
        resource,
        createdAt,
        expiresAt,
        generation: input.generation,
        // The ref comes with the first rotation, which issues an identkit refresh token.
        refreshRefDigest: null,
        refreshDigest: hex,
        refreshDigestAlgorithm: "sha256",
        previousRefreshDigest: null,
        refreshedAt,
        refreshExpiresAt,
        codeDigest: null,
        source: "import",
      };
      const inserted = await store.importGrant(grant, {
        maxOtherGrants: settings.maxGrantsPerAccount,
        at: now,
      });
      if (inserted === "id_taken") return existingResult();
      if (inserted === "account_inactive") return { status: "account_disabled" };
      if (inserted === "revoked") return { status: "revoked" };
      if (inserted !== "inserted") return { status: inserted };
      try {
        await ctx.emit({
          type: "oauth.grant_imported",
          accountId,
          clientId,
          grantId: id,
          scopes: [...scopes],
          method: "sha256",
        });
      } catch (error) {
        // No grant stands without its audit record. The delete writes no tombstone: for the
        // audit trail the import did not happen, so a retry may import it. If the delete fails,
        // its error goes up and the grant stands without its record.
        await store.rollBackImport("grant", id);
        throw new OperationRolledBackError(accountId, { cause: error, hookFailed: false });
      }
      return { status: "imported" };
    },
  };
}
