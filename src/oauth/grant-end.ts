import type { Context } from "../context.js";
import type { OAuthGrantRecord } from "../storage/types.js";

/** Why a grant ended, in `oauth.grant_ended`. */
export type OAuthGrantEndReason =
  | "revoked_by_client"
  | "revoked"
  | "revoked_all"
  | "client_deleted"
  | "account_disabled"
  | "replaced"
  | "code_reuse"
  | "refresh_reuse"
  | "expired";

/**
 * Ends every OAuth grant of the account, and its codes, if the store has OAuth, also when the
 * `oauth` option is not set (grants from an earlier configuration must end too). Returns the
 * ended grants.
 */
export async function endAllOAuthGrants(
  ctx: Context,
  accountId: string,
): Promise<OAuthGrantRecord[]> {
  const store = ctx.store.oauth;
  if (!store) return [];
  return store.deleteGrantsForAccount(accountId);
}

/**
 * Records `oauth.grant_ended` for each grant. A throwing sink does not skip the other events;
 * the first error goes up after all of them.
 */
export async function emitOAuthGrantsEnded(
  ctx: Context,
  accountId: string,
  grants: readonly OAuthGrantRecord[],
  reason: OAuthGrantEndReason,
): Promise<void> {
  let failure: { error: unknown } | null = null;
  for (const grant of grants) {
    try {
      await ctx.emit({
        type: "oauth.grant_ended",
        accountId,
        clientId: grant.clientId,
        grantId: grant.id,
        reason,
      });
    } catch (error) {
      failure ??= { error };
    }
  }
  if (failure) throw failure.error;
}
