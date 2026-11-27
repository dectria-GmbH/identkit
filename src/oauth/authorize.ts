import { toAccountView } from "../accounts.js";
import { addSeconds } from "../clock.js";
import { randomToken } from "../crypto.js";
import { InvalidArgumentError } from "../errors.js";
import { utf8 } from "../bytes.js";
import { isRecord } from "../oidc-jwt.js";
import type { OAuthClientRecord } from "../storage/types.js";
import {
  admits,
  CLIENT_ID,
  duplicateNames,
  orderedScopes,
  readParams,
  requireId,
  toClientView,
  type OAuthInternals,
  type OAuthParams,
} from "./common.js";
import { matchRedirectUri, type RedirectUriRules } from "./redirect-uris.js";

/** Context string of the sealed consent ticket. A value sealed for anything else does not open. */
const TICKET_CONTEXT = "identkit/oauth/consent/v1";
const MAX_TICKET_LENGTH = 8192;
const MAX_STATE_LENGTH = 1024;
/** RFC 7636 section 4.2: 43 to 128 unreserved characters. */
const CODE_CHALLENGE = /^[A-Za-z0-9._~-]{43,128}$/;

/**
 * Why an authorization request is invalid. Render it on your own page: identkit never sends an
 * authorization error to the client's redirect URI (RFC 9700 section 4.11.2).
 */
export type AuthorizeError =
  | "invalid_request"
  | "invalid_client"
  | "invalid_redirect_uri"
  | "unauthorized_client"
  | "unsupported_response_type"
  | "invalid_target";

export type AuthorizeRefusal = "no_account" | "account_disabled" | "refused_by_policy";

export type AuthorizeBeginResult =
  | {
      /**
       * Show the consent page. Put `ticket` into a hidden field of the approve and deny form; it
       * is bound to the account and sealed, so it also works as the form's CSRF token.
       */
      status: "consent";
      ticket: string;
      expiresAt: Date;
      /** `name` is text the client chose: escape it for HTML. */
      client: { id: string; name: string | null; redirectUri: string };
      resource: string;
      /** The default scopes, always granted. */
      scopes: string[];
      /** The opt-in scopes; offer them unticked. You decide which ones the page shows. */
      optInScopes: string[];
      /** The opt-in scopes named in the request's `scope`. */
      requestedOptInScopes: string[];
    }
  | { status: "invalid"; error: AuthorizeError; description: string }
  | { status: "refused"; reason: AuthorizeRefusal };

export type AuthorizeDecisionResult =
  /** Redirect the browser to `location` (HTTP 303 after the form POST). */
  | { status: "redirect"; location: string }
  /** Render on your page, never redirect. */
  | {
      status: "invalid";
      error: "invalid_ticket" | "ticket_expired" | "account_mismatch";
      description: string;
    }
  | { status: "refused"; reason: AuthorizeRefusal };

export interface OAuthAuthorize {
  /**
   * Checks an authorization request. Call it with the account of the signed-in session; without
   * a session, send the browser to your sign-in first, with the full request URL as the return
   * target. Pass the query as `URLSearchParams`, so identkit can refuse repeated parameters.
   * The request's `scope` only marks opt-in scopes as requested; the consent decides.
   */
  begin(input: { params: OAuthParams; accountId: string }): Promise<AuthorizeBeginResult>;
  /**
   * The person approved. `optInScopes` are the opt-in scopes they ticked; a scope outside the
   * option `optInScopes` throws `InvalidArgumentError`. Stores a single-use code and returns the
   * redirect to the client, with `code`, `state` and `iss`.
   */
  approve(input: {
    ticket: string;
    accountId: string;
    optInScopes?: string[];
  }): Promise<AuthorizeDecisionResult>;
  /** The person denied. Returns the redirect with `error=access_denied`, `state` and `iss`. */
  deny(input: { ticket: string; accountId: string }): Promise<AuthorizeDecisionResult>;
}

interface Ticket {
  accountId: string;
  clientId: string;
  redirectUri: string;
  /** True if the request named `redirect_uri`. */
  redirectUriExplicit: boolean;
  codeChallenge: string;
  resource: string;
  state: string | null;
  requestedOptIn: string[];
  expiresAt: number;
}

function parseTicket(bytes: Uint8Array): Ticket | null {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
  if (!isRecord(value) || value["v"] !== 1) return null;
  const { a, c, r, re, p, s, st, o, x } = value;
  if (
    typeof a !== "string" ||
    typeof c !== "string" ||
    typeof r !== "string" ||
    typeof re !== "boolean" ||
    typeof p !== "string" ||
    typeof s !== "string" ||
    (st !== null && typeof st !== "string") ||
    !Array.isArray(o) ||
    !o.every((item) => typeof item === "string") ||
    typeof x !== "number"
  ) {
    return null;
  }
  return {
    accountId: a,
    clientId: c,
    redirectUri: r,
    redirectUriExplicit: re,
    codeChallenge: p,
    resource: s,
    state: st,
    requestedOptIn: o,
    expiresAt: x,
  };
}

/** Appends the parameters to the redirect URI and keeps its query as it is (RFC 6749 3.1.2). */
function redirectTo(uri: string, values: Record<string, string | null>): string {
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(values)) {
    if (value !== null) query.set(name, value);
  }
  const separator = uri.includes("?") ? (uri.endsWith("?") || uri.endsWith("&") ? "" : "&") : "?";
  return `${uri}${separator}${query.toString()}`;
}

const invalid = (error: AuthorizeError, description: string): AuthorizeBeginResult => ({
  status: "invalid",
  error,
  description,
});

export function redirectRules(internals: OAuthInternals): RedirectUriRules {
  const { registration, redirectUris } = internals.settings;
  return {
    maxLength: registration.maxRedirectUriLength,
    allowIpv6Loopback: redirectUris.allowIpv6Loopback,
    allowPrivateUseSchemes: redirectUris.allowPrivateUseSchemes,
  };
}

export function createAuthorize(internals: OAuthInternals): OAuthAuthorize {
  const { ctx, settings, store, sealer } = internals;
  const rules = redirectRules(internals);

  async function openTicket(sealed: unknown): Promise<Ticket | null> {
    if (typeof sealed !== "string" || sealed.length === 0 || sealed.length > MAX_TICKET_LENGTH) {
      return null;
    }
    try {
      return parseTicket(await sealer.open(sealed, TICKET_CONTEXT));
    } catch {
      return null;
    }
  }

  /** The account must exist and be active. */
  async function account(accountId: string) {
    const found = await ctx.store.accounts.findById(accountId);
    if (!found) return { refused: "no_account" as const };
    if (found.status !== "active") return { refused: "account_disabled" as const };
    return { account: found };
  }

  /** The ticket of a decision, checked against the time and the account, or the reason. */
  async function decisionTicket(
    input: unknown,
  ): Promise<{ ticket: Ticket; accountId: string } | AuthorizeDecisionResult> {
    if (!isRecord(input)) throw new InvalidArgumentError("needs { ticket, accountId }");
    const accountId = requireId(input["accountId"], "accountId");
    const ticket = await openTicket(input["ticket"]);
    if (!ticket) {
      return { status: "invalid", error: "invalid_ticket", description: "The request is invalid." };
    }
    if (ctx.clock.now().getTime() >= ticket.expiresAt) {
      return {
        status: "invalid",
        error: "ticket_expired",
        description: "The request has expired. Start again from the application.",
      };
    }
    if (ticket.accountId !== accountId) {
      return {
        status: "invalid",
        error: "account_mismatch",
        description: "The request belongs to another sign-in.",
      };
    }
    return { ticket, accountId };
  }

  return {
    async begin(input) {
      if (!isRecord(input)) throw new InvalidArgumentError("begin needs { params, accountId }");
      const accountId = requireId(input.accountId, "accountId");
      const params = readParams(input.params);
      if (!params) {
        return duplicateNames(input.params).has("resource")
          ? invalid("invalid_target", "Only one resource may be requested.")
          : invalid("invalid_request", "A parameter was sent more than once or is malformed.");
      }
      const clientId = params.get("client_id");
      if (clientId === undefined || !CLIENT_ID.test(clientId)) {
        return invalid("invalid_request", "client_id is missing or malformed.");
      }
      const client: OAuthClientRecord | null = await store.findClient(clientId);
      if (!client) return invalid("invalid_client", "The client is not registered.");
      const requestedRedirectUri = params.get("redirect_uri") ?? null;
      const redirectUri = matchRedirectUri(client.redirectUris, requestedRedirectUri, rules);
      if (redirectUri === null) {
        return invalid(
          "invalid_redirect_uri",
          "The redirect URI is not registered for the client.",
        );
      }
      if (!client.grantTypes.includes("authorization_code")) {
        return invalid(
          "unauthorized_client",
          "The client may not use the authorization code grant.",
        );
      }
      const responseType = params.get("response_type");
      if (responseType === undefined)
        return invalid("invalid_request", "response_type is missing.");
      if (responseType !== "code") {
        return invalid("unsupported_response_type", "Only response_type=code is supported.");
      }
      if (params.get("code_challenge_method") !== "S256") {
        return invalid("invalid_request", "PKCE with code_challenge_method=S256 is required.");
      }
      const codeChallenge = params.get("code_challenge");
      if (codeChallenge === undefined || !CODE_CHALLENGE.test(codeChallenge)) {
        return invalid("invalid_request", "code_challenge is missing or malformed.");
      }
      const state = params.get("state") ?? null;
      if (state !== null && state.length > MAX_STATE_LENGTH) {
        return invalid("invalid_request", "state is too long.");
      }
      const resource = params.get("resource") ?? settings.resources[0] ?? "";
      if (!settings.resources.includes(resource)) {
        return invalid("invalid_target", "The resource is not served by this server.");
      }
      const named = (params.get("scope") ?? "").split(" ");
      const requestedOptIn = settings.optInScopes.filter((s) => named.includes(s));

      const checked = await account(accountId);
      if ("refused" in checked) return { status: "refused", reason: checked.refused };
      const allowed = await admits(internals, {
        phase: "authorize",
        account: toAccountView(checked.account),
        client: toClientView(client),
        scopes: orderedScopes(settings, requestedOptIn),
      });
      if (!allowed) return { status: "refused", reason: "refused_by_policy" };

      const expiresAt = addSeconds(ctx.clock.now(), settings.consentSeconds);
      const ticket = await sealer.seal(
        utf8(
          JSON.stringify({
            v: 1,
            a: accountId,
            c: client.id,
            r: redirectUri,
            re: requestedRedirectUri !== null,
            p: codeChallenge,
            s: resource,
            st: state,
            o: requestedOptIn,
            x: expiresAt.getTime(),
          }),
        ),
        TICKET_CONTEXT,
      );
      return {
        status: "consent",
        ticket,
        expiresAt,
        client: { id: client.id, name: client.name, redirectUri },
        resource,
        scopes: [...settings.defaultScopes],
        optInScopes: [...settings.optInScopes],
        requestedOptInScopes: requestedOptIn,
      };
    },

    async approve(input) {
      const optIn: unknown = isRecord(input) ? (input["optInScopes"] ?? []) : [];
      if (
        !Array.isArray(optIn) ||
        !optIn.every((s) => typeof s === "string" && settings.optInScopes.includes(s)) ||
        new Set(optIn).size !== optIn.length
      ) {
        throw new InvalidArgumentError("optInScopes must name opt-in scopes, each once");
      }
      const decided = await decisionTicket(input);
      if ("status" in decided) return decided;
      const { ticket, accountId } = decided;
      const checked = await account(accountId);
      if ("refused" in checked) return { status: "refused", reason: checked.refused };
      // The client may be gone, or its redirect URIs changed, since the consent page opened.
      const client = await store.findClient(ticket.clientId);
      if (!client || matchRedirectUri(client.redirectUris, ticket.redirectUri, rules) === null) {
        return {
          status: "invalid",
          error: "invalid_ticket",
          description: "The request is invalid.",
        };
      }
      const scopes = orderedScopes(settings, optIn);
      // Asked again: the policy may have changed while the consent page was open.
      const allowed = await admits(internals, {
        phase: "authorize",
        account: toAccountView(checked.account),
        client: toClientView(client),
        scopes,
      });
      if (!allowed) return { status: "refused", reason: "refused_by_policy" };

      // The event before the code: no code stands without its record.
      await ctx.emit({
        type: "oauth.consent_approved",
        accountId,
        clientId: client.id,
        scopes: [...scopes],
      });
      const now = ctx.clock.now();
      const code = `${settings.prefixes.code}${randomToken()}`;
      await store.insertCode({
        digest: await ctx.hasher.digest("oauth-code", code),
        clientId: client.id,
        accountId,
        redirectUri: ticket.redirectUri,
        redirectUriExplicit: ticket.redirectUriExplicit,
        codeChallenge: ticket.codeChallenge,
        resource: ticket.resource,
        scopes,
        createdAt: now,
        expiresAt: addSeconds(now, settings.codeSeconds),
      });
      return {
        status: "redirect",
        location: redirectTo(ticket.redirectUri, {
          code,
          state: ticket.state,
          iss: settings.issuer,
        }),
      };
    },

    async deny(input) {
      const decided = await decisionTicket(input);
      if ("status" in decided) return decided;
      const { ticket, accountId } = decided;
      await ctx.emit({
        type: "oauth.consent_denied",
        accountId,
        clientId: ticket.clientId,
        scopes: orderedScopes(settings, ticket.requestedOptIn),
      });
      return {
        status: "redirect",
        location: redirectTo(ticket.redirectUri, {
          error: "access_denied",
          state: ticket.state,
          iss: settings.issuer,
        }),
      };
    },
  };
}
