/**
 * Rules for redirect URIs: what a registration may name, and which requested URI matches a
 * registered one. The registered string must equal its normalized form, so a URI that two
 * parsers could read differently (case, encoding, dot segments, default ports, Unicode hosts)
 * never gets in. Punycode hosts (a label that starts with `xn--`) are refused too.
 */

/** Visible ASCII only: no white space, no control characters, no Unicode. */
const VISIBLE_ASCII = /^[\x21-\x7e]+$/;
/** A host name or IPv4 address after parsing. */
const HOST = /^[a-z0-9.-]+$/;
/** A private-use scheme of RFC 8252 section 7.1: reverse domain name, with a dot. */
const PRIVATE_USE_SCHEME = /^[a-z][a-z0-9+-]*(\.[a-z0-9+-]+)+:$/;

export interface RedirectUriRules {
  maxLength: number;
  allowIpv6Loopback: boolean;
  allowPrivateUseSchemes: boolean;
}

/** `localhost` and `127.0.0.1`, plus `[::1]` if allowed. A loopback URI ignores its port. */
function isLoopbackHost(hostname: string, rules: RedirectUriRules): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    (rules.allowIpv6Loopback && hostname === "[::1]")
  );
}

/**
 * The normalized form of a URL as the WHATWG parser writes it. For an origin-only URL the
 * parser adds `/`; a registration may leave it out.
 */
function sameAsNormalized(raw: string, url: URL): boolean {
  if (raw === url.href) return true;
  return url.pathname === "/" && url.search === "" && !raw.includes("?") && `${raw}/` === url.href;
}

/** Parses a redirect URI that passes every rule, or returns null. */
export function parseRedirectUri(raw: unknown, rules: RedirectUriRules): URL | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > rules.maxLength) return null;
  if (!VISIBLE_ASCII.test(raw) || raw.includes("#") || raw.includes("\\")) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.username !== "" || url.password !== "" || url.hash !== "") return null;
  if (!sameAsNormalized(raw, url)) return null;
  if (url.protocol === "https:" || url.protocol === "http:") {
    if (url.hostname === "") return null;
    const ipv6 = rules.allowIpv6Loopback && url.hostname === "[::1]";
    if (!ipv6 && !HOST.test(url.hostname)) return null;
    // A host of dots only, or with an empty label, is no host. A punycode label (`xn--`) can
    // spell a host that looks like another one (homograph), so it is refused.
    if (
      !ipv6 &&
      url.hostname.split(".").some((label) => label === "" || label.startsWith("xn--"))
    ) {
      return null;
    }
    if (url.protocol === "http:" && !isLoopbackHost(url.hostname, rules)) return null;
    return url;
  }
  if (rules.allowPrivateUseSchemes && PRIVATE_USE_SCHEME.test(url.protocol) && url.host === "") {
    return url;
  }
  return null;
}

/** True if the URI is a valid loopback redirect URI, whose port a request may change. */
function isLoopbackUri(url: URL, rules: RedirectUriRules): boolean {
  return url.protocol === "http:" && isLoopbackHost(url.hostname, rules);
}

/**
 * The registered redirect URI that a request names, or null. With no `requested` value, the
 * client must have exactly one registered URI. Otherwise the requested string must equal a
 * registered one; for a loopback registration (`http` on `localhost`, `127.0.0.1` or, if
 * allowed, `[::1]`) the port may differ (RFC 8252 section 7.3), but the scheme, host, path and
 * query must match. `localhost` and `127.0.0.1` never match each other. Returns the URI to send
 * the response to: the requested string, or the registered one if none was requested. Both
 * must pass the current rules.
 */
export function matchRedirectUri(
  registered: readonly string[],
  requested: string | null,
  rules: RedirectUriRules,
): string | null {
  if (requested === null) {
    const [only, ...others] = registered;
    if (only === undefined || others.length > 0) return null;
    return parseRedirectUri(only, rules) ? only : null;
  }
  // Checked again also for an exact match: the rules may be stricter than at registration.
  const url = parseRedirectUri(requested, rules);
  if (!url) return null;
  if (registered.includes(requested)) return requested;
  if (!isLoopbackUri(url, rules)) return null;
  for (const candidate of registered) {
    const known = parseRedirectUri(candidate, rules);
    if (
      known &&
      isLoopbackUri(known, rules) &&
      known.hostname === url.hostname &&
      known.pathname === url.pathname &&
      known.search === url.search
    ) {
      return requested;
    }
  }
  return null;
}
