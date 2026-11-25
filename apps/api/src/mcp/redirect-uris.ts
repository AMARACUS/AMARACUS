/**
 * Which redirect URIs an OAuth client may register and use.
 *
 * - https:// anywhere (hosted apps such as ChatGPT and Claude).
 * - http:// on the loopback interface only, on any port (RFC 8252 section 7.3, native apps).
 * - The private URI schemes of known editors.
 */
const EDITOR_SCHEMES = new Set(['cursor:', 'vscode:', 'vscode-insiders:', 'windsurf:', 'zed:', 'kiro:', 'trae:']);
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

function parse(uri: unknown): URL | null {
  if (typeof uri !== 'string' || uri.length > 1024) return null;
  try {
    return new URL(uri);
  } catch {
    return null;
  }
}

export function isLoopbackRedirect(uri: string): boolean {
  const u = parse(uri);
  return !!u && u.protocol === 'http:' && LOOPBACK_HOSTS.has(u.hostname);
}

export function isAllowedRedirectUri(uri: unknown): uri is string {
  const u = parse(uri);
  if (!u || u.hash || u.username || u.password) return false;
  if (u.protocol === 'https:') return true;
  if (u.protocol === 'http:') return LOOPBACK_HOSTS.has(u.hostname);
  return EDITOR_SCHEMES.has(u.protocol);
}

/** Exact match, except that the port of a loopback redirect is ignored. */
export function redirectUriMatches(registered: string[], requested: string): boolean {
  if (registered.includes(requested)) return true;
  if (!isLoopbackRedirect(requested)) return false;
  const want = new URL(requested);
  return registered.some((r) => {
    if (!isLoopbackRedirect(r)) return false;
    const have = new URL(r);
    return have.hostname === want.hostname && have.pathname === want.pathname && have.search === want.search;
  });
}

/** What the consent page shows as the destination. */
export function redirectDestination(uri: string): string {
  const u = new URL(uri);
  if (u.protocol === 'https:') return u.host;
  if (u.protocol === 'http:') return `an app on this computer (${u.hostname})`;
  return `the ${u.protocol.replace(':', '')} app on this computer`;
}
