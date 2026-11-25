/**
 * A path on this site to go to after sign-in, or null. Anything that could leave the site
 * (another origin, "//host", "/\host", a javascript: URL) is refused.
 */
export function safeRedirectPath(value: string | null | undefined): string | null {
  if (!value || !value.startsWith('/')) return null;
  try {
    const base = 'https://redirect.invalid';
    const url = new URL(value, base);
    return url.origin === base ? url.pathname + url.search + url.hash : null;
  } catch {
    return null;
  }
}
