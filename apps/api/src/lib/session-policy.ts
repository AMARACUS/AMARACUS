/**
 * Console session lifetime: a sliding 30-day idle window.
 *
 * A session stays valid as long as it is used at least once every 30 days; each
 * authenticated request pushes the expiry back to 30 days from now. Signing out
 * deletes the session immediately.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

export const SESSION_IDLE_TTL_MS = 30 * DAY_MS;

// Extend at most once a day, so active users don't cause a database write per request.
export const SESSION_REFRESH_INTERVAL_MS = DAY_MS;

export function sessionExpiryFrom(now: number = Date.now()): Date {
  return new Date(now + SESSION_IDLE_TTL_MS);
}

/** True when the session was last extended more than a refresh interval ago. */
export function shouldExtendSession(expiresAt: Date, now: number = Date.now()): boolean {
  return new Date(expiresAt).getTime() - now < SESSION_IDLE_TTL_MS - SESSION_REFRESH_INTERVAL_MS;
}
