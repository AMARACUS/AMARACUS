import { db } from './data-store';
import { sendSecurityAlertEmail } from './email-service';

/**
 * Watches decrypts per caller. When one API key (or user) decrypts more than the alert level in a
 * rolling hour, a stolen key reading a stolen database is the likely cause
 * (docs/recovery/breach-drill-2026-11.md), so:
 *   - a security.decrypt_spike audit entry is written and owners and admins are emailed, at most
 *     once a day per caller;
 *   - an API key is also locked straight away (status DISABLED) and a security.key_auto_locked entry
 *     is written, unless DECRYPT_AUTO_LOCK=0. The lock takes effect on the very next request: it is
 *     held in memory as well as saved, so the background database write cannot be overtaken.
 *     An owner unlocks it with "Enable" in the console (POST /v1/credentials/:id/enable).
 *
 * Counts live in this process's memory and restart from zero when the API restarts.
 * DECRYPT_ALERT_PER_HOUR sets the level (default 1,000 decrypts in an hour).
 */
const WINDOW_MS = 60 * 60 * 1000;
const REALERT_MS = 24 * 60 * 60 * 1000;

interface Counter {
  windowStart: number;
  count: number;
  alertedAt?: number;
}

const counters = new Map<string, Counter>();
const lockedKeys = new Set<string>();

export function decryptAlertThreshold(): number {
  const configured = Number(process.env.DECRYPT_ALERT_PER_HOUR);
  return Number.isFinite(configured) && configured > 0 ? configured : 1000;
}

export function decryptAutoLockEnabled(): boolean {
  const v = (process.env.DECRYPT_AUTO_LOCK || '').trim().toLowerCase();
  return !(v === '0' || v === 'false' || v === 'off');
}

/** True when this API key was locked for a decrypt spike and has not been enabled again. */
export function isKeyAutoLocked(credentialId: string): boolean {
  return lockedKeys.has(credentialId);
}

/** Called when an owner enables the key again: lifts the lock and starts its count afresh. */
export function clearAutoLock(credentialId: string): void {
  lockedKeys.delete(credentialId);
  for (const id of Array.from(counters.keys())) {
    if (id.endsWith(`:${credentialId}`)) counters.delete(id);
  }
}

/** Test helper. */
export function resetDecryptAlertCounters(): void {
  counters.clear();
  lockedKeys.clear();
}

/**
 * Records one successful decrypt. Everything up to the lock decision runs synchronously, before
 * the first await, so a key over the level is refused from the next request on.
 * Resolves to true when this call crossed the level and an alert was raised.
 */
export async function noteDecrypt(event: {
  organizationId?: string | null;
  actorId?: string | null;
  ipAddress?: string;
  /** Set when the caller authenticated with this API key (so it can be locked). */
  isApiKey?: boolean;
}): Promise<boolean> {
  if (!event.organizationId || !event.actorId) return false;
  const id = `${event.organizationId}:${event.actorId}`;
  const now = Date.now();
  let c = counters.get(id);
  if (!c || now - c.windowStart > WINDOW_MS) {
    c = { windowStart: now, count: 0, alertedAt: c?.alertedAt };
    counters.set(id, c);
  }
  c.count++;

  const threshold = decryptAlertThreshold();
  if (c.count < threshold) return false;
  if (c.alertedAt && now - c.alertedAt < REALERT_MS) return false;
  c.alertedAt = now;

  const lock = Boolean(event.isApiKey) && decryptAutoLockEnabled();
  if (lock) lockedKeys.add(event.actorId);

  const credential = event.isApiKey ? await db.findCredentialById(event.actorId).catch(() => null) : null;
  const who = credential ? `API key "${credential.name}" (${credential.prefix}…)` : `account ${event.actorId}`;
  const what = `${who} decrypted ${c.count} values in the last hour, above your alert level of ${threshold}. ` +
    `Last request from IP ${event.ipAddress || 'unknown'}.`;
  const details = lock
    ? `${what} The key has been locked automatically, so it can no longer be used. If this was you, ` +
      `open the console, API Keys, and press Enable on the key (consider limiting it to your server's IPs ` +
      `first). If not, revoke it and create a new one, then check the audit log for crypto.decrypt events.`
    : `${what} If you did not expect this, revoke the key in the console (API Keys) now, then check the ` +
      `audit log for crypto.decrypt events.`;

  if (lock) {
    await db.updateCredentialStatus(event.actorId, 'DISABLED').catch((err) =>
      console.error('[DecryptAlerts] Saving the key lock failed (it still holds in memory):', err?.message || err)
    );
  }

  await db.createAuditEvent({
    organizationId: event.organizationId,
    userId: event.actorId,
    action: 'security.decrypt_spike',
    resourceType: event.isApiKey ? 'ApiCredential' : 'User',
    resourceId: event.actorId,
    metadata: { decryptsInLastHour: c.count, threshold, locked: lock, keyName: credential?.name, keyPrefix: credential?.prefix },
    ipAddress: event.ipAddress,
  });
  if (lock) {
    await db.createAuditEvent({
      organizationId: event.organizationId,
      userId: event.actorId,
      action: 'security.key_auto_locked',
      resourceType: 'ApiCredential',
      resourceId: event.actorId,
      metadata: { reason: 'decrypt_spike', decryptsInLastHour: c.count, threshold, keyName: credential?.name },
      ipAddress: event.ipAddress,
    });
  }

  const members = await db.getOrgMembers(event.organizationId).catch(() => []);
  const recipients = members.filter((m) => m.role === 'OWNER' || m.role === 'ADMIN').map((m) => m.user.email);
  for (const toEmail of new Set(recipients)) {
    await sendSecurityAlertEmail({
      toEmail,
      alertTitle: lock
        ? 'An AMARACUS API key was locked after unusual decrypts'
        : 'Unusual number of decrypts on your AMARACUS account',
      alertDetails: details,
      severity: lock ? 'CRITICAL' : 'HIGH',
    }).catch((err) => console.error('[DecryptAlerts] Alert email failed:', err?.message || err));
  }
  return true;
}
