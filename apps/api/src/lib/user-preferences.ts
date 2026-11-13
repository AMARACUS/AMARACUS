import { prisma } from '@amaracus/database';
import { isTestEnv } from './runtime-config';

export interface UserPreferences {
  marketingEmails: boolean;
  securityAlertsOnly: boolean;
  telemetryOptIn: boolean;
  cookieConsentStatus: string;
  updatedAt: string;
}

/**
 * A user's email and privacy choices. Outside tests they are stored in the
 * user_communication_preference table, so a marketing opt-in or opt-out survives restarts and
 * deploys. The test suite has no database, so it uses this map instead (the same split as
 * DataStore's memory mode).
 */
const memoryStore = new Map<string, UserPreferences>();

function defaults(): UserPreferences {
  return {
    marketingEmails: false, // Marketing email needs an explicit opt-in
    securityAlertsOnly: true, // Security alerts and key lifecycle notices cannot be turned off
    telemetryOptIn: true,
    cookieConsentStatus: 'essential_only',
    updatedAt: new Date().toISOString(),
  };
}

function fromRow(row: { marketingEmails: boolean; telemetryOptIn: boolean; cookieConsentStatus: string; updatedAt: Date }): UserPreferences {
  return {
    marketingEmails: row.marketingEmails,
    securityAlertsOnly: true,
    telemetryOptIn: row.telemetryOptIn,
    cookieConsentStatus: row.cookieConsentStatus,
    updatedAt: row.updatedAt.toISOString(),
  };
}

/** The user's preferences, or the defaults (no marketing email) if none were saved. */
export async function getUserPreferences(userId: string): Promise<UserPreferences> {
  if (isTestEnv()) {
    return { ...(memoryStore.get(userId) || defaults()) };
  }
  const row = await prisma.userCommunicationPreference.findUnique({ where: { userId } });
  return row ? fromRow(row) : defaults();
}

/** Saves a change to the user's preferences and returns the full result. */
export async function setUserPreferences(userId: string, prefs: Partial<UserPreferences>): Promise<UserPreferences> {
  const current = await getUserPreferences(userId);
  const updated: UserPreferences = {
    ...current,
    ...prefs,
    securityAlertsOnly: true, // Essential for contractual compliance & incident notification
    updatedAt: new Date().toISOString(),
  };
  if (isTestEnv()) {
    memoryStore.set(userId, updated);
    return { ...updated };
  }
  const data = {
    marketingEmails: updated.marketingEmails,
    telemetryOptIn: updated.telemetryOptIn,
    cookieConsentStatus: updated.cookieConsentStatus,
  };
  const row = await prisma.userCommunicationPreference.upsert({
    where: { userId },
    create: { userId, ...data },
    update: data,
  });
  return fromRow(row);
}

/** Deletes the user's preferences (account deletion; the row also goes with the user by cascade). */
export async function clearUserPreferences(userId: string): Promise<void> {
  if (isTestEnv()) {
    memoryStore.delete(userId);
    return;
  }
  await prisma.userCommunicationPreference.deleteMany({ where: { userId } });
}
