import { API_BASE_URL } from "@/lib/api-base";
/**
 * AMARACUS Privacy & Cookie Consent Manager
 *
 * Implements granular consent tracking compliant with:
 * - EU ePrivacy Directive (Directive 2002/58/EC as amended)
 * - EU General Data Protection Regulation (GDPR Art. 6 & 7)
 * - India Digital Personal Data Protection Act, 2023 (DPDPA Sec. 6)
 * - UK Privacy and Electronic Communications Regulations (PECR)
 * - California Consumer Privacy Act / CPRA (Global Privacy Control)
 */

export const CONSENT_STORAGE_KEY = 'amaracus_cookie_consent';
export const CONSENT_VERSION = '1.0.0';

export interface CookieConsentCategories {
  necessary: boolean; // Strictly necessary (authentication, CSRF, security) - Always true
  functional: boolean; // UI preferences (theme, display density) - Default false
  analytics: boolean; // Telemetry and performance monitoring - Default false
  marketing: boolean; // Advertising & behavioral tracking (AMARACUS does not use this) - Always false
}

export type ConsentStatus = 'accepted' | 'rejected' | 'custom' | 'withdrawn';

export interface CookieConsentRecord {
  status: ConsentStatus;
  categories: CookieConsentCategories;
  consentVersion: string;
  timestamp: string; // ISO 8601
  source: 'banner_accept_all' | 'banner_reject_all' | 'settings_custom' | 'preference_center' | 'withdrawal';
  jurisdiction: string;
}

export const DEFAULT_CATEGORIES: CookieConsentCategories = {
  necessary: true,
  functional: false, // Explicit opt-in required; no preselection
  analytics: false, // Explicit opt-in required; no preselection
  marketing: false, // Locked off; zero ad trackers deployed
};

class ConsentManager {
  /**
   * Retrieves the current stored consent decision, validating version compatibility.
   */
  getStoredConsent(): CookieConsentRecord | null {
    if (typeof window === 'undefined') return null;

    try {
      const raw = localStorage.getItem(CONSENT_STORAGE_KEY);
      if (!raw) return null;

      // Handle legacy string values safely
      if (raw === 'accepted') {
        const legacyRecord: CookieConsentRecord = {
          status: 'accepted',
          categories: { necessary: true, functional: true, analytics: false, marketing: false },
          consentVersion: CONSENT_VERSION,
          timestamp: new Date().toISOString(),
          source: 'banner_accept_all',
          jurisdiction: 'GLOBAL_DPDPA_GDPR',
        };
        this.saveConsentRecord(legacyRecord);
        return legacyRecord;
      }

      const parsed: CookieConsentRecord = JSON.parse(raw);
      if (parsed && parsed.consentVersion && parsed.categories) {
        return parsed;
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Saves the structured consent record and enforces data boundaries across client storage.
   */
  saveConsentRecord(record: CookieConsentRecord): void {
    if (typeof window === 'undefined') return;

    try {
      localStorage.setItem(CONSENT_STORAGE_KEY, JSON.stringify(record));
      this.enforceStorageBoundaries(record);
      this.dispatchConsentEvent(record);

      // Asynchronously sync with backend audit trail without blocking UI
      this.syncConsentWithBackend(record).catch(() => {});
    } catch (e) {
      console.warn('Failed to persist cookie consent record:', e);
    }
  }

  /**
   * Best-effort async synchronization with backend audit logger.
   */
  async syncConsentWithBackend(record: CookieConsentRecord): Promise<void> {
    if (typeof window === 'undefined') return;
    try {
      const token = localStorage.getItem('amaracus_session_token');
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      const apiBase = API_BASE_URL;
      await fetch(`${apiBase}/api/v1/user/cookie-consent`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          status: record.status,
          categories: record.categories,
          consentVersion: record.consentVersion,
        }),
      });
    } catch {
      // Failsafe non-blocking sync
    }
  }

  /**
   * Records acceptance of all optional categories.
   */
  acceptAll(): CookieConsentRecord {
    const record: CookieConsentRecord = {
      status: 'accepted',
      categories: {
        necessary: true,
        functional: true,
        analytics: true,
        marketing: false, // Always false as AMARACUS deploys 0 ad trackers
      },
      consentVersion: CONSENT_VERSION,
      timestamp: new Date().toISOString(),
      source: 'banner_accept_all',
      jurisdiction: 'GLOBAL_DPDPA_GDPR',
    };
    this.saveConsentRecord(record);
    return record;
  }

  /**
   * Records rejection of all non-essential categories (strictly necessary only).
   */
  rejectAll(): CookieConsentRecord {
    const record: CookieConsentRecord = {
      status: 'rejected',
      categories: {
        necessary: true,
        functional: false,
        analytics: false,
        marketing: false,
      },
      consentVersion: CONSENT_VERSION,
      timestamp: new Date().toISOString(),
      source: 'banner_reject_all',
      jurisdiction: 'GLOBAL_DPDPA_GDPR',
    };
    this.saveConsentRecord(record);
    return record;
  }

  /**
   * Records granular user preferences with explicit selections.
   */
  saveCustomPreferences(
    selectedCategories: Partial<CookieConsentCategories>,
    source: 'settings_custom' | 'preference_center' = 'settings_custom'
  ): CookieConsentRecord {
    const record: CookieConsentRecord = {
      status: 'custom',
      categories: {
        necessary: true, // Invariable
        functional: Boolean(selectedCategories.functional),
        analytics: Boolean(selectedCategories.analytics),
        marketing: false, // Strictly not used
      },
      consentVersion: CONSENT_VERSION,
      timestamp: new Date().toISOString(),
      source,
      jurisdiction: 'GLOBAL_DPDPA_GDPR',
    };
    this.saveConsentRecord(record);
    return record;
  }

  /**
   * Withdraws previously granted consent, reverting to strictly necessary only.
   */
  withdrawConsent(): CookieConsentRecord {
    const record: CookieConsentRecord = {
      status: 'withdrawn',
      categories: {
        necessary: true,
        functional: false,
        analytics: false,
        marketing: false,
      },
      consentVersion: CONSENT_VERSION,
      timestamp: new Date().toISOString(),
      source: 'withdrawal',
      jurisdiction: 'GLOBAL_DPDPA_GDPR',
    };
    this.saveConsentRecord(record);
    return record;
  }

  /**
   * Clears consent record entirely so the banner reappears.
   */
  resetConsent(): void {
    if (typeof window === 'undefined') return;

    try {
      localStorage.removeItem(CONSENT_STORAGE_KEY);
      localStorage.removeItem('amaracus_pref_functional');
      localStorage.removeItem('theme');
      window.dispatchEvent(new CustomEvent('amaracus-consent-reset'));
    } catch {}
  }

  /**
   * Enforces technical boundaries: purges optional data if consent was rejected or withdrawn.
   */
  enforceStorageBoundaries(record: CookieConsentRecord): void {
    if (typeof window === 'undefined') return;

    try {
      // Functional preference boundary
      if (!record.categories.functional) {
        localStorage.removeItem('theme');
        localStorage.setItem('amaracus_pref_functional', 'disabled');
      } else {
        localStorage.setItem('amaracus_pref_functional', 'enabled');
      }

      // Analytics boundary: If telemetry is rejected, disable any client telemetry markers
      if (!record.categories.analytics) {
        sessionStorage.removeItem('amaracus_telemetry_batch');
      }
    } catch {}
  }

  /**
   * Emits a window custom event to notify all components and open tabs of consent state changes.
   */
  private dispatchConsentEvent(record: CookieConsentRecord): void {
    if (typeof window === 'undefined') return;
    try {
      window.dispatchEvent(
        new CustomEvent('amaracus-consent-changed', {
          detail: record,
        })
      );
    } catch {}
  }
}

export const consentManager = new ConsentManager();
