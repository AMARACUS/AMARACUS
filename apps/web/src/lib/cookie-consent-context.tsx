"use client";

import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import {
  consentManager,
  CookieConsentRecord,
  CookieConsentCategories,
  DEFAULT_CATEGORIES,
} from "./consent-manager";

interface CookieConsentContextType {
  consent: CookieConsentRecord | null;
  hasConsented: boolean;
  isBannerOpen: boolean;
  isSettingsOpen: boolean;
  openBanner: () => void;
  closeBanner: () => void;
  openSettings: () => void;
  closeSettings: () => void;
  acceptAll: () => void;
  rejectAll: () => void;
  saveCustom: (categories: CookieConsentCategories) => void;
  withdrawConsent: () => void;
  resetConsent: () => void;
}

const CookieConsentContext = createContext<CookieConsentContextType | undefined>(undefined);

export function CookieConsentProvider({ children }: { children: React.ReactNode }) {
  const [consent, setConsent] = useState<CookieConsentRecord | null>(null);
  const [hasConsented, setHasConsented] = useState<boolean>(true); // default true to avoid flash on server render
  const [isBannerOpen, setIsBannerOpen] = useState<boolean>(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState<boolean>(false);

  // Initialize consent on mount
  useEffect(() => {
    const stored = consentManager.getStoredConsent();
    if (stored) {
      setConsent(stored);
      setHasConsented(true);
      setIsBannerOpen(false);
      consentManager.enforceStorageBoundaries(stored);
    } else {
      setConsent(null);
      setHasConsented(false);
      setIsBannerOpen(true);
    }

    const handleConsentChanged = (event: Event) => {
      const customEvent = event as CustomEvent<CookieConsentRecord>;
      if (customEvent.detail) {
        setConsent(customEvent.detail);
        setHasConsented(true);
      }
    };

    const handleConsentReset = () => {
      setConsent(null);
      setHasConsented(false);
      setIsBannerOpen(true);
      setIsSettingsOpen(false);
    };

    window.addEventListener("amaracus-consent-changed", handleConsentChanged);
    window.addEventListener("amaracus-consent-reset", handleConsentReset);

    return () => {
      window.removeEventListener("amaracus-consent-changed", handleConsentChanged);
      window.removeEventListener("amaracus-consent-reset", handleConsentReset);
    };
  }, []);

  const openBanner = useCallback(() => setIsBannerOpen(true), []);
  const closeBanner = useCallback(() => setIsBannerOpen(false), []);

  const openSettings = useCallback(() => setIsSettingsOpen(true), []);
  const closeSettings = useCallback(() => setIsSettingsOpen(false), []);

  const acceptAll = useCallback(() => {
    const record = consentManager.acceptAll();
    setConsent(record);
    setHasConsented(true);
    setIsBannerOpen(false);
    setIsSettingsOpen(false);
  }, []);

  const rejectAll = useCallback(() => {
    const record = consentManager.rejectAll();
    setConsent(record);
    setHasConsented(true);
    setIsBannerOpen(false);
    setIsSettingsOpen(false);
  }, []);

  const saveCustom = useCallback((categories: CookieConsentCategories) => {
    const record = consentManager.saveCustomPreferences(categories);
    setConsent(record);
    setHasConsented(true);
    setIsBannerOpen(false);
    setIsSettingsOpen(false);
  }, []);

  const withdrawConsent = useCallback(() => {
    const record = consentManager.withdrawConsent();
    setConsent(record);
    setHasConsented(true);
    setIsSettingsOpen(false);
  }, []);

  const resetConsent = useCallback(() => {
    consentManager.resetConsent();
    setConsent(null);
    setHasConsented(false);
    setIsBannerOpen(true);
    setIsSettingsOpen(false);
  }, []);

  return (
    <CookieConsentContext.Provider
      value={{
        consent,
        hasConsented,
        isBannerOpen,
        isSettingsOpen,
        openBanner,
        closeBanner,
        openSettings,
        closeSettings,
        acceptAll,
        rejectAll,
        saveCustom,
        withdrawConsent,
        resetConsent,
      }}
    >
      {children}
    </CookieConsentContext.Provider>
  );
}

export function useCookieConsent() {
  const context = useContext(CookieConsentContext);
  if (!context) {
    throw new Error("useCookieConsent must be used within a CookieConsentProvider");
  }
  return context;
}
