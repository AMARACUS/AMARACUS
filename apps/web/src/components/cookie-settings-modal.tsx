"use client";

import React, { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { Sliders, X, Lock, CheckCircle2, EyeOff, BarChart3, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useCookieConsent } from "@/lib/cookie-consent-context";
import { CookieConsentCategories, DEFAULT_CATEGORIES } from "@/lib/consent-manager";
import { cloudDefaults } from "@/lib/cloud/cloud-defaults";

export function CookieSettingsModal() {
  const { isSettingsOpen, closeSettings, consent, saveCustom, rejectAll, acceptAll } = useCookieConsent();
  const [categories, setCategories] = useState<CookieConsentCategories>(DEFAULT_CATEGORIES);
  const modalRef = useRef<HTMLDivElement>(null);
  const previousActiveElement = useRef<HTMLElement | null>(null);

  // Sync state, focus management & scroll lock when modal opens
  useEffect(() => {
    if (isSettingsOpen) {
      previousActiveElement.current = document.activeElement as HTMLElement;
      if (consent) {
        setCategories(consent.categories);
      } else {
        // Unselected default: non-essential categories are NOT pre-selected (EDPB/GDPR compliant)
        setCategories(DEFAULT_CATEGORIES);
      }

      const prevOverflow = document.body.style.overflow;
      document.body.style.overflow = "hidden";

      // Focus first focusable element inside modal
      const timer = setTimeout(() => {
        if (modalRef.current) {
          const focusable = modalRef.current.querySelector<HTMLElement>(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
          );
          if (focusable) {
            focusable.focus();
          } else {
            modalRef.current.focus();
          }
        }
      }, 50);

      return () => {
        clearTimeout(timer);
        document.body.style.overflow = prevOverflow;
        if (previousActiveElement.current) {
          previousActiveElement.current.focus();
        }
      };
    }
  }, [isSettingsOpen, consent]);

  // Handle ESC key and focus trapping (Tab / Shift+Tab)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isSettingsOpen) return;
      if (e.key === "Escape") {
        e.preventDefault();
        closeSettings();
        return;
      }

      if (e.key === "Tab" && modalRef.current) {
        const focusables = modalRef.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];

        if (e.shiftKey) {
          if (document.activeElement === first) {
            e.preventDefault();
            last.focus();
          }
        } else {
          if (document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isSettingsOpen, closeSettings]);

  if (!isSettingsOpen) return null;

  const handleToggle = (key: keyof CookieConsentCategories) => {
    if (key === "necessary" || key === "marketing") return; // Immutable
    setCategories((prev) => ({
      ...prev,
      [key]: !prev[key],
    }));
  };

  const handleSavePreferences = () => {
    saveCustom(categories);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-xs p-4 animate-in fade-in duration-200"
      role="dialog"
      aria-modal="true"
      aria-labelledby="cookie-settings-title"
      aria-describedby="cookie-settings-desc"
    >
      <div
        ref={modalRef}
        className="w-full max-w-2xl bg-white rounded-2xl border border-[#E9EDE7] shadow-2xl p-6 sm:p-8 space-y-6 text-xs text-[#333333] max-h-[90vh] flex flex-col focus:outline-none"
        tabIndex={-1}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-4 pb-4 border-b border-[#E9EDE7]">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-7 h-7 rounded-lg bg-[#EAF3EC] border border-[#C8E0CF] flex items-center justify-center text-[#008031] shrink-0">
                <Sliders className="w-4 h-4" />
              </span>
              <h2 id="cookie-settings-title" className="font-editorial text-xl sm:text-2xl font-bold text-[#1A1A1A]">
                Cookie &amp; Storage Preferences
              </h2>
            </div>
            <p id="cookie-settings-desc" className="text-xs text-[#636863] mt-1 leading-relaxed">
              Control which browser storage technologies AMARACUS may utilize on your device.
              You may modify or withdraw your consent at any time.
            </p>
          </div>
          <button
            onClick={closeSettings}
            className="text-[#8C928C] hover:text-[#1A1A1A] p-1.5 rounded-lg hover:bg-[#FAF9F6] transition-colors"
            aria-label="Close preferences"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Categories Body */}
        <div className="space-y-4 overflow-y-auto pr-1 flex-1">
          {/* Strictly Necessary Category */}
          <div className="p-4 rounded-xl bg-[#FAF9F6] border border-[#E9EDE7] space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-sm text-[#1A1A1A] flex items-center gap-2">
                <Lock className="w-4 h-4 text-[#008031]" />
                Strictly Necessary Storage
              </span>
              <span className="text-[11px] font-bold uppercase tracking-wider px-2.5 py-0.5 rounded bg-[#EAF3EC] text-[#008031] border border-[#C8E0CF]">
                Always Active
              </span>
            </div>
            <p className="text-xs text-[#636863] leading-relaxed">
              These items are strictly indispensable for operating the platform, authenticating API sessions,
              preventing CSRF attacks, and recording your privacy preferences. They cannot be disabled.
            </p>
            <div className="pt-1 text-[11px] font-mono text-[#767676] space-y-0.5 border-t border-[#E9EDE7]">
              <div>• <code>sessionToken</code>: First-party HTTP-Only cookie for API verification (7 days).</div>
              <div>• <code>amaracus_session_token</code>: Client bearer authorization token (session duration).</div>
              <div>• <code>amaracus_cookie_consent</code>: Persistent consent record.</div>
              <div>• <code>__cf_bm</code>: Cloudflare edge bot protection &amp; DDoS mitigation (30 mins).</div>
            </div>
          </div>

          {/* Functional & UI Preferences Category */}
          <div className="p-4 rounded-xl bg-white border border-[#E9EDE7] space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-sm text-[#1A1A1A] flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#008031]" />
                Functional &amp; UI Preferences
              </span>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={categories.functional}
                  onChange={() => handleToggle("functional")}
                  className="sr-only peer"
                  aria-label="Toggle Functional and UI Preferences"
                />
                <div className="w-9 h-5 bg-gray-200 peer-focus-visible:ring-2 peer-focus-visible:ring-[#008031] peer-focus-visible:ring-offset-2 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[#008031]"></div>
              </label>
            </div>
            <p className="text-xs text-[#636863] leading-relaxed">
              Enables AMARACUS to remember your interface customizations (such as dark or light theme) across browser
              sessions to prevent visual flickering.
            </p>
            <div className="pt-1 text-[11px] font-mono text-[#767676] border-t border-[#E9EDE7]">
              • <code>theme</code>: Browser localStorage (1 year).
            </div>
          </div>

          {/* Analytics & Telemetry Category */}
          <div className="p-4 rounded-xl bg-white border border-[#E9EDE7] space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-sm text-[#1A1A1A] flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-[#008031]" />
                Performance Telemetry
              </span>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={categories.analytics}
                  onChange={() => handleToggle("analytics")}
                  className="sr-only peer"
                  aria-label="Toggle Performance Telemetry"
                />
                <div className="w-9 h-5 bg-gray-200 peer-focus-visible:ring-2 peer-focus-visible:ring-[#008031] peer-focus-visible:ring-offset-2 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[#008031]"></div>
              </label>
            </div>
            <p className="text-xs text-[#636863] leading-relaxed">
              Allows optional aggregated client error telemetry to assist engineers in diagnosing cryptographic API failures.
              AMARACUS does NOT use third-party analytics cookies or cross-site tracking tools.
            </p>
          </div>

          {/* Advertising & Marketing Category */}
          <div className="p-4 rounded-xl bg-[#FAF9F6] border border-[#E9EDE7] space-y-2 opacity-80">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-sm text-[#767676] flex items-center gap-2">
                <EyeOff className="w-4 h-4 text-[#767676]" />
                Advertising &amp; Retargeting Trackers
              </span>
              <span className="text-[11px] font-bold uppercase tracking-wider px-2.5 py-0.5 rounded bg-gray-100 text-gray-500 border border-gray-200">
                Not Used
              </span>
            </div>
            <p className="text-xs text-[#767676] leading-relaxed">
              AMARACUS operates under an absolute zero-tracker architecture. We do not partner with ad exchanges,
              deploy retargeting pixels, or engage in behavioral advertising profiling.
            </p>
          </div>
        </div>

        {/* Footer Actions with Equal Prominence */}
        <div className="pt-4 border-t border-[#E9EDE7] flex flex-col sm:flex-row items-center justify-between gap-3">
          {cloudDefaults.hasCloudSite ? (
          <Link
            href="/cookies"
            onClick={closeSettings}
            className="text-xs text-[#008031] underline hover:text-[#006627] font-medium order-3 sm:order-1"
          >
            Review Cookie Policy &rarr;
          </Link>
          ) : (
            <span className="order-3 sm:order-1" />
          )}
          <div className="flex flex-col sm:flex-row items-center gap-2 w-full sm:w-auto order-1 sm:order-2">
            <Button
              type="button"
              variant="outline"
              onClick={rejectAll}
              className="w-full sm:w-auto text-xs border-[#1A1A1A] text-[#1A1A1A] hover:bg-[#F8F7F4] font-semibold h-9 px-4"
            >
              Reject Non-Essential
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={handleSavePreferences}
              className="w-full sm:w-auto text-xs border-[#008031] text-[#008031] hover:bg-[#EAF3EC] font-semibold h-9 px-4"
            >
              Save Preferences
            </Button>
            <Button
              type="button"
              onClick={acceptAll}
              className="w-full sm:w-auto text-xs bg-[#008031] hover:bg-[#006627] text-white font-semibold h-9 px-4"
            >
              Accept All
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
