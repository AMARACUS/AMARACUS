"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AlertCircle, Loader2, LogOut, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api-client";
import { useEdition } from "@/lib/edition";
import { cloudDefaults } from "@/lib/cloud/cloud-defaults";
import type { SelfHostLicenseTexts } from "@/lib/selfhost";

interface LicenseBoxProps {
  id: string;
  title: string;
  text: string;
  sha256: string;
  read: boolean;
  onRead: () => void;
}

/** A scrollable licence text. It reports once the reader has scrolled to the very end. */
function LicenseBox({ id, title, text, sha256, read, onRead }: LicenseBoxProps) {
  const ref = useRef<HTMLDivElement>(null);

  const check = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    // A few pixels of slack: browsers round scroll positions on zoomed or high-DPI screens.
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 4) onRead();
  }, [onRead]);

  // A short text that fits the box needs no scrolling.
  useEffect(() => {
    check();
  }, [check, text]);

  return (
    <section aria-labelledby={`${id}-title`} className="space-y-2">
      <div className="flex items-baseline justify-between gap-3">
        <h2 id={`${id}-title`} className="text-sm font-semibold text-[#1A1A1A]">
          {title}
        </h2>
        <span className={read ? "text-[11px] font-medium text-[#008031]" : "text-[11px] text-[#767676]"}>
          {read ? "Read to the end" : "Scroll to the end to continue"}
        </span>
      </div>
      <div
        ref={ref}
        onScroll={check}
        tabIndex={0}
        role="region"
        aria-labelledby={`${id}-title`}
        className="h-72 overflow-y-auto rounded-lg border border-[#E9EDE7] bg-white p-4 text-xs leading-relaxed text-[#333333] whitespace-pre-wrap font-mono focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#008031]"
      >
        {text}
      </div>
      <p className="text-[10px] text-[#8C928C] break-all">SHA-256: {sha256}</p>
    </section>
  );
}

/**
 * Full-page screen shown by a self-hosted installation until its owner has accepted the two licences.
 * Nothing is pre-ticked and nothing can be accepted before both texts have been scrolled to the end.
 */
export function SelfHostActivationGate() {
  const router = useRouter();
  const { user, logout } = useAuth();
  const { refresh } = useEdition();

  const [licenses, setLicenses] = useState<SelfHostLicenseTexts | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [shieldRead, setShieldRead] = useState(false);
  const [commercialRead, setCommercialRead] = useState(false);
  const [acceptShield, setAcceptShield] = useState(false);
  const [acceptCommercial, setAcceptCommercial] = useState(false);
  const [licensee, setLicensee] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.selfhost
      .licenses()
      .then((res) => {
        if (!cancelled) setLicenses(res.data);
      })
      .catch((err: any) => {
        if (!cancelled) setLoadError(err?.message || "Could not load the licence texts.");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const markShieldRead = useCallback(() => setShieldRead(true), []);
  const markCommercialRead = useCallback(() => setCommercialRead(true), []);

  const licenseeTrimmed = licensee.trim();
  const bothRead = shieldRead && commercialRead;
  const canSubmit =
    !!user && !!licenses && bothRead && acceptShield && acceptCommercial && licenseeTrimmed.length >= 2 && !submitting;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit || !licenses) return;
    setSubmitting(true);
    setError(null);
    try {
      await api.selfhost.accept({
        acceptShield: true,
        acceptCommercialTerms: true,
        licensee: licenseeTrimmed,
        shieldSha256: licenses.shield.sha256,
        commercialSha256: licenses.commercial.sha256,
      });
      await refresh();
    } catch (err: any) {
      setError(err?.message || "Activation failed. Please try again.");
      setSubmitting(false);
    }
  };

  const handleLogout = async () => {
    await logout();
    router.push("/login");
  };

  return (
    <div className="min-h-screen bg-[#F8F7F4] px-4 py-10 text-[#1A1A1A]">
      <div className="mx-auto max-w-4xl space-y-8">
        <header className="space-y-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#C8E0CF] bg-[#EAF3EC] text-[#008031]">
                <Shield className="h-5 w-5 fill-[#008031]/20 stroke-[#008031]" aria-hidden="true" />
              </div>
              <span className="font-editorial text-xl font-bold tracking-tight">AMARACUS</span>
            </div>
            {user && (
              <button
                type="button"
                onClick={handleLogout}
                className="inline-flex items-center gap-1.5 rounded-lg border border-[#E9EDE7] bg-white px-3 py-1.5 text-xs font-medium text-[#555555] hover:bg-[#F3F2EE] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#008031]"
              >
                <LogOut className="h-3.5 w-3.5" aria-hidden="true" /> Sign out
              </button>
            )}
          </div>
          <h1 className="font-editorial text-3xl font-bold tracking-tight md:text-4xl">Activate self-hosting</h1>
          <p className="text-sm leading-relaxed text-[#636863]">
            This installation is not active yet. Before it can run cryptographic operations, the person or company
            that owns it must read and accept the two licences below. Nothing is accepted until you tick both boxes
            and press the button at the end of this page.
          </p>
        </header>

        <section aria-labelledby="terms-in-plain-english" className="rounded-xl border border-[#E9EDE7] bg-white p-5">
          <h2 id="terms-in-plain-english" className="mb-2 text-sm font-semibold">
            In plain English
          </h2>
          <ul className="list-disc space-y-1.5 pl-5 text-xs leading-relaxed text-[#444444]">
            <li>
              The first <strong>1,000</strong> successful cryptographic operations are free for life. This is a lifetime
              allowance, not a monthly one, and it is shared by your whole corporate group across all installations.
            </li>
            <li>
              From operation 1,001 you need a licence key. Keys are priced at <strong>USD 0.15 per 1,000 operations</strong>,
              the same rate as AMARACUS Cloud Pay As You Go. Buy keys from AMARACUS ({cloudDefaults.licensingContactEmail})
              and paste them in under Licence and Usage.
            </li>
            <li>This installation sends nothing to AMARACUS. There is no telemetry.</li>
            <li>
              Decrypt, unwrap and verify always keep working, so data you protected earlier stays readable even when
              no licence key covers new operations.
            </li>
          </ul>
          <p className="mt-3 text-[11px] text-[#767676]">
            This summary is a convenience only. The two licence texts below are the binding documents.
          </p>
        </section>

        {loadError && (
          <div role="alert" className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700">
            <AlertCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>{loadError}</span>
          </div>
        )}

        {!licenses && !loadError && (
          <div className="flex items-center gap-2 text-xs text-[#767676]" role="status">
            <Loader2 className="h-3.5 w-3.5 animate-spin text-[#008031]" aria-hidden="true" />
            <span>Loading licence texts...</span>
          </div>
        )}

        {licenses && (
          <form onSubmit={handleSubmit} className="space-y-8" aria-describedby="activation-help">
            <div className="grid gap-6 lg:grid-cols-2">
              <LicenseBox
                id="license-shield"
                title={licenses.shield.title}
                text={licenses.shield.text}
                sha256={licenses.shield.sha256}
                read={shieldRead}
                onRead={markShieldRead}
              />
              <LicenseBox
                id="license-commercial"
                title={`${licenses.commercial.title} (version ${licenses.commercial.version})`}
                text={licenses.commercial.text}
                sha256={licenses.commercial.sha256}
                read={commercialRead}
                onRead={markCommercialRead}
              />
            </div>

            <fieldset className="space-y-4 rounded-xl border border-[#E9EDE7] bg-white p-5">
              <legend className="px-1 text-sm font-semibold">Your acceptance</legend>
              <p id="activation-help" className="text-xs text-[#767676]">
                The tick boxes unlock after you have scrolled each licence text to its end.
              </p>

              <label className="flex items-start gap-2.5 text-xs leading-relaxed text-[#333333]">
                <input
                  type="checkbox"
                  checked={acceptShield}
                  onChange={(e) => setAcceptShield(e.target.checked)}
                  disabled={!shieldRead || submitting}
                  className="mt-0.5 rounded border-[#C8E0CF] text-[#008031] focus:ring-[#008031]"
                />
                <span>I have read and I accept the {licenses.shield.title}.</span>
              </label>

              <label className="flex items-start gap-2.5 text-xs leading-relaxed text-[#333333]">
                <input
                  type="checkbox"
                  checked={acceptCommercial}
                  onChange={(e) => setAcceptCommercial(e.target.checked)}
                  disabled={!commercialRead || submitting}
                  className="mt-0.5 rounded border-[#C8E0CF] text-[#008031] focus:ring-[#008031]"
                />
                <span>I have read and I accept the {licenses.commercial.title}.</span>
              </label>

              <div className="space-y-1.5">
                <label htmlFor="licensee-name" className="text-xs font-medium text-[#1A1A1A]">
                  Licensee legal name
                </label>
                <Input
                  id="licensee-name"
                  type="text"
                  autoComplete="organization"
                  value={licensee}
                  onChange={(e) => setLicensee(e.target.value)}
                  disabled={submitting}
                  maxLength={200}
                  aria-describedby="licensee-help"
                  placeholder="Example Holdings Ltd"
                />
                <p id="licensee-help" className="text-[11px] text-[#767676]">
                  The legal name of the company or corporate group, or the individual, that is accepting. If you accept
                  for a company, you confirm that you are authorised to bind it.
                </p>
              </div>

              {!user && (
                <div className="rounded-lg border border-[#C8E0CF] bg-[#EAF3EC] p-3 text-xs text-[#1A1A1A]">
                  You are not signed in. Sign in, or create the first account, to accept the licences.{" "}
                  <Link href="/login?redirect=%2Fdashboard" className="font-semibold text-[#008031] underline">
                    Sign in
                  </Link>{" "}
                  or{" "}
                  <Link href="/signup?redirect=%2Fdashboard" className="font-semibold text-[#008031] underline">
                    create an account
                  </Link>
                  .
                </div>
              )}

              {error && (
                <div role="alert" className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700">
                  <AlertCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>{error}</span>
                </div>
              )}

              <div className="flex justify-end">
                <Button type="submit" disabled={!canSubmit}>
                  {submitting ? (
                    <>
                      <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" /> Activating...
                    </>
                  ) : (
                    "Accept and activate"
                  )}
                </Button>
              </div>
            </fieldset>
          </form>
        )}
      </div>
    </div>
  );
}
