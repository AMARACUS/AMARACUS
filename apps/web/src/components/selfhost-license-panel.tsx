"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { AlertCircle, AlertTriangle, CheckCircle2, Download, Loader2, ShieldCheck } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api-client";
import { useEdition } from "@/lib/edition";
import { cloudDefaults } from "@/lib/cloud/cloud-defaults";
import type { SelfHostLedgerVerification } from "@/lib/selfhost";

const nf = new Intl.NumberFormat("en-US");

function formatDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-lg border border-[#E9EDE7] bg-[#FAF9F6] p-4">
      <dt className="text-[11px] font-medium uppercase tracking-wide text-[#767676]">{label}</dt>
      <dd className="mt-1 text-2xl font-semibold tabular-nums text-[#1A1A1A]">{value}</dd>
      {hint && <p className="mt-1 text-[11px] text-[#767676]">{hint}</p>}
    </div>
  );
}

/** The "Licence and usage" page of a self-hosted installation. It replaces the Cloud plans and checkout page. */
export function SelfHostLicensePanel() {
  const { user } = useAuth();
  const { status, refresh } = useEdition();

  const [loaded, setLoaded] = useState(false);
  const [licenseKey, setLicenseKey] = useState("");
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);
  const [addSuccess, setAddSuccess] = useState<string | null>(null);

  const [verifying, setVerifying] = useState(false);
  const [verification, setVerification] = useState<SelfHostLedgerVerification | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  // The status fetched at page load has no usage when the visitor was not signed in yet, so ask again.
  useEffect(() => {
    let cancelled = false;
    refresh().finally(() => {
      if (!cancelled) setLoaded(true);
    });
    return () => {
      cancelled = true;
    };
  }, [refresh, user?.id]);

  const usage = status?.usage;
  const keys = status?.licenseKeys ?? [];
  const acceptance = status?.acceptance ?? null;
  const rate = usage ? (usage.ratePer1kOpsCents / 100).toFixed(2) : "0.15";
  const currency = usage?.currency ?? "USD";
  const usedPercent = usage && usage.totalAllowance > 0 ? Math.min(100, (usage.lifetimeOperations / usage.totalAllowance) * 100) : 0;

  const handleAddKey = async (e: React.FormEvent) => {
    e.preventDefault();
    const key = licenseKey.trim();
    if (!key) return;
    setAdding(true);
    setAddError(null);
    setAddSuccess(null);
    try {
      await api.selfhost.addLicenseKey(key);
      setLicenseKey("");
      setAddSuccess("Licence key added.");
      await refresh();
    } catch (err: any) {
      if (err?.code === "INVALID_LICENSE_KEY") {
        setAddError("This licence key is not valid. Check that you pasted the whole key.");
      } else if (err?.code === "LICENSE_KEY_ALREADY_ADDED") {
        setAddError("This licence key has already been added.");
      } else {
        setAddError(err?.message || "Could not add the licence key.");
      }
    } finally {
      setAdding(false);
    }
  };

  const handleVerify = async () => {
    setVerifying(true);
    setVerifyError(null);
    setVerification(null);
    try {
      const res = await api.selfhost.verifyLedger();
      setVerification(res.data);
    } catch (err: any) {
      setVerifyError(err?.message || "Could not verify the usage ledger.");
    } finally {
      setVerifying(false);
    }
  };

  const handleExport = async () => {
    setExporting(true);
    setExportError(null);
    try {
      const blob = await api.selfhost.exportLedger();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "amaracus-usage-ledger.jsonl";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setExportError(err?.message || "Could not download the usage ledger.");
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-8">
      <div className="border-b border-[#E9EDE7] pb-6">
        <h1 className="font-editorial text-3xl md:text-4xl font-bold text-[#1A1A1A] tracking-tight">Licence and usage</h1>
        <p className="mt-1.5 text-sm text-[#636863] leading-relaxed">
          The first {nf.format(usage?.freeAllowance ?? 1000)} successful cryptographic operations on this installation
          are free for life. After that you need a licence key, at USD {rate} per 1,000 operations. Decrypt, unwrap and
          verify always keep working. This installation sends nothing to AMARACUS.
        </p>
      </div>

      {!user && (
        <div className="rounded-lg border border-[#C8E0CF] bg-[#EAF3EC] p-3 text-xs text-[#1A1A1A]">
          Sign in to see usage and manage licence keys.{" "}
          <Link href="/login?redirect=%2Fdashboard%2Fbilling" className="font-semibold text-[#008031] underline">
            Sign in
          </Link>
        </div>
      )}

      {usage?.licenseRequired && (
        <div role="alert" className="flex items-start gap-3 rounded-xl border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-600" aria-hidden="true" />
          <div className="space-y-1">
            <p className="font-semibold">A licence key is required.</p>
            <p className="text-xs leading-relaxed">
              This installation has used all of its {nf.format(usage.totalAllowance)} permitted operations. New
              encrypt, sign and key-generation requests are refused until you add a licence key. Decrypt, unwrap and
              verify still work, so your existing data stays readable. To buy a key, contact{" "}
              <a className="font-medium underline" href={`mailto:${cloudDefaults.licensingContactEmail}`}>
                {cloudDefaults.licensingContactEmail}
              </a>
              .
            </p>
          </div>
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Usage</CardTitle>
          <CardDescription>
            Lifetime count of successful cryptographic operations, shared by your whole corporate group across all
            installations.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {!usage ? (
            <p className="text-xs text-[#767676]" role="status">
              {loaded ? "Usage is shown to signed-in users." : "Loading usage..."}
            </p>
          ) : (
            <>
              <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                <Stat label="Operations used" value={nf.format(usage.lifetimeOperations)} hint="Lifetime" />
                <Stat label="Free allowance" value={nf.format(usage.freeAllowance)} hint="Free for life" />
                <Stat label="Licensed operations" value={nf.format(usage.licensedOperations)} hint="From licence keys" />
                <Stat label="Remaining" value={nf.format(usage.remaining)} hint={`of ${nf.format(usage.totalAllowance)} permitted`} />
              </dl>
              <div>
                <div
                  className="h-2 w-full overflow-hidden rounded-full bg-[#E9EDE7]"
                  role="progressbar"
                  aria-label="Operations used out of the permitted total"
                  aria-valuemin={0}
                  aria-valuemax={usage.totalAllowance}
                  aria-valuenow={Math.min(usage.lifetimeOperations, usage.totalAllowance)}
                >
                  <div
                    className={usage.licenseRequired ? "h-full bg-amber-500" : "h-full bg-[#008031]"}
                    style={{ width: `${usedPercent}%` }}
                  />
                </div>
                <p className="mt-1.5 text-[11px] text-[#767676]">
                  {nf.format(usage.lifetimeOperations)} of {nf.format(usage.totalAllowance)} permitted operations used.
                  Licence keys cost {currency} {rate} per 1,000 operations.
                </p>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Licence keys</CardTitle>
          <CardDescription>
            Licence keys are bought from AMARACUS (
            <a className="text-[#008031] underline" href={`mailto:${cloudDefaults.licensingContactEmail}`}>
              {cloudDefaults.licensingContactEmail}
            </a>
            ). Paste a key here to add its operations to this installation.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5 text-xs">
          <form onSubmit={handleAddKey} className="space-y-2">
            <label htmlFor="license-key" className="font-medium text-[#1A1A1A]">
              Licence key
            </label>
            <div className="flex flex-col gap-2 sm:flex-row">
              <Input
                id="license-key"
                value={licenseKey}
                onChange={(e) => setLicenseKey(e.target.value)}
                placeholder="Paste your licence key"
                autoComplete="off"
                spellCheck={false}
                disabled={adding || !user}
                className="font-mono text-xs"
                aria-describedby="license-key-feedback"
              />
              <Button type="submit" disabled={adding || !user || !licenseKey.trim()} className="sm:w-auto">
                {adding ? (
                  <>
                    <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" /> Adding...
                  </>
                ) : (
                  "Add licence key"
                )}
              </Button>
            </div>
            <div id="license-key-feedback" aria-live="polite">
              {addError && (
                <p className="flex items-center gap-1.5 text-red-700">
                  <AlertCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" /> {addError}
                </p>
              )}
              {addSuccess && (
                <p className="flex items-center gap-1.5 text-emerald-700">
                  <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" /> {addSuccess}
                </p>
              )}
            </div>
          </form>

          {keys.length === 0 ? (
            <p className="text-[#767676]">No licence keys have been added yet.</p>
          ) : (
            <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Licence keys added to this installation">
              <table className="w-full text-left">
                <caption className="sr-only">Licence keys added to this installation</caption>
                <thead>
                  <tr className="border-b border-[#E9EDE7] text-[11px] uppercase tracking-wide text-[#767676]">
                    <th scope="col" className="py-2 pr-4 font-medium">Licence ID</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Licensee</th>
                    <th scope="col" className="py-2 pr-4 text-right font-medium">Operations</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Issued</th>
                    <th scope="col" className="py-2 font-medium">Added</th>
                  </tr>
                </thead>
                <tbody>
                  {keys.map((k) => (
                    <tr key={k.licenseId} className="border-b border-[#F0EFEA]">
                      <td className="py-2 pr-4 font-mono text-[11px]">{k.licenseId}</td>
                      <td className="py-2 pr-4">{k.licensee}</td>
                      <td className="py-2 pr-4 text-right tabular-nums">{nf.format(k.operations)}</td>
                      <td className="py-2 pr-4">{formatDate(k.issuedAt)}</td>
                      <td className="py-2">{formatDate(k.addedAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Usage ledger</CardTitle>
          <CardDescription>
            Every counted operation is written to a hash-chained ledger on this installation. Verify it to check that
            no entry has been changed or removed, or download it as JSON Lines for your own records.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-xs">
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" onClick={handleVerify} disabled={verifying || !user}>
              {verifying ? (
                <>
                  <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" /> Verifying...
                </>
              ) : (
                <>
                  <ShieldCheck className="mr-1.5 h-4 w-4" aria-hidden="true" /> Verify ledger
                </>
              )}
            </Button>
            <Button type="button" variant="outline" onClick={handleExport} disabled={exporting || !user}>
              {exporting ? (
                <>
                  <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" /> Preparing...
                </>
              ) : (
                <>
                  <Download className="mr-1.5 h-4 w-4" aria-hidden="true" /> Download usage ledger
                </>
              )}
            </Button>
          </div>

          <div aria-live="polite" className="space-y-2">
            {verification && verification.valid && (
              <p className="flex items-start gap-1.5 rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-emerald-800">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                <span>
                  The ledger is intact. {nf.format(verification.entriesChecked)} entries checked, cumulative total{" "}
                  {nf.format(verification.cumulativeTotal)} operations.
                </span>
              </p>
            )}
            {verification && !verification.valid && (
              <p role="alert" className="flex items-start gap-1.5 rounded-lg border border-red-200 bg-red-50 p-3 text-red-800">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                <span>
                  The ledger failed verification
                  {verification.firstBrokenSeq !== null ? ` at entry ${nf.format(verification.firstBrokenSeq)}` : ""}.{" "}
                  {nf.format(verification.entriesChecked)} entries were checked before the problem was found. The
                  ledger may have been changed after it was written.
                </span>
              </p>
            )}
            {verifyError && (
              <p role="alert" className="flex items-center gap-1.5 text-red-700">
                <AlertCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" /> {verifyError}
              </p>
            )}
            {exportError && (
              <p role="alert" className="flex items-center gap-1.5 text-red-700">
                <AlertCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" /> {exportError}
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Licence acceptance</CardTitle>
          <CardDescription>The record of who activated this installation.</CardDescription>
        </CardHeader>
        <CardContent className="text-xs">
          {acceptance ? (
            <dl className="grid gap-3 sm:grid-cols-3">
              <div>
                <dt className="text-[11px] font-medium uppercase tracking-wide text-[#767676]">Licensee</dt>
                <dd className="mt-0.5 text-sm text-[#1A1A1A]">{acceptance.licensee}</dd>
              </div>
              <div>
                <dt className="text-[11px] font-medium uppercase tracking-wide text-[#767676]">Accepted by</dt>
                <dd className="mt-0.5 text-sm text-[#1A1A1A]">{acceptance.acceptedByEmail}</dd>
              </div>
              <div>
                <dt className="text-[11px] font-medium uppercase tracking-wide text-[#767676]">Accepted on</dt>
                <dd className="mt-0.5 text-sm text-[#1A1A1A]">{formatDate(acceptance.acceptedAt)}</dd>
              </div>
            </dl>
          ) : (
            <p className="text-[#767676]">{loaded ? "No acceptance has been recorded." : "Loading..."}</p>
          )}
          {status && (
            <p className="mt-4 text-[10px] leading-relaxed text-[#8C928C] break-all">
              {status.licenses.shield.title} SHA-256 {status.licenses.shield.sha256}. {status.licenses.commercial.title}{" "}
              (version {status.licenses.commercial.version}) SHA-256 {status.licenses.commercial.sha256}.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
