"use client";

import React, { useEffect, useState } from "react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Key, Activity, ShieldCheck, Zap, ArrowUpRight, Cpu, Plus, Loader2 } from "lucide-react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api-client";
import { apiUrl } from "@/lib/api-base";
import { useEdition } from "@/lib/edition";
import { cloudDefaults } from "@/lib/cloud/cloud-defaults";
import { ChoosePlanCard } from "@/components/cloud/choose-plan-card";

interface OverviewData {
  operations: number | null;
  periodEnd: string | null;
  planName: string | null;
  planId: string | null;
  keysTotal: number | null;
  keysActive: number | null;
  pqcKeys: number | null;
  policiesActive: number | null;
  recent: { id: string; action: string; resourceType: string; createdAt: string }[] | null;
}

const EMPTY: OverviewData = {
  operations: null,
  periodEnd: null,
  planName: null,
  planId: null,
  keysTotal: null,
  keysActive: null,
  pqcKeys: null,
  policiesActive: null,
  recent: null,
};

const PQC_ALGORITHM = /ML-KEM|ML-DSA|SLH-DSA|HYBRID/i;

function show(value: number | null): string {
  return value === null ? "—" : value.toLocaleString();
}

export default function DashboardPage() {
  const { activeOrg, loading: authLoading } = useAuth();
  const { edition } = useEdition();
  const selfHosted = edition === "selfhosted";
  const [data, setData] = useState<OverviewData>(EMPTY);
  const [loading, setLoading] = useState(false);
  const [apiStatus, setApiStatus] = useState<"checking" | "ready" | "degraded">("checking");

  useEffect(() => {
    fetch(apiUrl("/health/ready"))
      .then((r) => setApiStatus(r.ok ? "ready" : "degraded"))
      .catch(() => setApiStatus("degraded"));
  }, []);

  useEffect(() => {
    if (!activeOrg?.id) {
      setData(EMPTY);
      return;
    }
    const orgId = activeOrg.id;
    setLoading(true);
    // Each source loads on its own; one failing leaves only its figures blank.
    Promise.allSettled([
      api.billing.get(orgId),
      api.keys.list(orgId),
      api.policies.list(orgId),
      api.audit.list(orgId, 8),
    ]).then(([billing, keys, policies, audit]) => {
      const next: OverviewData = { ...EMPTY };
      if (billing.status === "fulfilled") {
        const b: any = (billing.value as any)?.data;
        next.operations = typeof b?.usage?.operationCount === "number" ? b.usage.operationCount : null;
        next.periodEnd = b?.usage?.periodEnd || null;
        next.planName = b?.plan?.name || null;
        next.planId = b?.plan?.id || null;
      }
      if (keys.status === "fulfilled") {
        const list: any[] = (keys.value as any)?.data || [];
        next.keysTotal = list.length;
        next.keysActive = list.filter((k) => k.status === "ACTIVE").length;
        next.pqcKeys = list.filter((k) => PQC_ALGORITHM.test(String(k.algorithm))).length;
      }
      if (policies.status === "fulfilled") {
        const list: any[] = (policies.value as any)?.data || [];
        next.policiesActive = list.filter((p) => p.status === "ACTIVE").length;
      }
      if (audit.status === "fulfilled") {
        next.recent = ((audit.value as any)?.auditEvents || []).slice(0, 8);
      }
      setData(next);
      setLoading(false);
    });
  }, [activeOrg?.id]);

  const signedOut = !authLoading && !activeOrg;

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="font-editorial text-3xl font-bold text-[#1A1A1A] tracking-tight">Console Overview</h1>
          <p className="text-sm text-[#636863] mt-1">
            Usage, keys and policies for {activeOrg?.name || "your organization"}.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link href="/dashboard/crypto">
            <Button size="sm">
              <Zap className="w-3.5 h-3.5 mr-1.5" /> Playground
            </Button>
          </Link>
          <Link href="/dashboard/keys">
            <Button variant="outline" size="sm">
              <Plus className="w-3.5 h-3.5 mr-1" /> New Key
            </Button>
          </Link>
        </div>
      </div>

      {/* Live API status */}
      <div
        className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs ${
          apiStatus === "degraded" ? "border-[#F2C9C9] bg-[#FDF2F2]" : "border-[#C8E0CF] bg-[#EAF3EC]"
        }`}
      >
        <div className={`flex items-center gap-2.5 font-medium ${apiStatus === "degraded" ? "text-[#B42318]" : "text-[#008031]"}`}>
          {apiStatus === "checking" ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <span className={`inline-flex rounded-full h-2.5 w-2.5 ${apiStatus === "ready" ? "bg-[#008031]" : "bg-[#B42318]"}`} aria-hidden="true" />
          )}
          <span>
            API:{" "}
            {apiStatus === "checking" ? "checking…" : apiStatus === "ready" ? "ready (database connected)" : "not ready, see the status page"}
          </span>
        </div>
        {!selfHosted && data.planName && (
          <div className="text-[#555555]">
            Plan: <strong>{data.planName}</strong>
            {data.periodEnd && <> · period ends {new Date(data.periodEnd).toLocaleDateString()}</>}
          </div>
        )}
      </div>

      {signedOut && (
        <div className="p-4 rounded-xl border border-dashed border-[#E9EDE7] bg-white text-xs text-[#636863]">
          Sign in to see your organization&apos;s usage, keys and policies.
        </div>
      )}

      {/* No free tier: nothing works until a plan is active, so that comes first */}
      {!signedOut && !loading && !selfHosted && data.planId === 'FREE' && <ChoosePlanCard />}

      {/* First run: shown until the organization has its first managed key */}
      {!signedOut && !loading && data.keysTotal === 0 && (selfHosted || data.planId !== 'FREE') && (
        <Card className="border-[#C8E0CF]">
          <CardHeader>
            <CardTitle>Encrypt your first value in three steps</CardTitle>
            <CardDescription>
              About five minutes. {cloudDefaults.hasCloudSite ? "Each encrypt or decrypt call uses one operation from your monthly allowance." : "Each successful cryptographic operation counts toward your lifetime allowance."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ol className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-[#555555]">
              <li className="p-4 rounded-xl border border-[#E9EDE7] bg-[#FAF9F6] space-y-2">
                <span className="font-semibold text-[#1A1A1A] block">1. Create a managed key</span>
                <span className="block">Pick AES-256-GCM for encryption. The key never leaves AMARACUS.</span>
                <Link href="/dashboard/keys" className="inline-block text-[#008031] font-semibold underline">Create a key</Link>
              </li>
              <li className="p-4 rounded-xl border border-[#E9EDE7] bg-[#FAF9F6] space-y-2">
                <span className="font-semibold text-[#1A1A1A] block">2. Create an API key</span>
                <span className="block">For this first try tick Encrypt and Decrypt. In a real app, use an Encrypt-only key where data is saved and a separate Decrypt key where it is shown. The key is shown once, so copy it then.</span>
                <Link href="/dashboard/api-keys" className="inline-block text-[#008031] font-semibold underline">Create an API key</Link>
              </li>
              <li className="p-4 rounded-xl border border-[#E9EDE7] bg-[#FAF9F6] space-y-2">
                <span className="font-semibold text-[#1A1A1A] block">3. Call /v1/encrypt</span>
                <span className="block">Send a value such as an email address; store the envelope you get back. Try it first in the Playground.</span>
                <span className="flex gap-3">
                  <Link href="/dashboard/crypto" className="text-[#008031] font-semibold underline">Open Playground</Link>
                  <Link href={cloudDefaults.hasCloudSite ? "/guides/encryption-api/" : "/docs/"} className="text-[#008031] font-semibold underline">{cloudDefaults.hasCloudSite ? "Read the guide" : "Read the docs"}</Link>
                </span>
              </li>
            </ol>
          </CardContent>
        </Card>
      )}

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between text-xs text-[#767676] font-medium">
              <span>Operations (this billing period)</span>
              <Activity className="w-4 h-4 text-[#008031]" />
            </div>
            <div className="font-editorial text-3xl font-bold text-[#1A1A1A] mt-2">{loading ? "…" : show(data.operations)}</div>
          </CardHeader>
          <CardContent className="text-xs text-[#767676]">
            <Link href="/dashboard/billing" className="hover:underline">See usage and limits</Link>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between text-xs text-[#767676] font-medium">
              <span>Managed Keys</span>
              <Key className="w-4 h-4 text-[#008031]" />
            </div>
            <div className="font-editorial text-3xl font-bold text-[#1A1A1A] mt-2">{loading ? "…" : show(data.keysTotal)}</div>
          </CardHeader>
          <CardContent className="text-xs text-[#767676]">
            <span>{data.keysActive === null ? "—" : `${data.keysActive.toLocaleString()} active`}</span>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between text-xs text-[#767676] font-medium">
              <span>Active Policies</span>
              <ShieldCheck className="w-4 h-4 text-[#008031]" />
            </div>
            <div className="font-editorial text-3xl font-bold text-[#1A1A1A] mt-2">{loading ? "…" : show(data.policiesActive)}</div>
          </CardHeader>
          <CardContent className="text-xs text-[#767676]">
            <Link href="/dashboard/policies" className="hover:underline">Manage policies</Link>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between text-xs text-[#767676] font-medium">
              <span>Post-Quantum Keys</span>
              <Cpu className="w-4 h-4 text-[#008031]" />
            </div>
            <div className="font-editorial text-3xl font-bold text-[#1A1A1A] mt-2">{loading ? "…" : show(data.pqcKeys)}</div>
          </CardHeader>
          <CardContent className="text-xs text-[#767676]">
            <span>ML-KEM, ML-DSA and hybrid keys</span>
          </CardContent>
        </Card>
      </div>

      {/* Recent activity from the audit log */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-4 border-b border-[#E9EDE7]">
          <div>
            <CardTitle>Recent Activity</CardTitle>
            <CardDescription>The latest entries in your organization&apos;s audit log.</CardDescription>
          </div>
          <Link href="/dashboard/audit">
            <Button variant="ghost" size="sm" className="text-xs">
              View Audit Log <ArrowUpRight className="w-3.5 h-3.5 ml-1" />
            </Button>
          </Link>
        </CardHeader>
        <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Recent activity table">
          <table className="w-full text-xs text-left">
            <thead className="bg-[#FAF9F6] text-[#767676] border-b border-[#E9EDE7]">
              <tr>
                <th className="px-6 py-3 font-semibold">When</th>
                <th className="px-6 py-3 font-semibold">Action</th>
                <th className="px-6 py-3 font-semibold">Resource</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E9EDE7]">
              {!data.recent || data.recent.length === 0 ? (
                <tr>
                  <td colSpan={3} className="px-6 py-8 text-center text-[#767676]">
                    {loading ? "Loading…" : data.recent === null ? "No activity to show." : "No activity yet."}
                  </td>
                </tr>
              ) : (
                data.recent.map((row) => (
                  <tr key={row.id} className="hover:bg-[#FAF9F6] transition-colors">
                    <td className="px-6 py-3.5 font-mono text-[#767676]">{new Date(row.createdAt).toLocaleString()}</td>
                    <td className="px-6 py-3.5 font-medium text-[#1A1A1A]">{row.action}</td>
                    <td className="px-6 py-3.5">
                      <Badge variant="outline">{row.resourceType}</Badge>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
