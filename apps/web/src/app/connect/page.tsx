"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { AlertCircle, AlertTriangle, Loader2, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-context";
import { cloudDefaults } from "@/lib/cloud/cloud-defaults";

interface RequestDetails {
  clientName: string;
  destination: string;
  isLocalApp: boolean;
  scopes: { id: string; label: string; preselected: boolean }[];
}

interface EnvironmentOption {
  id: string;
  label: string;
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen flex flex-col justify-center items-center px-6 pt-12 pb-56 bg-[#F8F7F4]">
      <main className="w-full max-w-md">
        <div className="text-center mb-6">
          <Link href="/" className="inline-flex items-center gap-2">
            <div className="w-9 h-9 rounded-lg bg-[#EAF3EC] border border-[#C8E0CF] flex items-center justify-center text-[#008031]">
              <Shield className="w-5 h-5 fill-[#008031]/20 stroke-[#008031]" aria-hidden="true" />
            </div>
            <span className="font-editorial text-2xl font-bold tracking-tight text-[#1A1A1A]">AMARACUS</span>
          </Link>
        </div>
        <div className="p-6 rounded-2xl border border-[#E9EDE7] bg-white shadow-card space-y-5 text-sm text-[#1A1A1A]">
          {children}
        </div>
      </main>
    </div>
  );
}

function Notice({ children }: { children: React.ReactNode }) {
  return (
    <div role="alert" className="p-3 rounded-lg border border-red-200 bg-red-50 text-red-700 flex items-start gap-2 text-xs">
      <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" aria-hidden="true" />
      <span>{children}</span>
    </div>
  );
}

export default function ConnectPage() {
  const { user, organizations, activeOrg, loading: authLoading } = useAuth();
  const [request, setRequest] = useState<string | null>(null);
  const [details, setDetails] = useState<RequestDetails | null>(null);
  const [fatal, setFatal] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [orgId, setOrgId] = useState("");
  const [environments, setEnvironments] = useState<EnvironmentOption[] | null>(null);
  const [environmentId, setEnvironmentId] = useState("");
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [needsPlan, setNeedsPlan] = useState(false);

  useEffect(() => {
    const value = new URLSearchParams(window.location.search).get("request");
    if (!value) {
      setFatal("This page is opened by the app you are connecting. Start from your AI assistant or coding agent.");
      return;
    }
    setRequest(value);
    api.mcpConnect
      .request(value)
      .then(({ data }) => {
        setDetails(data);
        setChosen(new Set(data.scopes.filter((s) => s.preselected).map((s) => s.id)));
      })
      .catch((err) => setFatal(err.message || "This connection request could not be read."));
  }, []);

  useEffect(() => {
    if (!orgId && organizations.length) setOrgId(activeOrg?.id || organizations[0].id);
  }, [organizations, activeOrg, orgId]);

  useEffect(() => {
    if (!orgId) return;
    let current = true;
    setEnvironments(null);
    setEnvironmentId("");
    setError(null);
    setNeedsPlan(false);
    (async () => {
      const options: EnvironmentOption[] = [];
      const { projects } = await api.projects.list(orgId);
      for (const project of projects || []) {
        const res = await api.environments.list(orgId, project.id);
        for (const env of res.environments || []) options.push({ id: env.id, label: `${project.name} / ${env.name}` });
      }
      if (!current) return;
      setEnvironments(options);
      setEnvironmentId(options[0]?.id || "");
    })().catch((err) => {
      if (!current) return;
      setEnvironments([]);
      setError(err.message || "Your projects could not be loaded.");
    });
    return () => {
      current = false;
    };
  }, [orgId]);

  const toggle = (id: string) =>
    setChosen((prev) => {
      const next = new Set(prev);
      if (!next.delete(id)) next.add(id);
      return next;
    });

  const answer = async (allow: boolean) => {
    if (!request) return;
    setBusy(true);
    setError(null);
    setNeedsPlan(false);
    try {
      const { data } = allow
        ? await api.mcpConnect.approve(orgId, { request, environmentId, scopes: Array.from(chosen) })
        : await api.mcpConnect.deny(request);
      window.location.assign(data.redirectTo);
    } catch (err: any) {
      if (err.status === 402) setNeedsPlan(true);
      else setError(err.message || "The connection could not be completed.");
      setBusy(false);
    }
  };

  if (fatal) {
    return (
      <Shell>
        <h1 className="text-lg font-semibold">Connection request</h1>
        <Notice>{fatal}</Notice>
      </Shell>
    );
  }

  if (!details || authLoading) {
    return (
      <Shell>
        <p className="flex items-center gap-2 text-[#636863]" role="status">
          <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" /> Reading the connection request...
        </p>
      </Shell>
    );
  }

  const header = (
    <div className="space-y-2">
      <h1 className="text-lg font-semibold">Connect {details.clientName} to AMARACUS</h1>
      <p className="text-[#636863] leading-relaxed">
        After you decide, you return to <strong className="text-[#1A1A1A] break-words">{details.destination}</strong>. The app
        chose its own name; AMARACUS has not verified it.
      </p>
    </div>
  );

  if (!user) {
    const here = `/connect/?request=${encodeURIComponent(request || "")}`;
    return (
      <Shell>
        {header}
        <p className="text-[#636863]">Sign in to choose what it may do.</p>
        <Link href={`/login?redirect=${encodeURIComponent(here)}`} className="block">
          <Button className="w-full">Sign in to continue</Button>
        </Link>
      </Shell>
    );
  }

  return (
    <Shell>
      {header}

      {details.isLocalApp && (
        <div className="p-3 rounded-lg border border-amber-200 bg-amber-50 text-amber-900 flex items-start gap-2 text-xs">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" aria-hidden="true" />
          <span>Continue only if you started this yourself, just now, in an app on this computer.</span>
        </div>
      )}

      {organizations.length > 1 && (
        <div className="space-y-1.5">
          <label htmlFor="connect-org" className="font-medium">Organization</label>
          <select
            id="connect-org"
            value={orgId}
            onChange={(e) => setOrgId(e.target.value)}
            className="w-full h-10 rounded-lg border border-[#E9EDE7] bg-white px-3"
          >
            {organizations.map((o) => (
              <option key={o.id} value={o.id}>{o.name}</option>
            ))}
          </select>
        </div>
      )}

      <div className="space-y-1.5">
        <label htmlFor="connect-env" className="font-medium">Project and environment</label>
        <select
          id="connect-env"
          value={environmentId}
          onChange={(e) => setEnvironmentId(e.target.value)}
          disabled={!environments?.length}
          className="w-full h-10 rounded-lg border border-[#E9EDE7] bg-white px-3 disabled:opacity-60"
        >
          {environments === null && <option value="">Loading...</option>}
          {environments?.length === 0 && <option value="">No environments found</option>}
          {environments?.map((e) => (
            <option key={e.id} value={e.id}>{e.label}</option>
          ))}
        </select>
        {environments?.length === 0 && (
          <p className="text-xs text-[#636863]">
            Create a project in the{" "}
            <Link href="/dashboard/projects" className="text-[#008031] underline">console</Link>, then start again.
          </p>
        )}
      </div>

      <fieldset className="space-y-2">
        <legend className="font-medium mb-1">It may</legend>
        {details.scopes.map((s) => (
          <label key={s.id} className="flex items-start gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={chosen.has(s.id)}
              onChange={() => toggle(s.id)}
              className="mt-0.5 w-4 h-4 shrink-0 accent-[#008031]"
            />
            <span className="leading-snug">{s.label}</span>
          </label>
        ))}
      </fieldset>

      <p className="text-xs text-[#636863] leading-relaxed">
        Text you encrypt, hash or decrypt through this connection passes through the app and its AI model. Operations count
        towards your plan. You can disconnect any time under{" "}
        <Link href="/dashboard/api-keys" className="text-[#008031] underline">API Credentials</Link>.
      </p>

      {needsPlan && (
        <Notice>
          This organization has no active plan, so it cannot connect apps yet.{" "}
          {cloudDefaults.hasCloudSite && <Link href="/pricing" className="underline">See the plans</Link>}
        </Notice>
      )}
      {error && <Notice>{error}</Notice>}

      <div className="flex gap-3">
        <Button variant="outline" className="flex-1" disabled={busy} onClick={() => answer(false)}>
          Cancel
        </Button>
        <Button className="flex-1" disabled={busy || !environmentId || chosen.size === 0} onClick={() => answer(true)}>
          {busy ? "Connecting..." : "Allow"}
        </Button>
      </div>
      <p className="text-xs text-[#767676] text-center">Signed in as {user.email}</p>
    </Shell>
  );
}
