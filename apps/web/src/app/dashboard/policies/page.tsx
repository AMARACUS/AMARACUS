"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Modal } from "@/components/ui/modal";
import { Plus, Shield, Loader2 } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api-client";

interface PolicyRule {
  id?: string;
  name?: string;
  category?: string;
  effect?: string;
  enabled?: boolean;
  condition?: { algorithms?: string[]; [key: string]: any };
}

interface PolicyItem {
  id: string;
  name: string;
  description?: string | null;
  enforcementMode: string;
  status: string;
  version: number;
  rules: PolicyRule[];
}

function parseAlgorithms(text: string): string[] {
  return text
    .split(",")
    .map((s) => s.trim().toUpperCase().replace(/_/g, "-"))
    .filter(Boolean);
}

function algorithmsFor(policy: PolicyItem, effect: "ALLOW" | "DENY"): string {
  const algs = (Array.isArray(policy.rules) ? policy.rules : [])
    .filter((r) => r.enabled !== false && r.effect === effect && Array.isArray(r.condition?.algorithms))
    .flatMap((r) => r.condition!.algorithms!);
  return algs.length > 0 ? algs.join(", ") : "—";
}

export default function PoliciesPage() {
  const { activeOrg, requireAuth, loading: authLoading } = useAuth();
  const [policies, setPolicies] = useState<PolicyItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [allowed, setAllowed] = useState("AES-256-GCM, ED25519, ML-KEM-768");
  const [denied, setDenied] = useState("MD5, SHA-1, 3DES");
  const [enforcementMode, setEnforcementMode] = useState<"ENFORCE" | "AUDIT">("AUDIT");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const loadPolicies = useCallback(async () => {
    if (!activeOrg?.id) {
      setPolicies([]);
      return;
    }
    setLoading(true);
    setLoadError(null);
    try {
      const res = await api.policies.list(activeOrg.id);
      setPolicies((res?.data || []) as PolicyItem[]);
    } catch (err: any) {
      setLoadError(err?.message || "Policies could not be loaded.");
    } finally {
      setLoading(false);
    }
  }, [activeOrg?.id]);

  useEffect(() => {
    loadPolicies();
  }, [loadPolicies]);

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !activeOrg?.id) return;

    const rules: PolicyRule[] = [];
    const allowList = parseAlgorithms(allowed);
    const denyList = parseAlgorithms(denied);
    if (allowList.length > 0) {
      rules.push({ name: "Allowed algorithms", category: "ALGORITHM_RESTRICTION", effect: "ALLOW", enabled: true, condition: { algorithms: allowList } });
    }
    if (denyList.length > 0) {
      rules.push({ name: "Denied algorithms", category: "ALGORITHM_RESTRICTION", effect: "DENY", enabled: true, condition: { algorithms: denyList } });
    }
    if (rules.length === 0) {
      setSubmitError("Add at least one allowed or denied algorithm.");
      return;
    }

    setSubmitting(true);
    setSubmitError(null);
    try {
      await api.policies.create(activeOrg.id, {
        name: name.trim(),
        description: description.trim() || undefined,
        rules,
        enforcementMode,
      });
      setIsModalOpen(false);
      await loadPolicies();
    } catch (err: any) {
      setSubmitError(err?.message || "The policy could not be saved.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E9EDE7] pb-6">
        <div>
          <h1 className="font-editorial text-3xl md:text-4xl font-bold text-[#1A1A1A] tracking-tight">
            Cryptographic Policies
          </h1>
          <p className="text-sm text-[#636863] mt-1.5 leading-relaxed">
            Rules that allow or deny algorithms for your organization&apos;s cryptographic operations.
          </p>
        </div>
        <Button
          onClick={() => {
            if (!requireAuth("create cryptographic policies")) return;
            setName("");
            setDescription("");
            setSubmitError(null);
            setIsModalOpen(true);
          }}
          className="shrink-0"
        >
          <Plus className="w-4 h-4 mr-1.5" /> Create Policy
        </Button>
      </div>

      {!authLoading && !activeOrg && (
        <div className="p-4 rounded-xl border border-dashed border-[#E9EDE7] bg-white text-xs text-[#636863]">
          Sign in to see and manage your organization&apos;s policies.
        </div>
      )}

      {loadError && (
        <div role="alert" className="p-3 rounded-lg border border-[#F2C9C9] bg-[#FDF2F2] text-xs text-[#B42318]">
          {loadError}
        </div>
      )}

      {loading ? (
        <div className="py-16 flex flex-col items-center justify-center text-[#767676]">
          <Loader2 className="w-6 h-6 animate-spin text-[#008031] mb-2" />
          <span className="text-xs">Loading policies…</span>
        </div>
      ) : activeOrg && policies.length === 0 && !loadError ? (
        <div className="p-12 text-center border border-dashed border-[#E9EDE7] rounded-2xl bg-white space-y-3">
          <div className="w-12 h-12 rounded-2xl bg-[#EAF3EC] text-[#008031] flex items-center justify-center mx-auto">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-[#1A1A1A]">No policies yet</h3>
            <p className="text-xs text-[#767676] max-w-sm mx-auto mt-1">
              Without a policy, the platform&apos;s built-in secure defaults apply. Create one to restrict algorithms further.
            </p>
          </div>
        </div>
      ) : (
        <div className="grid md:grid-cols-2 gap-6">
          {policies.map((p) => (
            <Card key={p.id} className="hover:shadow-card transition-shadow">
              <CardHeader>
                <div className="flex items-center justify-between gap-2">
                  <CardTitle className="text-lg font-semibold">{p.name}</CardTitle>
                  <Badge variant={p.status !== "ACTIVE" ? "outline" : p.enforcementMode === "ENFORCE" ? "default" : "warning"}>
                    {p.status !== "ACTIVE" ? "Archived" : p.enforcementMode === "ENFORCE" ? "Enforced" : p.enforcementMode === "AUDIT" ? "Audit only" : p.enforcementMode}
                  </Badge>
                </div>
                {p.description && <CardDescription className="text-xs text-[#636863] mt-1">{p.description}</CardDescription>}
              </CardHeader>
              <CardContent className="space-y-3 text-xs text-[#555555]">
                <div className="p-3 rounded-lg bg-[#FAF9F6] border border-[#E9EDE7] space-y-2">
                  <div><strong>Allowed algorithms:</strong> {algorithmsFor(p, "ALLOW")}</div>
                  <div><strong>Denied algorithms:</strong> {algorithmsFor(p, "DENY")}</div>
                  <div><strong>Rules:</strong> {Array.isArray(p.rules) ? p.rules.length : 0} · <strong>Version:</strong> {p.version}</div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Modal
        isOpen={isModalOpen}
        onClose={() => !submitting && setIsModalOpen(false)}
        title="Create Cryptographic Policy"
        description="Saved to your organization and applied by the policy engine to cryptographic operations."
      >
        <form onSubmit={handleCreatePolicy} className="space-y-4 text-xs">
          <div>
            <label className="font-medium text-[#1A1A1A] block mb-1.5">Policy Name *</label>
            <Input
              placeholder="e.g. Production algorithm baseline"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="font-medium text-[#1A1A1A] block mb-1.5">Description</label>
            <Input
              placeholder="e.g. Baseline for all production services"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          <div>
            <label className="font-medium text-[#1A1A1A] block mb-1.5">Allowed algorithms (comma-separated)</label>
            <Input value={allowed} onChange={(e) => setAllowed(e.target.value)} placeholder="e.g. AES-256-GCM, ED25519" />
          </div>

          <div>
            <label className="font-medium text-[#1A1A1A] block mb-1.5">Denied algorithms (comma-separated)</label>
            <Input value={denied} onChange={(e) => setDenied(e.target.value)} placeholder="e.g. MD5, SHA-1, 3DES" />
          </div>

          <fieldset>
            <legend className="font-medium text-[#1A1A1A] mb-1.5">Mode</legend>
            <div className="flex gap-4">
              <label className="flex items-center gap-1.5">
                <input type="radio" name="mode" checked={enforcementMode === "AUDIT"} onChange={() => setEnforcementMode("AUDIT")} />
                Audit only (log violations)
              </label>
              <label className="flex items-center gap-1.5">
                <input type="radio" name="mode" checked={enforcementMode === "ENFORCE"} onChange={() => setEnforcementMode("ENFORCE")} />
                Enforce (block violations)
              </label>
            </div>
          </fieldset>

          {submitError && (
            <div role="alert" className="p-2.5 rounded-lg border border-[#F2C9C9] bg-[#FDF2F2] text-[#B42318]">
              {submitError}
            </div>
          )}

          <div className="flex justify-end gap-3 pt-2">
            <Button type="button" variant="outline" size="sm" onClick={() => setIsModalOpen(false)} disabled={submitting}>
              Cancel
            </Button>
            <Button type="submit" size="sm" disabled={submitting}>
              {submitting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Saving...
                </>
              ) : (
                "Save Policy"
              )}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
