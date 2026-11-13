"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Modal } from "@/components/ui/modal";
import { 
  Plus, 
  Key, 
  Copy, 
  Check, 
  AlertCircle, 
  Loader2, 
  Trash2, 
  RotateCw, 
  ShieldCheck, 
  Power, 
  SlidersHorizontal 
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api-client";
import { API_BASE_URL } from "@/lib/api-base";

const API_URL = API_BASE_URL;

/** "203.0.113.7, 10.0.0.0/8" or one per line -> ["203.0.113.7", "10.0.0.0/8"]. The API validates them. */
function parseIpList(text: string): string[] {
  return text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
}

interface ApiCredentialItem {
  id: string;
  name: string;
  prefix: string;
  environmentId: string;
  scopes?: string[];
  allowedIps?: string[];
  status?: "ACTIVE" | "DISABLED" | "REVOKED" | "EXPIRED";
  revokedAt?: string | null;
  lastUsedAt?: string | null;
  createdAt: string;
}

interface EnvOption {
  id: string;
  name: string;
  projectName: string;
  type: string;
}

const AVAILABLE_SCOPES = [
  { id: "crypto:encrypt", label: "Encrypt", desc: "Encrypt data. Enough for a server that only saves data" },
  { id: "crypto:decrypt", label: "Decrypt", desc: "Read encrypted data back. Give it only to the service that shows the data" },
  { id: "crypto:execute", label: "All cryptographic operations", desc: "Encrypt AND decrypt, sign, verify and hash" },
  { id: "crypto:read", label: "Cryptographic Policy & Config Read", desc: "View algorithms and active policies" },
  { id: "keys:read", label: "Keys Read", desc: "List and view cryptographic key metadata" },
  { id: "keys:create", label: "Keys Create", desc: "Register and create cryptographic keys" },
  { id: "keys:rotate", label: "Keys Rotate", desc: "Rotate keys to new cryptographic versions" },
  { id: "pqc:execute", label: "PQC Operations", desc: "ML-KEM encapsulation, decapsulation, ML-DSA signatures" },
  { id: "certificates:read", label: "Certificates Read", desc: "List X.509 certificates and CAs" },
  { id: "certificates:issue", label: "Certificates Issue", desc: "Issue new X.509 certificates" },
  { id: "cbom:read", label: "CBOM Read", desc: "Export CycloneDX CBOM and view findings" },
  { id: "advanced:execute", label: "Advanced Cryptography", desc: "Execute ZK proofs, FHE evaluations, MPC sessions" },
  { id: "webhooks:write", label: "Webhooks Manage", desc: "Register endpoints and inspect deliveries" },
  { id: "jobs:write", label: "Jobs Execute", desc: "Dispatch async cryptographic jobs" },
  { id: "os:posture", label: "Posture Read", desc: "Read the cryptographic posture report" },
  { id: "usage:read", label: "Usage Read", desc: "Read metered operation usage" },
];

export default function ApiKeysPage() {
  const { activeOrg, requireAuth } = useAuth();
  const [credentials, setCredentials] = useState<ApiCredentialItem[]>([]);
  const [environments, setEnvironments] = useState<EnvOption[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Generate Key Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [allowedIpsText, setAllowedIpsText] = useState("");
  // Edit allowed IPs of an existing key
  const [ipsTarget, setIpsTarget] = useState<ApiCredentialItem | null>(null);
  const [ipsText, setIpsText] = useState("");
  const [savingIps, setSavingIps] = useState(false);
  const [name, setName] = useState("");
  const [selectedEnvId, setSelectedEnvId] = useState("");
  // Encrypt-only by default: a key on a server that saves data should not be able to read it back.
  // A stolen key that can decrypt exposes every record (docs/recovery/breach-drill-2026-11.md).
  const [selectedScopes, setSelectedScopes] = useState<string[]>([
    "crypto:encrypt",
    "crypto:read",
    "keys:read",
  ]);
  const canEncrypt = selectedScopes.some((s) => s === "crypto:encrypt" || s === "crypto:execute");
  const canDecrypt = selectedScopes.some((s) => s === "crypto:decrypt" || s === "crypto:execute");
  const [submitting, setSubmitting] = useState(false);
  const [generatedSecret, setGeneratedSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Rotate Key State
  const [rotateTarget, setRotateTarget] = useState<ApiCredentialItem | null>(null);
  const [rotating, setRotating] = useState(false);
  const [rotatedSecret, setRotatedSecret] = useState<string | null>(null);
  const [copiedRotated, setCopiedRotated] = useState(false);

  // Action status IDs
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    if (!activeOrg) {
      setCredentials([
        {
          id: "demo-cred-preview-1",
          name: "Sample Cryptographic Gateway (Preview)",
          prefix: "amk_live_demo99a...",
          environmentId: "demo-env-1",
          scopes: ["crypto:execute", "crypto:read", "pqc:execute"],
          status: "ACTIVE",
          createdAt: new Date().toISOString(),
        },
      ]);
      setEnvironments([
        { id: "demo-env-1", name: "Production", projectName: "Sample Cryptographic Service", type: "production" },
      ]);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      // First try canonical /api/v1/credentials
      let credItems: ApiCredentialItem[] = [];
      try {
        const v1Res = await fetch(`${API_URL}/api/v1/credentials`, {
          headers: { "x-organization-id": activeOrg.id },
          credentials: "include",
        });
        if (v1Res.ok) {
          const v1Json = await v1Res.json();
          credItems = v1Json.data || [];
        }
      } catch {}

      if (credItems.length === 0) {
        // Fallback to legacy org endpoint
        const credData = await api.credentials.list(activeOrg.id);
        credItems = credData.credentials || [];
      }
      setCredentials(credItems);

      // Fetch projects to list valid environments
      const projData = await api.projects.list(activeOrg.id);
      const envList: EnvOption[] = [];
      if (projData.projects) {
        for (const p of projData.projects) {
          if (p.environments) {
            for (const env of p.environments) {
              envList.push({
                id: env.id,
                name: env.name,
                projectName: p.name,
                type: env.type,
              });
            }
          }
        }
      }
      setEnvironments(envList);
      if (envList.length > 0) {
        setSelectedEnvId((prev) => prev || envList[0].id);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load credentials.");
    } finally {
      setLoading(false);
    }
  }, [activeOrg]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleOpenModal = () => {
    if (!requireAuth("generate live API credentials")) return;
    setName("");
    setGeneratedSecret(null);
    setCopied(false);
    setSelectedScopes(["crypto:encrypt", "crypto:read", "keys:read"]);
    setAllowedIpsText("");
    if (environments.length > 0) {
      setSelectedEnvId(environments[0].id);
    }
    setIsModalOpen(true);
  };

  const handleToggleScope = (scopeId: string) => {
    setSelectedScopes((prev) =>
      prev.includes(scopeId) ? prev.filter((s) => s !== scopeId) : [...prev, scopeId]
    );
  };

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !activeOrg) return;

    if (!selectedEnvId) {
      alert("Please select a project environment before generating credentials.");
      return;
    }

    const envObj = environments.find((e) => e.id === selectedEnvId);

    setSubmitting(true);
    try {
      // Call canonical /api/v1/credentials endpoint
      const res = await fetch(`${API_URL}/api/v1/credentials`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-organization-id": activeOrg.id,
        },
        credentials: "include",
        body: JSON.stringify({
          name: name.trim(),
          environment: envObj?.type === "production" ? "live" : "test",
          environmentId: selectedEnvId,
          scopes: selectedScopes,
          ...(parseIpList(allowedIpsText).length ? { allowedIps: parseIpList(allowedIpsText) } : {}),
        }),
      });

      const json = await res.json();
      if (!res.ok) {
        throw new Error(json.error?.message || "Failed to generate credential");
      }

      setGeneratedSecret(json.data.rawApiKey);
      await loadData();
    } catch (err: any) {
      alert(err.message || "Failed to generate credential.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleCopySecret = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleToggleStatus = async (item: ApiCredentialItem) => {
    if (!requireAuth("modify API credential status")) return;
    if (!activeOrg) return;
    const currentStatus = item.status || (item.revokedAt ? "REVOKED" : "ACTIVE");
    if (currentStatus === "REVOKED") return;

    const newStatus = currentStatus === "ACTIVE" ? "DISABLED" : "ACTIVE";
    setTogglingId(item.id);

    try {
      const res = await fetch(`${API_URL}/api/v1/credentials/${item.id}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "x-organization-id": activeOrg.id,
        },
        credentials: "include",
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) {
        const j = await res.json();
        throw new Error(j.error?.message || "Failed to update status");
      }
      await loadData();
    } catch (err: any) {
      alert(err.message || "Failed to toggle status");
    } finally {
      setTogglingId(null);
    }
  };

  const handleOpenIps = (item: ApiCredentialItem) => {
    if (!requireAuth("limit an API key to IP addresses")) return;
    setIpsTarget(item);
    setIpsText((item.allowedIps || []).join("\n"));
  };

  const handleSaveIps = async () => {
    if (!ipsTarget || !activeOrg) return;
    setSavingIps(true);
    try {
      const list = parseIpList(ipsText);
      const res = await fetch(`${API_URL}/api/v1/credentials/${ipsTarget.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", "x-organization-id": activeOrg.id },
        credentials: "include",
        body: JSON.stringify({ allowedIps: list.length ? list : null }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error?.message || "Failed to save allowed IPs");
      setIpsTarget(null);
      await loadData();
    } catch (err: any) {
      alert(err.message || "Failed to save allowed IPs");
    } finally {
      setSavingIps(false);
    }
  };

  const handleOpenRotate = (item: ApiCredentialItem) => {
    if (!requireAuth("rotate API credentials")) return;
    setRotateTarget(item);
    setRotatedSecret(null);
    setCopiedRotated(false);
  };

  const handleConfirmRotate = async () => {
    if (!rotateTarget || !activeOrg) return;
    setRotating(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/credentials/${rotateTarget.id}/rotate`, {
        method: "POST",
        headers: { "x-organization-id": activeOrg.id },
        credentials: "include",
      });
      const json = await res.json();
      if (!res.ok) {
        throw new Error(json.error?.message || "Failed to rotate credential");
      }
      setRotatedSecret(json.data.rawApiKey);
      await loadData();
    } catch (err: any) {
      alert(err.message || "Failed to rotate key");
      setRotateTarget(null);
    } finally {
      setRotating(false);
    }
  };

  const handleRevoke = async (id: string) => {
    if (!requireAuth("revoke API credentials")) return;
    if (!activeOrg) return;
    if (!confirm("Are you sure you want to permanently revoke this credential? All applications using it will immediately fail.")) return;
    setRevokingId(id);
    try {
      const res = await fetch(`${API_URL}/api/v1/credentials/${id}`, {
        method: "DELETE",
        headers: { "x-organization-id": activeOrg.id },
        credentials: "include",
      });
      if (!res.ok) {
        const j = await res.json();
        throw new Error(j.error?.message || "Failed to revoke credential");
      }
      await loadData();
    } catch (err: any) {
      alert(err.message || "Failed to revoke credential.");
    } finally {
      setRevokingId(null);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E9EDE7] pb-6">
        <div>
          <h1 className="font-editorial text-3xl md:text-4xl font-bold text-[#1A1A1A] tracking-tight">
            API Credentials & Keys
          </h1>
          <p className="text-sm text-[#636863] mt-1.5 leading-relaxed">
            Manage granularly scoped credentials (<code className="px-1.5 py-0.5 rounded bg-[#F3F2EE] font-mono text-xs text-[#008031]">am_live_...</code> and <code className="px-1.5 py-0.5 rounded bg-[#F3F2EE] font-mono text-xs text-[#008031]">am_test_...</code>) for programmatic access in{" "}
            <span className="font-medium text-[#1A1A1A]">{activeOrg?.name || "your organization"}</span>.
          </p>
        </div>
        <Button onClick={handleOpenModal} className="shrink-0" disabled={environments.length === 0}>
          <Plus className="w-4 h-4 mr-1.5" /> Generate Key
        </Button>
      </div>

      {/* Security Info */}
      <div className="p-4 rounded-xl border border-[#C8E0CF] bg-[#EAF3EC] text-xs text-[#008031] flex items-start gap-3">
        <ShieldCheck className="w-4 h-4 shrink-0 mt-0.5" />
        <div>
          <strong>Zero-Secret Persistence:</strong> Plaintext secret keys are revealed exactly once upon creation or rotation. Only SHA-256 hashes are stored in the database. Requests require valid permissions and least-privilege scopes.
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-red-200 bg-red-50 text-red-700 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Credentials Table */}
      {loading ? (
        <div className="py-20 flex flex-col items-center justify-center text-[#767676]">
          <Loader2 className="w-6 h-6 animate-spin text-[#008031] mb-2" />
          <span className="text-xs">Loading credentials...</span>
        </div>
      ) : credentials.length === 0 ? (
        <div className="p-12 text-center border border-dashed border-[#E9EDE7] rounded-2xl bg-white space-y-4">
          <div className="w-12 h-12 rounded-2xl bg-[#EAF3EC] text-[#008031] flex items-center justify-center mx-auto">
            <Key className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-[#1A1A1A]">No active credentials</h3>
            <p className="text-xs text-[#767676] max-w-sm mx-auto mt-1">
              Generate a scoped API credential to authenticate external clients, the TypeScript/Python SDKs, and CLI tools.
            </p>
          </div>
          <Button onClick={handleOpenModal} size="sm" disabled={environments.length === 0}>
            <Plus className="w-3.5 h-3.5 mr-1" /> Generate Key
          </Button>
        </div>
      ) : (
        <Card className="border-[#E9EDE7]">
          <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="API credentials table">
            <table className="w-full text-xs text-left">
              <thead className="bg-[#FAF9F6] text-[#767676] border-b border-[#E9EDE7]">
                <tr>
                  <th className="px-5 py-3.5 font-semibold">Credential Name</th>
                  <th className="px-5 py-3.5 font-semibold">Key Token Prefix</th>
                  <th className="px-5 py-3.5 font-semibold">Scopes Granted</th>
                  <th className="px-5 py-3.5 font-semibold">Environment</th>
                  <th className="px-5 py-3.5 font-semibold">Status</th>
                  <th className="px-5 py-3.5 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E9EDE7]">
                {credentials.map((k) => {
                  const status = k.status || (k.revokedAt ? "REVOKED" : "ACTIVE");
                  const isRevoked = status === "REVOKED";
                  const isDisabled = status === "DISABLED";
                  const envObj = environments.find((e) => e.id === k.environmentId);
                  const envLabel = envObj ? `${envObj.projectName} / ${envObj.name}` : "Environment";
                  const isLive = k.prefix.startsWith("am_live_");

                  return (
                    <tr key={k.id} className="hover:bg-[#FAF9F6] transition-colors">
                      <td className="px-5 py-4">
                        <div className="font-semibold text-[#1A1A1A]">{k.name}</div>
                        <div className="text-[10px] text-[#8C928C] font-mono">ID: {k.id}</div>
                        <div className="text-[10px] text-[#636863] mt-0.5">
                          IPs: {k.allowedIps && k.allowedIps.length ? k.allowedIps.join(", ") : "any address"}
                        </div>
                      </td>
                      <td className="px-5 py-4 font-mono text-[#555555]">
                        <div className="flex items-center gap-1.5">
                          <Badge variant="outline" className={`font-mono text-[10px] ${isLive ? "bg-purple-50 text-purple-700 border-purple-200" : "bg-blue-50 text-blue-700 border-blue-200"}`}>
                            {isLive ? "LIVE" : "TEST"}
                          </Badge>
                          <span>{k.prefix}••••••••</span>
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        <div className="flex flex-wrap gap-1 max-w-xs">
                          {k.scopes && k.scopes.length > 0 ? (
                            k.scopes.slice(0, 3).map((sc) => (
                              <span key={sc} className="px-1.5 py-0.5 rounded bg-[#F3F2EE] font-mono text-[9px] text-[#555555]">
                                {sc}
                              </span>
                            ))
                          ) : (
                            <span className="text-[#8C928C] italic text-[11px]">Full Legacy Access</span>
                          )}
                          {k.scopes && k.scopes.length > 3 && (
                            <span className="px-1.5 py-0.5 rounded bg-[#F3F2EE] font-mono text-[9px] text-[#555555]">
                              +{k.scopes.length - 3} more
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        <Badge variant="outline" className="text-[11px]">{envLabel}</Badge>
                      </td>
                      <td className="px-5 py-4">
                        <Badge
                          variant="outline"
                          className={`text-[10px] font-semibold ${
                            isRevoked
                              ? "bg-red-50 text-red-700 border-red-200"
                              : isDisabled
                              ? "bg-amber-50 text-amber-700 border-amber-200"
                              : "bg-green-50 text-green-700 border-green-200"
                          }`}
                        >
                          {status}
                        </Badge>
                      </td>
                      <td className="px-5 py-4 text-right">
                        {!isRevoked && (
                          <div className="flex items-center justify-end gap-1.5">
                            <Button
                              variant="outline"
                              size="sm"
                              title="Rotate Key Material"
                              onClick={() => handleOpenRotate(k)}
                              className="text-xs h-7 px-2"
                            >
                              <RotateCw className="w-3 h-3 mr-1" /> Rotate
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              title="Limit this key to your server's IP addresses"
                              onClick={() => handleOpenIps(k)}
                              className="text-xs h-7 px-2"
                            >
                              Allowed IPs
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              title={isDisabled ? "Enable Key" : "Disable Key"}
                              disabled={togglingId === k.id}
                              onClick={() => handleToggleStatus(k)}
                              className={`text-xs h-7 px-2 ${isDisabled ? "text-[#008031]" : "text-amber-600 hover:text-amber-700"}`}
                            >
                              {togglingId === k.id ? (
                                <Loader2 className="w-3 h-3 animate-spin" />
                              ) : (
                                <Power className="w-3 h-3 mr-1" />
                              )}
                              {isDisabled ? "Enable" : "Disable"}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              title="Revoke Key Permanently"
                              aria-label={`Revoke API key ${k.name} permanently`}
                              disabled={revokingId === k.id}
                              onClick={() => handleRevoke(k.id)}
                              className="text-red-600 hover:text-red-700 hover:bg-red-50 text-xs h-7 px-2"
                            >
                              {revokingId === k.id ? (
                                <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" />
                              ) : (
                                <Trash2 className="w-3 h-3" aria-hidden="true" />
                              )}
                            </Button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Generate Key Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => !submitting && setIsModalOpen(false)}
        title={generatedSecret ? "Your New API Secret Key" : "Generate API Credential"}
        description={
          generatedSecret
            ? "Save this secret key in a secure vault or .env file now. For security reasons, it will never be displayed again."
            : "Create a credential scoped with least-privilege permissions for programmatic access."
        }
      >
        {generatedSecret ? (
          <div className="space-y-4 text-xs">
            <div className="p-3.5 rounded-xl border border-[#C8E0CF] bg-[#EAF3EC] text-[#008031] font-mono break-all flex items-center justify-between gap-3">
              <span className="select-all font-semibold">{generatedSecret}</span>
              <Button size="sm" variant="outline" onClick={() => handleCopySecret(generatedSecret)} className="shrink-0 bg-white">
                {copied ? <Check className="w-3.5 h-3.5 mr-1 text-[#008031]" /> : <Copy className="w-3.5 h-3.5 mr-1" />}
                {copied ? "Copied" : "Copy"}
              </Button>
            </div>
            <div className="flex justify-end pt-2">
              <Button size="sm" onClick={() => setIsModalOpen(false)}>Done</Button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleGenerate} className="space-y-4 text-xs">
            <div>
              <label className="font-medium text-[#1A1A1A] block mb-1.5">Credential Name *</label>
              <Input
                placeholder="e.g. Production Microservice Gateway"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="font-medium text-[#1A1A1A] block mb-1.5">Target Environment *</label>
              <select
                value={selectedEnvId}
                onChange={(e) => setSelectedEnvId(e.target.value)}
                className="w-full h-10 rounded-lg border border-[#E9EDE7] bg-white px-3 text-xs text-[#1A1A1A] focus:border-[#008031]"
                required
              >
                {environments.map((e) => (
                  <option key={e.id} value={e.id}>
                    {e.projectName} &rarr; {e.name} ({e.type})
                  </option>
                ))}
              </select>
            </div>

            {/* Granular Scopes Selection */}
            <div className="space-y-1.5 pt-1">
              <label htmlFor="new-key-allowed-ips" className="font-medium text-[#1A1A1A] block">
                Allowed IP addresses <span className="font-normal text-[#767676]">(optional, recommended)</span>
              </label>
              <textarea
                id="new-key-allowed-ips"
                value={allowedIpsText}
                onChange={(e) => setAllowedIpsText(e.target.value)}
                rows={2}
                placeholder="203.0.113.7, 10.0.0.0/8"
                className="w-full rounded-lg border border-[#E9EDE7] bg-white px-3 py-2 text-xs font-mono text-[#1A1A1A] focus:border-[#008031]"
              />
              <p className="text-[10px] text-[#767676] leading-relaxed">
                Your server&apos;s public IPs or CIDR ranges, separated by commas or new lines. A copy of the key used from
                anywhere else is refused. Leave empty to allow any address.
              </p>
            </div>

            <div className="space-y-2 pt-1">
              <label className="font-medium text-[#1A1A1A] block">Granted Scopes (Least Privilege)</label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-48 overflow-y-auto p-1 border border-[#E9EDE7] rounded-xl bg-[#FAF9F6]">
                {AVAILABLE_SCOPES.map((sc) => {
                  const isChecked = selectedScopes.includes(sc.id);
                  return (
                    <label
                      key={sc.id}
                      className={`flex items-start gap-2 p-2 rounded-lg border text-xs cursor-pointer transition-colors ${
                        isChecked ? "bg-[#EAF3EC] border-[#C8E0CF]" : "bg-white border-[#E9EDE7] hover:bg-[#F3F2EE]"
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => handleToggleScope(sc.id)}
                        className="mt-0.5 rounded text-[#008031] focus:ring-[#008031]"
                      />
                      <div className="min-w-0">
                        <div className="font-semibold text-[#1A1A1A] leading-tight">{sc.label}</div>
                        <div className="text-[10px] text-[#767676] font-mono">{sc.id}</div>
                      </div>
                    </label>
                  );
                })}
              </div>
              {canEncrypt && canDecrypt && (
                <p role="alert" className="text-[11px] leading-relaxed text-[#8C6D1F] bg-[#FFF8E6] border border-[#F2DFA7] rounded-lg p-2.5">
                  This key can both encrypt and decrypt. If it sits on a server an attacker can reach, they can read
                  every record. Safer: one key with only Encrypt where data is saved, and a separate key with Decrypt
                  only in the service that shows the data.
                </p>
              )}
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <Button type="button" variant="outline" size="sm" onClick={() => setIsModalOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" size="sm" disabled={submitting}>
                {submitting ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Generating...
                  </>
                ) : (
                  "Generate Key"
                )}
              </Button>
            </div>
          </form>
        )}
      </Modal>

      {/* Allowed IPs Modal */}
      <Modal
        isOpen={!!ipsTarget}
        onClose={() => !savingIps && setIpsTarget(null)}
        title={`Allowed IPs: ${ipsTarget?.name || ""}`}
        description="Requests with this key from any other address get 403 IP_NOT_ALLOWED. Leave empty to allow any address."
        maxWidth="max-w-md"
      >
        <div className="space-y-3 text-xs">
          <label htmlFor="edit-key-allowed-ips" className="font-medium text-[#1A1A1A] block">IP addresses or CIDR ranges</label>
          <textarea
            id="edit-key-allowed-ips"
            value={ipsText}
            onChange={(e) => setIpsText(e.target.value)}
            rows={4}
            placeholder={"203.0.113.7\n10.0.0.0/8"}
            className="w-full rounded-lg border border-[#E9EDE7] bg-white px-3 py-2 font-mono text-[#1A1A1A] focus:border-[#008031]"
          />
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" size="sm" onClick={() => setIpsTarget(null)} disabled={savingIps}>
              Cancel
            </Button>
            <Button type="button" size="sm" onClick={handleSaveIps} disabled={savingIps}>
              {savingIps ? "Saving…" : "Save"}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Rotate Key Modal */}
      <Modal
        isOpen={!!rotateTarget}
        onClose={() => !rotating && setRotateTarget(null)}
        title={rotatedSecret ? "New Rotated Secret Key" : `Rotate Key: ${rotateTarget?.name}`}
        description={
          rotatedSecret
            ? "Save this new rotated secret key now. The previous key material has been immediately invalidated."
            : "Rotating this credential will immediately invalidate the previous secret key and generate a new raw key with the same scopes."
        }
      >
        {rotatedSecret ? (
          <div className="space-y-4 text-xs">
            <div className="p-3.5 rounded-xl border border-[#C8E0CF] bg-[#EAF3EC] text-[#008031] font-mono break-all flex items-center justify-between gap-3">
              <span className="select-all font-semibold">{rotatedSecret}</span>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  navigator.clipboard.writeText(rotatedSecret);
                  setCopiedRotated(true);
                  setTimeout(() => setCopiedRotated(false), 2000);
                }}
                className="shrink-0 bg-white"
              >
                {copiedRotated ? <Check className="w-3.5 h-3.5 mr-1 text-[#008031]" /> : <Copy className="w-3.5 h-3.5 mr-1" />}
                {copiedRotated ? "Copied" : "Copy"}
              </Button>
            </div>
            <div className="flex justify-end pt-2">
              <Button size="sm" onClick={() => setRotateTarget(null)}>Done</Button>
            </div>
          </div>
        ) : (
          <div className="space-y-4 text-xs">
            <p className="text-[#555555]">
              Are you sure you want to rotate <strong className="text-[#1A1A1A]">{rotateTarget?.name}</strong>?
              Any microservice currently using the old token will experience authentication failures until updated.
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <Button variant="outline" size="sm" onClick={() => setRotateTarget(null)}>
                Cancel
              </Button>
              <Button size="sm" onClick={handleConfirmRotate} disabled={rotating}>
                {rotating ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <RotateCw className="w-3.5 h-3.5 mr-1.5" />}
                {rotating ? "Rotating..." : "Rotate Key Now"}
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}