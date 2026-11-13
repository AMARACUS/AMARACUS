"use client";

import React, { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { 
  Terminal, 
  Play, 
  Copy, 
  Check, 
  RotateCw, 
  Send, 
  Code2, 
  Layers, 
  ShieldCheck, 
  Key, 
  Fingerprint, 
  Compass, 
  Cpu, 
  Webhook, 
  Clock, 
  Activity 
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { API_BASE_URL } from "@/lib/api-base";

interface EndpointPreset {
  id: string;
  category: string;
  name: string;
  method: "GET" | "POST" | "PATCH" | "DELETE";
  path: string;
  description: string;
  body?: Record<string, any>;
  headers?: Record<string, string>;
}

const ENDPOINT_PRESETS: EndpointPreset[] = [
  // Phase 10.5 Universal Cryptographic Runtime
  {
    id: "universal-crypto-execute",
    category: "Universal Crypto Runtime (Phase 10.5)",
    name: "Execute Operation (Encrypt)",
    method: "POST",
    path: "/api/v1/crypto/execute",
    description: "Executes an operation across the 6-state lifecycle runtime (REQUESTED -> VALIDATING -> AUTHORIZING -> RESOLVING -> EXECUTING -> COMPLETED).",
    body: {
      type: "ENCRYPT",
      algorithm: "AES-256-GCM",
      policy: "DEFAULT_SECURE",
      params: {
        plaintext: "Top secret cryptographic infrastructure payload 2026",
        key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        keyEncoding: "hex",
        aad: "tenant-amaracus-primary"
      }
    }
  },
  {
    id: "universal-crypto-operations",
    category: "Universal Crypto Runtime (Phase 10.5)",
    name: "List Runtime Operations History",
    method: "GET",
    path: "/api/v1/crypto/operations",
    description: "Inspect persisted cryptographic execution records audited with zero secret or plaintext leakage.",
  },
  {
    id: "universal-crypto-policies",
    category: "Universal Crypto Runtime (Phase 10.5)",
    name: "List Runtime Governance Policies",
    method: "GET",
    path: "/api/v1/crypto/policies",
    description: "Inspect active cryptographic security policies (DEFAULT_SECURE, FIPS_COMPLIANT, PQC_PREFERRED).",
  },
  // Post-Quantum Cryptography
  {
    id: "pqc-algorithms",
    category: "Post-Quantum Cryptography",
    name: "List PQC Algorithms",
    method: "GET",
    path: "/api/v1/pqc/algorithms",
    description: "Get list of NIST FIPS-standardized post-quantum algorithms (ML-KEM-768, ML-DSA-65).",
  },
  {
    id: "pqc-keypair",
    category: "Post-Quantum Cryptography",
    name: "Generate PQC Keypair (ML-KEM-768)",
    method: "POST",
    path: "/api/v1/pqc/keypair",
    description: "Generate an authentic NIST FIPS 203 ML-KEM-768 lattice-based keypair.",
    body: {
      algorithm: "ML_KEM_768",
    },
  },
  {
    id: "pqc-keypair-dsa",
    category: "Post-Quantum Cryptography",
    name: "Generate PQC Keypair (ML-DSA-65)",
    method: "POST",
    path: "/api/v1/pqc/keypair",
    description: "Generate an authentic NIST FIPS 204 ML-DSA-65 lattice-based signature keypair.",
    body: {
      algorithm: "ML_DSA_65",
    },
  },

  // Classical Cryptography
  {
    id: "crypto-algorithms",
    category: "Classical Cryptography",
    name: "List Cryptographic Algorithms",
    method: "GET",
    path: "/api/v1/crypto/algorithms",
    description: "Query full registry of symmetric, asymmetric, and hash algorithms.",
  },
  {
    id: "crypto-policies",
    category: "Classical Cryptography",
    name: "List Cryptographic Policies",
    method: "GET",
    path: "/api/v1/crypto/policies",
    description: "Inspect active cryptographic security policies and baseline enforcement.",
  },
  {
    id: "crypto-encrypt",
    category: "Classical Cryptography",
    name: "AES-256-GCM Encryption",
    method: "POST",
    path: "/api/v1/crypto/encrypt",
    description: "Encrypt payload using AES-256-GCM authenticated encryption.",
    body: {
      algorithm: "AES_256_GCM",
      plaintext: "Confidential payment transaction payload 2026",
      key: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
    },
  },

  // Key Management & BYOK
  {
    id: "keys-list",
    category: "Key Management",
    name: "List Managed Keys",
    method: "GET",
    path: "/api/v1/keys",
    description: "List cryptographic keys and their active versions.",
  },
  {
    id: "keys-providers",
    category: "Key Management",
    name: "Provider Health & Discovery",
    method: "GET",
    path: "/api/v1/keys/providers",
    description: "Check availability and status of KMS backends and HSM providers.",
  },

  // PKI & Certificates
  {
    id: "certs-list",
    category: "PKI & Certificates",
    name: "List Issued Certificates",
    method: "GET",
    path: "/api/v1/pki/certificates",
    description: "Query all active and revoked X.509 certificates.",
  },
  {
    id: "certs-cas",
    category: "PKI & Certificates",
    name: "List Certificate Authorities",
    method: "GET",
    path: "/api/v1/pki/certificate-authorities",
    description: "List Root and Intermediate Certificate Authorities.",
  },

  // Cryptographic Intelligence & CBOM
  {
    id: "cbom-export",
    category: "Cryptographic Intelligence & CBOM",
    name: "Export CycloneDX CBOM",
    method: "GET",
    path: "/api/v1/crypto/cbom/export?format=cyclonedx",
    description: "Export formal CycloneDX 1.6 Cryptographic Bill of Materials.",
  },
  {
    id: "crypto-findings",
    category: "Cryptographic Intelligence & CBOM",
    name: "List Cryptographic Findings",
    method: "GET",
    path: "/api/v1/crypto/findings",
    description: "View algorithmic compliance findings, deprecated cipher warnings, and PQC readiness.",
  },

  // Advanced Cryptography
  {
    id: "adv-zk-circuits",
    category: "Advanced Cryptography",
    name: "List ZK Circuits (preview)",
    method: "GET",
    path: "/api/v1/advanced/zk/circuits",
    description: "List registered Zero-Knowledge circuits. Preview: Schnorr/Pedersen proofs only (no Groth16, PLONK or Bulletproofs).",
  },
  {
    id: "adv-fhe-keys",
    category: "Advanced Cryptography",
    name: "List FHE Keys (preview)",
    method: "GET",
    path: "/api/v1/advanced/fhe/keys",
    description: "List FHE key sets (Microsoft SEAL BFV). Preview: keys are held by the server.",
  },
  {
    id: "adv-mpc-sessions",
    category: "Advanced Cryptography",
    name: "List MPC Sessions (preview)",
    method: "GET",
    path: "/api/v1/advanced/mpc/sessions",
    description: "List additive secret-sharing MPC sessions. Preview: runs inside one server process.",
  },
  {
    id: "adv-threshold-keys",
    category: "Advanced Cryptography",
    name: "List Threshold Keys (preview)",
    method: "GET",
    path: "/api/v1/advanced/threshold/keys",
    description: "List threshold signing keys. Preview: not a vetted FROST implementation.",
  },

  // Platform & Webhooks
  {
    id: "health",
    category: "Platform & Observability",
    name: "Platform Health Check",
    method: "GET",
    path: "/api/v1/health",
    description: "Public health check and service metadata.",
  },
  {
    id: "auth-me",
    category: "Platform & Observability",
    name: "Principal Identity (/auth/me)",
    method: "GET",
    path: "/api/v1/auth/me",
    description: "Inspect caller identity, organization context, and granted scopes.",
  },
  {
    id: "webhooks-list",
    category: "Platform & Observability",
    name: "List Webhook Endpoints",
    method: "GET",
    path: "/api/v1/webhooks",
    description: "List event subscription endpoints and health.",
  },
  {
    id: "usage-query",
    category: "Platform & Observability",
    name: "Query API Usage Telemetry",
    method: "GET",
    path: "/api/v1/usage",
    description: "Retrieve aggregated request counts, latencies, and error rates.",
  },
];

export default function ApiExplorerPage() {
  const { activeOrg } = useAuth();

  const [selectedPreset, setSelectedPreset] = useState<EndpointPreset>(ENDPOINT_PRESETS[0]);
  const [method, setMethod] = useState<"GET" | "POST" | "PATCH" | "DELETE">(ENDPOINT_PRESETS[0].method);
  const [path, setPath] = useState<string>(ENDPOINT_PRESETS[0].path);
  const [requestBody, setRequestBody] = useState<string>(
    ENDPOINT_PRESETS[0].body ? JSON.stringify(ENDPOINT_PRESETS[0].body, null, 2) : ""
  );
  const [apiKeyHeader, setApiKeyHeader] = useState<string>("");
  const [idempotencyKey, setIdempotencyKey] = useState<string>("");
  const [searchFilter, setSearchFilter] = useState<string>("");

  const [executing, setExecuting] = useState(false);
  const [responseStatus, setResponseStatus] = useState<number | null>(null);
  const [responseHeaders, setResponseHeaders] = useState<Record<string, string>>({});
  const [responseBody, setResponseBody] = useState<string | null>(null);
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [requestId, setRequestId] = useState<string | null>(null);

  const [copiedCurl, setCopiedCurl] = useState(false);
  const [copiedResp, setCopiedResp] = useState(false);

  // Load preset selection
  const handleSelectPreset = (preset: EndpointPreset) => {
    setSelectedPreset(preset);
    setMethod(preset.method);
    setPath(preset.path);
    setRequestBody(preset.body ? JSON.stringify(preset.body, null, 2) : "");
    setResponseStatus(null);
    setResponseBody(null);
    setLatencyMs(null);
    setRequestId(null);
  };

  // Generate equivalent cURL string
  const generateCurlCommand = () => {
    const origin = API_BASE_URL;
    let curl = `curl -X ${method} "${origin}${path}" \\\n  -H "Accept: application/json"`;

    if (apiKeyHeader.trim()) {
      curl += ` \\\n  -H "Authorization: Bearer ${apiKeyHeader.trim()}"`;
    }

    if (idempotencyKey.trim()) {
      curl += ` \\\n  -H "Idempotency-Key: ${idempotencyKey.trim()}"`;
    }

    if (activeOrg?.id) {
      curl += ` \\\n  -H "x-organization-id: ${activeOrg.id}"`;
    }

    if (method !== "GET" && requestBody.trim()) {
      curl += ` \\\n  -H "Content-Type: application/json" \\\n  -d '${requestBody.replace(/'/g, "'\\''")}'`;
    }

    return curl;
  };

  const handleCopyCurl = () => {
    navigator.clipboard.writeText(generateCurlCommand());
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  const handleCopyResponse = () => {
    if (responseBody) {
      navigator.clipboard.writeText(responseBody);
      setCopiedResp(true);
      setTimeout(() => setCopiedResp(false), 2000);
    }
  };

  const handleSendRequest = async () => {
    setExecuting(true);
    setResponseStatus(null);
    setResponseBody(null);
    setLatencyMs(null);
    setRequestId(null);

    const startTime = performance.now();

    try {
      const headers: Record<string, string> = {
        Accept: "application/json",
      };

      if (apiKeyHeader.trim()) {
        headers["Authorization"] = `Bearer ${apiKeyHeader.trim()}`;
      }

      if (idempotencyKey.trim()) {
        headers["Idempotency-Key"] = idempotencyKey.trim();
      }

      if (activeOrg?.id) {
        headers["x-organization-id"] = activeOrg.id;
      }

      if (method !== "GET" && requestBody.trim()) {
        headers["Content-Type"] = "application/json";
      }

      const apiOrigin = API_BASE_URL;
      const res = await fetch(`${apiOrigin}${path}`, {
        method,
        headers,
        body: method !== "GET" && requestBody.trim() ? requestBody : undefined,
        credentials: "include", // Sends session cookies if present
      });

      const elapsed = Math.round(performance.now() - startTime);
      setLatencyMs(elapsed);
      setResponseStatus(res.status);

      const respReqId = res.headers.get("x-request-id");
      setRequestId(respReqId);

      const resHeadersObj: Record<string, string> = {};
      res.headers.forEach((val, key) => {
        resHeadersObj[key] = val;
      });
      setResponseHeaders(resHeadersObj);

      const contentType = res.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        const json = await res.json();
        setResponseBody(JSON.stringify(json, null, 2));
      } else {
        const text = await res.text();
        setResponseBody(text);
      }
    } catch (err: any) {
      const elapsed = Math.round(performance.now() - startTime);
      setLatencyMs(elapsed);
      setResponseStatus(0);
      setResponseBody(JSON.stringify({ error: { code: "NETWORK_ERROR", message: err.message || "Failed to reach API server" } }, null, 2));
    } finally {
      setExecuting(false);
    }
  };

  // Group presets by category
  const categories = Array.from(new Set(ENDPOINT_PRESETS.map((p) => p.category)));

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E9EDE7] pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-[#EAF3EC] text-[#008031] border border-[#C8E0CF]">
              <Terminal className="w-5 h-5" />
            </span>
            <h1 className="font-editorial text-3xl md:text-4xl font-bold text-[#1A1A1A] tracking-tight">
              API Explorer & Playground
            </h1>
          </div>
          <p className="text-sm text-[#636863] mt-1.5 leading-relaxed">
            Execute real requests against the canonical <code className="px-1.5 py-0.5 rounded bg-[#F3F2EE] text-xs font-mono text-[#008031]">/api/v1</code> developer platform.
            Test cryptographic operations, Post-Quantum keys, certificates, CBOM queries, and async jobs in real-time.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={handleCopyCurl}>
            {copiedCurl ? <Check className="w-3.5 h-3.5 mr-1.5 text-[#008031]" /> : <Copy className="w-3.5 h-3.5 mr-1.5" />}
            {copiedCurl ? "Copied cURL" : "Copy cURL"}
          </Button>
          <Button size="sm" onClick={handleSendRequest} disabled={executing}>
            {executing ? <RotateCw className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Send className="w-3.5 h-3.5 mr-1.5" />}
            {executing ? "Sending..." : "Send Request"}
          </Button>
        </div>
      </div>

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Preset Catalog (4 cols) */}
        <div className="lg:col-span-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="text-xs font-bold uppercase tracking-wider text-[#008031] bg-[#EAF3EC] px-2 py-0.5 rounded border border-[#C8E0CF] flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5" /> 1. Select Endpoint
            </div>
            <span className="text-[11px] text-[#8C928C]">
              {ENDPOINT_PRESETS.length} Presets Available
            </span>
          </div>

          {/* Quick Filter Input */}
          <Input
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="Search endpoints (e.g. pqc, encrypt, key)..."
            aria-label="Search endpoints"
            className="text-xs h-9 bg-white"
          />

          <div className="max-h-[640px] overflow-y-auto space-y-4 pr-1">
            {categories.map((cat) => {
              const matchedPresets = ENDPOINT_PRESETS.filter(
                (p) =>
                  p.category === cat &&
                  (!searchFilter.trim() ||
                    p.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
                    p.path.toLowerCase().includes(searchFilter.toLowerCase()) ||
                    p.category.toLowerCase().includes(searchFilter.toLowerCase()))
              );

              if (matchedPresets.length === 0) return null;

              return (
                <div key={cat} className="space-y-1.5">
                  <div className="text-[11px] font-bold text-[#1A1A1A] uppercase tracking-wide px-1 border-b border-[#E9EDE7] pb-1">
                    {cat}
                  </div>
                  <div className="space-y-1">
                    {matchedPresets.map((preset) => {
                      const isSelected = selectedPreset.id === preset.id;
                      return (
                        <button
                          key={preset.id}
                          onClick={() => handleSelectPreset(preset)}
                          className={`w-full text-left p-2.5 rounded-xl border text-xs transition-all flex items-start gap-2.5 ${
                            isSelected
                              ? "bg-[#EAF3EC] border-[#008031] text-[#1A1A1A] ring-1 ring-[#008031] shadow-xs"
                              : "bg-white border-[#E9EDE7] hover:bg-[#FAF9F6] text-[#555555]"
                          }`}
                        >
                          <span
                            className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase shrink-0 font-mono ${
                              preset.method === "GET"
                                ? "bg-blue-100 text-blue-700"
                                : preset.method === "POST"
                                ? "bg-green-100 text-green-700"
                                : preset.method === "PATCH"
                                ? "bg-amber-100 text-amber-700"
                                : "bg-red-100 text-red-700"
                            }`}
                          >
                            {preset.method}
                          </span>
                          <div className="min-w-0 flex-1">
                            <div className={`truncate font-medium ${isSelected ? "text-[#008031] font-semibold" : ""}`}>
                              {preset.name}
                            </div>
                            <div className="text-[10px] text-[#8C928C] font-mono truncate">{preset.path}</div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Request & Response Workbench (8 cols) */}
        <div className="lg:col-span-8 space-y-6">
          {/* Request Config Card */}
          <Card className="p-5 space-y-4 border-[#E9EDE7]">
            <div className="flex items-center justify-between border-b border-[#E9EDE7] pb-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-[#008031] bg-[#EAF3EC] px-2 py-0.5 rounded border border-[#C8E0CF]">
                  2. Request Builder
                </span>
                <span className="text-xs font-semibold text-[#1A1A1A]">{selectedPreset.name}</span>
                <span className="text-xs text-[#767676] hidden sm:inline">— {selectedPreset.description}</span>
              </div>
            </div>

            {/* URL & Method Input Bar with Prominent Send Button */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-[#1A1A1A] flex items-center gap-2">
                  <span>HTTP Method & Endpoint Path</span>
                  <span className="text-[10px] font-mono text-[#8C928C] font-normal">
                    Base: {API_BASE_URL}
                  </span>
                </label>
              </div>

              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                <div className="shrink-0 flex items-center gap-1.5">
                  <span className="text-[11px] font-bold text-[#767676] uppercase hidden sm:inline">Method:</span>
                  <select
                    value={method}
                    onChange={(e) => setMethod(e.target.value as any)}
                    className={`h-10 px-3 rounded-lg border font-mono text-xs font-bold uppercase focus:outline-none focus:ring-2 focus:ring-[#008031] ${
                      method === "GET"
                        ? "bg-blue-50 text-blue-700 border-blue-200"
                        : method === "POST"
                        ? "bg-green-50 text-green-700 border-green-200"
                        : method === "PATCH"
                        ? "bg-amber-50 text-amber-700 border-amber-200"
                        : "bg-red-50 text-red-700 border-red-200"
                    }`}
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PATCH">PATCH</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                </div>

                <div className="flex-1 flex items-center gap-1.5">
                  <span className="text-[11px] font-bold text-[#767676] uppercase hidden sm:inline">Path:</span>
                  <Input
                    value={path}
                    onChange={(e) => setPath(e.target.value)}
                    placeholder="/api/v1/..."
                    className="font-mono text-xs h-10 border-[#E9EDE7] bg-white font-medium"
                  />
                </div>

                <Button
                  size="default"
                  onClick={handleSendRequest}
                  disabled={executing}
                  className="bg-[#008031] hover:bg-[#006A28] text-white px-5 h-10 shrink-0 font-semibold shadow-xs flex items-center justify-center gap-2"
                >
                  {executing ? <RotateCw className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                  <span>{executing ? "Sending..." : "Send Request"}</span>
                </Button>
              </div>
            </div>

            {/* Optional Custom Headers */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
              <div>
                <label className="text-[11px] font-medium text-[#767676] block mb-1">
                  Authorization Bearer API Key (Optional)
                </label>
                <Input
                  value={apiKeyHeader}
                  onChange={(e) => setApiKeyHeader(e.target.value)}
                  placeholder="am_live_... (Defaults to active session)"
                  className="font-mono text-xs"
                />
              </div>
              <div>
                <label className="text-[11px] font-medium text-[#767676] block mb-1">
                  Idempotency-Key Header (Optional)
                </label>
                <Input
                  value={idempotencyKey}
                  onChange={(e) => setIdempotencyKey(e.target.value)}
                  placeholder="e.g. idem_test_12345"
                  className="font-mono text-xs"
                />
              </div>
            </div>

            {/* Request Body Editor */}
            <div className="space-y-1.5 pt-1">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <label htmlFor="api-explorer-body" className="text-xs font-semibold text-[#1A1A1A]">JSON Request Body</label>
                  {method === "GET" && (
                    <span className="text-[10px] text-[#8C928C] bg-[#F3F2EE] px-2 py-0.5 rounded font-mono">
                      Not required for GET requests
                    </span>
                  )}
                </div>
                {method !== "GET" && (
                  <button
                    onClick={() => {
                      try {
                        const parsed = JSON.parse(requestBody);
                        setRequestBody(JSON.stringify(parsed, null, 2));
                      } catch {}
                    }}
                    className="text-[10px] text-[#008031] hover:underline font-medium"
                  >
                    Format JSON
                  </button>
                )}
              </div>

              {method !== "GET" ? (
                <textarea
                  id="api-explorer-body"
                  value={requestBody}
                  onChange={(e) => setRequestBody(e.target.value)}
                  rows={6}
                  className="w-full p-3.5 rounded-xl border border-[#C8E0CF] bg-[#FAF9F6] font-mono text-xs text-[#1A1A1A] focus:outline-none focus:ring-2 focus:ring-[#008031]"
                  placeholder='{\n  "algorithm": "ML_KEM_768"\n}'
                />
              ) : (
                <div className="p-3.5 bg-[#FAF9F6] border border-[#E9EDE7] rounded-xl text-xs text-[#767676] flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <span>
                    <strong>GET request:</strong> No payload sent in request body. To test with a JSON body, click any <strong>POST</strong> endpoint in the catalog on the left (e.g., <em>Generate PQC Keypair</em>).
                  </span>
                  <button
                    onClick={() => {
                      const postPreset = ENDPOINT_PRESETS.find((p) => p.id === "pqc-keypair");
                      if (postPreset) handleSelectPreset(postPreset);
                    }}
                    className="text-xs font-semibold text-[#008031] hover:underline shrink-0"
                  >
                    Select &quot;Generate PQC Keypair&quot; &rarr;
                  </button>
                </div>
              )}
            </div>
          </Card>

          {/* Response Viewer Card */}
          <Card className="p-5 space-y-4 border-[#E9EDE7] bg-white">
            <div className="flex items-center justify-between border-b border-[#E9EDE7] pb-3">
              <div className="flex items-center gap-3">
                <span className="text-xs font-semibold uppercase tracking-wider text-[#8C928C]">Response</span>
                {responseStatus !== null && (
                  <Badge
                    variant="outline"
                    className={`font-mono text-xs ${
                      responseStatus >= 200 && responseStatus < 300
                        ? "bg-green-50 text-green-700 border-green-200"
                        : responseStatus >= 400 && responseStatus < 500
                        ? "bg-amber-50 text-amber-700 border-amber-200"
                        : "bg-red-50 text-red-700 border-red-200"
                    }`}
                  >
                    {responseStatus === 0 ? "Network Error" : `${responseStatus} ${responseStatus === 200 ? "OK" : responseStatus === 201 ? "Created" : ""}`}
                  </Badge>
                )}
                {latencyMs !== null && (
                  <span className="text-xs text-[#767676] flex items-center gap-1">
                    <Clock className="w-3 h-3 text-[#8C928C]" /> {latencyMs} ms
                  </span>
                )}
              </div>

              {responseBody && (
                <Button variant="outline" size="sm" onClick={handleCopyResponse}>
                  {copiedResp ? <Check className="w-3.5 h-3.5 mr-1 text-[#008031]" /> : <Copy className="w-3.5 h-3.5 mr-1" />}
                  {copiedResp ? "Copied" : "Copy"}
                </Button>
              )}
            </div>

            {requestId && (
              <div className="text-[11px] font-mono text-[#767676] flex items-center gap-1.5">
                <span>Correlation ID:</span>
                <span className="text-[#1A1A1A] font-semibold">{requestId}</span>
              </div>
            )}

            {/* Response Output Box */}
            <div className="relative">
              {executing ? (
                <div className="py-16 flex flex-col items-center justify-center text-[#767676] space-y-2">
                  <RotateCw className="w-6 h-6 animate-spin text-[#008031]" />
                  <span className="text-xs">Executing request against /api/v1...</span>
                </div>
              ) : responseBody ? (
                <pre className="p-4 rounded-xl border border-[#E9EDE7] bg-[#FAF9F6] font-mono text-xs text-[#1A1A1A] max-h-96 overflow-auto whitespace-pre-wrap break-all">
                  {responseBody}
                </pre>
              ) : (
                <div className="py-16 text-center text-xs text-[#8C928C] border border-dashed border-[#E9EDE7] rounded-xl bg-[#FAF9F6]">
                  Select an endpoint from the catalog and click <strong className="text-[#1A1A1A]">Send Request</strong> to inspect live responses.
                </div>
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
