"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Modal } from "@/components/ui/modal";
import {
  Compass,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  RefreshCw,
  Loader2,
  Download,
  Search,
  ArrowRight,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  FileCode,
  Network,
  Activity,
  Layers,
  FileText,
  Key,
  Lock,
  Eye,
  Check,
  Copy,
  Info,
  Sliders,
  ExternalLink,
  Plus
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api-client";

type TabKey = "overview" | "inventory" | "graph" | "findings" | "agility";

interface CryptoAsset {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  assetType: string;
  name: string;
  source: string;
  confidence: string;
  algorithm?: string | null;
  provider?: string | null;
  status: string;
  quantumStatus: string;
  fingerprint?: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  metadata?: any;
}

interface CryptoFinding {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  affectedAssetId?: string | null;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category: string;
  title: string;
  description: string;
  evidence?: any;
  policySource?: string | null;
  firstDetectedAt: string;
  lastDetectedAt: string;
  status: "OPEN" | "ACKNOWLEDGED" | "IN_PROGRESS" | "RESOLVED" | "SUPPRESSED" | "FALSE_POSITIVE";
  remediationGuidance?: string | null;
  resolutionComment?: string | null;
}

interface InventorySummary {
  totalAssets: number;
  assetsByType: Record<string, number>;
  openFindingsCount: number;
  totalFindingsCount: number;
  findingsBySeverity: Record<string, number>;
  quantumStatusSummary: Record<string, number>;
  latestScanDate: string | null;
}

interface MigrationPlan {
  id: string;
  name: string;
  description?: string;
  affectedAssetIds: string[];
  currentAlgorithm: string;
  targetAlgorithm: string;
  migrationStrategy: string;
  status: string;
  createdAt: string;
}

export default function CryptoIntelligencePage() {
  const { activeOrg, requireAuth } = useAuth();
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const [loading, setLoading] = useState<boolean>(true);
  const [scanning, setScanning] = useState<boolean>(false);
  const [exportingCbom, setExportingCbom] = useState<boolean>(false);

  // Data states
  const [summary, setSummary] = useState<InventorySummary | null>(null);
  const [assets, setAssets] = useState<CryptoAsset[]>([]);
  const [findings, setFindings] = useState<CryptoFinding[]>([]);
  const [relationships, setRelationships] = useState<any[]>([]);
  const [migrationPlans, setMigrationPlans] = useState<MigrationPlan[]>([]);

  // Modals & detail drawers
  const [selectedAsset, setSelectedAsset] = useState<CryptoAsset | null>(null);
  const [assetDetailsOpen, setAssetDetailsOpen] = useState<boolean>(false);
  const [selectedFinding, setSelectedFinding] = useState<CryptoFinding | null>(null);
  const [findingModalOpen, setFindingModalOpen] = useState<boolean>(false);
  const [falsePositiveComment, setFalsePositiveComment] = useState<string>("");

  // Impact Simulation
  const [selectedImpactAssetId, setSelectedImpactAssetId] = useState<string>("");
  const [impactData, setImpactData] = useState<any | null>(null);
  const [impactLoading, setImpactLoading] = useState<boolean>(false);

  // New Migration Plan Modal
  const [newPlanModalOpen, setNewPlanModalOpen] = useState<boolean>(false);
  const [planName, setPlanName] = useState<string>("");
  const [planCurrentAlgo, setPlanCurrentAlgo] = useState<string>("RSA-2048");
  const [planTargetAlgo, setPlanTargetAlgo] = useState<string>("ML-DSA-65");
  const [planStrategy, setPlanStrategy] = useState<string>("HYBRID_DUAL_RUN");

  // Filter states
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [typeFilter, setTypeFilter] = useState<string>("ALL");
  const [quantumFilter, setQuantumFilter] = useState<string>("ALL");
  const [findingSeverityFilter, setFindingSeverityFilter] = useState<string>("ALL");

  // Notifications
  const [notification, setNotification] = useState<{ type: "success" | "error"; message: string } | null>(null);

  const showNotification = (type: "success" | "error", message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 5000);
  };

  const loadData = useCallback(async () => {
    if (!activeOrg?.id) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const [invRes, assetsRes, findingsRes, relsRes, plansRes] = await Promise.all([
        api.intelligence.getInventory(activeOrg.id).catch(() => ({ data: null })),
        api.intelligence.listAssets(activeOrg.id).catch(() => ({ data: [] })),
        api.intelligence.listFindings(activeOrg.id).catch(() => ({ data: [] })),
        api.intelligence.listRelationships(activeOrg.id).catch(() => ({ data: [] })),
        api.intelligence.listMigrations(activeOrg.id).catch(() => ({ data: [] })),
      ]);

      if (invRes.data) setSummary(invRes.data);
      if (assetsRes.data) {
        setAssets(assetsRes.data);
        setSelectedImpactAssetId(prev => prev || (assetsRes.data.length > 0 ? assetsRes.data[0].id : null));
      }
      if (findingsRes.data) setFindings(findingsRes.data);
      if (relsRes.data) setRelationships(relsRes.data);
      if (plansRes.data) setMigrationPlans(plansRes.data);
    } catch (err: any) {
      console.error("Failed to load intelligence data:", err);
    } finally {
      setLoading(false);
    }
  }, [activeOrg?.id]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Trigger discovery scan
  const handleTriggerScan = async () => {
    if (!requireAuth("run cryptographic discovery scans")) return;
    if (!activeOrg?.id) return;
    setScanning(true);
    try {
      const res = await api.intelligence.scan(activeOrg.id);
      showNotification("success", `Discovery scan completed! ${res.scan?.totalAssetsDiscovered || 0} assets analyzed.`);
      await loadData();
    } catch (err: any) {
      showNotification("error", err.message || "Failed to run discovery scan.");
    } finally {
      setScanning(false);
    }
  };

  // Download CBOM JSON
  const handleDownloadCbom = async () => {
    if (!requireAuth("export CBOM manifests")) return;
    if (!activeOrg?.id) return;
    setExportingCbom(true);
    try {
      const cbom = await api.intelligence.exportCbom(activeOrg.id);
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(cbom, null, 2));
      const downloadAnchor = document.createElement("a");
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `amaracus-cbom-${activeOrg.id.slice(0, 8)}-${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      showNotification("success", "CBOM JSON exported successfully with cryptographic integrity hash!");
    } catch (err: any) {
      showNotification("error", err.message || "Failed to export CBOM.");
    } finally {
      setExportingCbom(false);
    }
  };

  // Run Impact Analysis Simulation
  const handleRunImpact = async (assetId: string) => {
    if (!activeOrg?.id || !assetId) return;
    setImpactLoading(true);
    try {
      const res = await api.intelligence.getImpact(activeOrg.id, assetId);
      setImpactData(res.data);
    } catch (err: any) {
      showNotification("error", err.message || "Failed to compute impact analysis.");
    } finally {
      setImpactLoading(false);
    }
  };

  // Update Finding status
  const handleUpdateFindingStatus = async (findingId: string, status: string, comment?: string) => {
    if (!activeOrg?.id) return;
    try {
      await api.intelligence.updateFinding(activeOrg.id, findingId, {
        status,
        resolutionComment: comment,
      });
      showNotification("success", `Finding marked as ${status}.`);
      setFindingModalOpen(false);
      setFalsePositiveComment("");
      await loadData();
    } catch (err: any) {
      showNotification("error", err.message || "Failed to update finding status.");
    }
  };

  // Create Migration Plan
  const handleCreatePlan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeOrg?.id || !planName.trim()) return;
    try {
      await api.intelligence.createMigration(activeOrg.id, {
        name: planName.trim(),
        currentAlgorithm: planCurrentAlgo,
        targetAlgorithm: planTargetAlgo,
        migrationStrategy: planStrategy,
      });
      showNotification("success", "Migration plan created successfully.");
      setNewPlanModalOpen(false);
      setPlanName("");
      await loadData();
    } catch (err: any) {
      showNotification("error", err.message || "Failed to create migration plan.");
    }
  };

  // Filtering helpers
  const filteredAssets = assets.filter((a) => {
    const q = searchQuery.trim().toLowerCase();
    const matchesSearch =
      !q ||
      Boolean(a.name && a.name.toLowerCase().includes(q)) ||
      Boolean(a.algorithm && a.algorithm.toLowerCase().includes(q)) ||
      Boolean(a.provider && a.provider.toLowerCase().includes(q)) ||
      Boolean(a.assetType && a.assetType.toLowerCase().includes(q)) ||
      Boolean(a.quantumStatus && a.quantumStatus.toLowerCase().includes(q)) ||
      Boolean(a.fingerprint && a.fingerprint.toLowerCase().includes(q));

    const matchesType = typeFilter === "ALL" || a.assetType === typeFilter;
    const matchesQuantum = quantumFilter === "ALL" || a.quantumStatus === quantumFilter;
    return matchesSearch && matchesType && matchesQuantum;
  });

  const filteredFindings = findings.filter((f) => {
    if (findingSeverityFilter === "ALL") return true;
    return f.severity === findingSeverityFilter;
  });

  // Quantum score calculations
  const totalAssets = summary?.totalAssets || assets.length || 0;
  const qVulnerable = summary?.quantumStatusSummary?.QUANTUM_VULNERABLE || 0;
  const qPqc = summary?.quantumStatusSummary?.PQC || 0;
  const qHybrid = summary?.quantumStatusSummary?.HYBRID || 0;
  const qClassical = summary?.quantumStatusSummary?.CLASSICAL || 0;

  return (
    <div className="p-6 md:p-8 max-w-7xl mx-auto space-y-6">
      {/* Toast Notification */}
      {notification && (
        <div
          className={`fixed top-4 right-4 z-50 px-4 py-3 rounded-lg shadow-lg border text-sm font-medium flex items-center gap-2 animate-in fade-in slide-in-from-top-2 ${
            notification.type === "success"
              ? "bg-[#EAF3EC] border-[#C8E0CF] text-[#008031]"
              : "bg-red-50 border-red-200 text-red-700"
          }`}
        >
          {notification.type === "success" ? <CheckCircle2 className="w-4 h-4 shrink-0" /> : <XCircle className="w-4 h-4 shrink-0" />}
          <span>{notification.message}</span>
        </div>
      )}

      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#E9EDE7] pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-2xl font-bold font-editorial tracking-tight text-[#1A1A1A]">
              Cryptographic Intelligence & CBOM
            </h1>
            <Badge variant="outline" className="bg-amber-50 text-amber-800 border-amber-200">
              Preview
            </Badge>
          </div>
          <p className="text-sm text-[#767676]">
            Continuous cryptographic asset inventory, dependency graph analysis, CBOM export, and post-quantum agility governance.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="outline"
            onClick={handleDownloadCbom}
            disabled={exportingCbom || loading}
            className="border-[#E9EDE7] text-[#1A1A1A] hover:bg-[#F3F2EE] flex items-center gap-1.5 text-xs font-semibold"
          >
            {exportingCbom ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            Export CBOM JSON
          </Button>

          <Button
            onClick={handleTriggerScan}
            disabled={scanning || loading}
            className="bg-[#008031] hover:bg-[#006A28] text-white flex items-center gap-1.5 text-xs font-semibold shadow-sm"
          >
            {scanning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            Run Discovery Scan
          </Button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-[#E9EDE7] space-x-6 overflow-x-auto text-sm">
        {[
          { key: "overview", label: "Overview & Telemetry", icon: Activity },
          { key: "inventory", label: "Cryptographic Inventory", icon: Layers, count: assets.length },
          { key: "graph", label: "Dependency & Impact Graph", icon: Network },
          { key: "findings", label: "Findings & Remediation", icon: ShieldAlert, count: findings.filter(f => f.status === "OPEN").length },
          { key: "agility", label: "Crypto-Agility & Migrations", icon: Compass, count: migrationPlans.length },
        ].map((t) => {
          const Icon = t.icon;
          const isActive = activeTab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key as TabKey)}
              className={`pb-3 font-medium flex items-center gap-2 transition-colors relative whitespace-nowrap ${
                isActive ? "text-[#008031] font-semibold" : "text-[#767676] hover:text-[#1A1A1A]"
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{t.label}</span>
              {t.count !== undefined && (
                <span
                  className={`text-[11px] px-1.5 py-0.5 rounded-full ${
                    isActive ? "bg-[#008031] text-white" : "bg-[#F3F2EE] text-[#767676]"
                  }`}
                >
                  {t.count}
                </span>
              )}
              {isActive && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-[#008031]" />}
            </button>
          );
        })}
      </div>

      {/* TAB 1: OVERVIEW & TELEMETRY */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {/* Top Metrics Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="bg-white border-[#E9EDE7]">
              <CardContent className="p-5">
                <div className="flex items-center justify-between text-xs text-[#767676] font-medium mb-1">
                  <span>TOTAL ASSETS</span>
                  <Layers className="w-4 h-4 text-[#767676]" />
                </div>
                <div className="text-2xl font-bold font-editorial text-[#1A1A1A]">{totalAssets}</div>
                <div className="text-[11px] text-[#767676] mt-1 flex items-center gap-1">
                  <span>{assets.filter(a => a.assetType === 'KEY').length} Keys</span> •
                  <span>{assets.filter(a => a.assetType === 'CERTIFICATE').length} Certs</span> •
                  <span>{assets.filter(a => a.assetType === 'CERTIFICATE_AUTHORITY').length} CAs</span>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-white border-[#E9EDE7]">
              <CardContent className="p-5">
                <div className="flex items-center justify-between text-xs text-amber-600 font-medium mb-1">
                  <span>QUANTUM VULNERABLE</span>
                  <AlertTriangle className="w-4 h-4 text-amber-500" />
                </div>
                <div className="text-2xl font-bold font-editorial text-amber-600">{qVulnerable}</div>
                <div className="text-[11px] text-amber-700 mt-1">
                  Vulnerable to Shor&apos;s Algorithm (RSA / ECC)
                </div>
              </CardContent>
            </Card>

            <Card className="bg-white border-[#E9EDE7]">
              <CardContent className="p-5">
                <div className="flex items-center justify-between text-xs text-[#008031] font-medium mb-1">
                  <span>PQC READY & HYBRID</span>
                  <ShieldCheck className="w-4 h-4 text-[#008031]" />
                </div>
                <div className="text-2xl font-bold font-editorial text-[#008031]">{qPqc + qHybrid}</div>
                <div className="text-[11px] text-[#008031] mt-1">
                  {qPqc} Pure PQC • {qHybrid} Hybrid Combiner
                </div>
              </CardContent>
            </Card>

            <Card className="bg-white border-[#E9EDE7]">
              <CardContent className="p-5">
                <div className="flex items-center justify-between text-xs text-red-600 font-medium mb-1">
                  <span>OPEN FINDINGS</span>
                  <ShieldAlert className="w-4 h-4 text-red-500" />
                </div>
                <div className="text-2xl font-bold font-editorial text-red-600">
                  {findings.filter(f => f.status === "OPEN").length}
                </div>
                <div className="text-[11px] text-red-700 mt-1">
                  {summary?.findingsBySeverity?.CRITICAL || 0} Critical • {summary?.findingsBySeverity?.HIGH || 0} High
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Quantum Readiness Distribution */}
          <Card className="bg-white border-[#E9EDE7]">
            <CardHeader className="pb-3 border-b border-[#E9EDE7]">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base font-bold text-[#1A1A1A]">
                    Quantum-Readiness Assessment
                  </CardTitle>
                  <CardDescription className="text-xs text-[#767676]">
                    NIST FIPS 203/204 Post-Quantum Cryptography transition status across all discovered assets.
                  </CardDescription>
                </div>
                <Badge variant="outline" className="bg-[#FAF9F6] border-[#E9EDE7] text-[11px]">
                  {totalAssets > 0 ? Math.round(((qPqc + qHybrid + qClassical) / totalAssets) * 100) : 0}% Grover/Shor Resistant
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="p-5 space-y-4">
              {/* Stacked Progress Bar */}
              <div 
                className="w-full h-3 rounded-full bg-[#F3F2EE] overflow-hidden flex"
                role="img"
                aria-label={`Post-quantum cryptographic readiness breakdown: ${qPqc} Pure PQC assets, ${qHybrid} Hybrid assets, ${qClassical} Classical Grover-Resistant assets, ${qVulnerable} Quantum-Vulnerable assets out of ${totalAssets} total inventory assets.`}
              >
                {totalAssets > 0 && (
                  <>
                    <div
                      style={{ width: `${(qPqc / totalAssets) * 100}%` }}
                      className="bg-[#008031]"
                      aria-hidden="true"
                    />
                    <div
                      style={{ width: `${(qHybrid / totalAssets) * 100}%` }}
                      className="bg-emerald-400"
                      aria-hidden="true"
                    />
                    <div
                      style={{ width: `${(qClassical / totalAssets) * 100}%` }}
                      className="bg-blue-400"
                      aria-hidden="true"
                    />
                    <div
                      style={{ width: `${(qVulnerable / totalAssets) * 100}%` }}
                      className="bg-amber-400"
                      aria-hidden="true"
                    />
                  </>
                )}
              </div>

              {/* Visually Hidden Accessible Table for Screen Readers */}
              <div className="sr-only">
                <table>
                  <caption>Post-quantum cryptographic inventory status summary</caption>
                  <thead>
                    <tr>
                      <th scope="col">Readiness Tier</th>
                      <th scope="col">Asset Count</th>
                      <th scope="col">Percentage</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <th scope="row">Pure Post-Quantum Cryptography</th>
                      <td>{qPqc}</td>
                      <td>{totalAssets > 0 ? Math.round((qPqc / totalAssets) * 100) : 0}%</td>
                    </tr>
                    <tr>
                      <th scope="row">Hybrid Combiners</th>
                      <td>{qHybrid}</td>
                      <td>{totalAssets > 0 ? Math.round((qHybrid / totalAssets) * 100) : 0}%</td>
                    </tr>
                    <tr>
                      <th scope="row">Classical Grover-Resistant</th>
                      <td>{qClassical}</td>
                      <td>{totalAssets > 0 ? Math.round((qClassical / totalAssets) * 100) : 0}%</td>
                    </tr>
                    <tr>
                      <th scope="row">Quantum-Vulnerable</th>
                      <td>{qVulnerable}</td>
                      <td>{totalAssets > 0 ? Math.round((qVulnerable / totalAssets) * 100) : 0}%</td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* Legend Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                <div className="p-3 rounded-lg bg-[#FAF9F6] border border-[#E9EDE7]">
                  <div className="flex items-center gap-1.5 font-semibold text-[#008031] mb-1">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#008031]" aria-hidden="true" />
                    <span>Pure PQC ({qPqc})</span>
                  </div>
                  <p className="text-[11px] text-[#767676]">
                    ML-KEM (FIPS 203) &amp; ML-DSA (FIPS 204). Lattice-based, fully immune to Shor&apos;s algorithm.
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-[#FAF9F6] border border-[#E9EDE7]">
                  <div className="flex items-center gap-1.5 font-semibold text-emerald-700 mb-1">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" aria-hidden="true" />
                    <span>Hybrid Combiners ({qHybrid})</span>
                  </div>
                  <p className="text-[11px] text-[#767676]">
                    X25519+ML-KEM-768. Protects against Store-Now-Decrypt-Later while retaining classical assurance.
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-[#FAF9F6] border border-[#E9EDE7]">
                  <div className="flex items-center gap-1.5 font-semibold text-blue-700 mb-1">
                    <span className="w-2.5 h-2.5 rounded-full bg-blue-400" aria-hidden="true" />
                    <span>Symmetric / Hashes ({qClassical})</span>
                  </div>
                  <p className="text-[11px] text-[#767676]">
                    AES-256-GCM, SHA-256. Retains ≥ 128 bits post-quantum security under Grover&apos;s bounds.
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-[#FAF9F6] border border-[#E9EDE7]">
                  <div className="flex items-center gap-1.5 font-semibold text-amber-700 mb-1">
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-400" aria-hidden="true" />
                    <span>Quantum-Vulnerable ({qVulnerable})</span>
                  </div>
                  <p className="text-[11px] text-[#767676]">
                    RSA and traditional ECC (ECDSA, Ed25519). Factoring and discrete log broken by Shor&apos;s algorithm.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Quick Action Banner */}
          <div className="p-4 rounded-xl border border-[#C8E0CF] bg-[#EAF3EC] flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-white border border-[#C8E0CF] flex items-center justify-center text-[#008031] shrink-0">
                <Compass className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-[#1A1A1A]">Automated Crypto-Agility Migration Planning</h4>
                <p className="text-xs text-[#555555]">
                  Identify candidates, configure target algorithms, and preview downstream dependency impacts.
                </p>
              </div>
            </div>
            <Button
              onClick={() => setActiveTab("agility")}
              className="bg-[#008031] hover:bg-[#006A28] text-white text-xs font-semibold px-4 py-2 shrink-0"
            >
              Open Migration Studio <ArrowRight className="w-3.5 h-3.5 ml-1" />
            </Button>
          </div>
        </div>
      )}

      {/* TAB 2: INVENTORY & CBOM */}
      {activeTab === "inventory" && (
        <div className="space-y-4">
          {/* Controls */}
          <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
            <div className="relative w-full md:w-80">
              <Search className="w-4 h-4 text-[#767676] absolute left-3 top-1/2 -translate-y-1/2" aria-hidden="true" />
              <Input
                placeholder="Search asset, algorithm, or provider..."
                aria-label="Search cryptographic assets, algorithms, or providers"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 pr-8 text-xs bg-white border-[#E9EDE7]"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#767676] hover:text-[#1A1A1A] p-0.5 rounded"
                  title="Clear search"
                  aria-label="Clear search query"
                >
                  <XCircle className="w-3.5 h-3.5" aria-hidden="true" />
                </button>
              )}
            </div>

            <div className="flex items-center gap-2 w-full md:w-auto overflow-x-auto">
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border border-[#E9EDE7] bg-white text-xs text-[#1A1A1A]"
              >
                <option value="ALL">All Types</option>
                <option value="KEY">Key</option>
                <option value="CERTIFICATE">Certificate</option>
                <option value="CERTIFICATE_AUTHORITY">Certificate Authority</option>
                <option value="CRYPTO_OPERATION">Cryptographic Operation</option>
                <option value="CRYPTO_LIBRARY">Source Code Usage</option>
              </select>

              <select
                value={quantumFilter}
                onChange={(e) => setQuantumFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border border-[#E9EDE7] bg-white text-xs text-[#1A1A1A]"
              >
                <option value="ALL">All Quantum Statuses</option>
                <option value="QUANTUM_VULNERABLE">Quantum Vulnerable</option>
                <option value="PQC">PQC Ready</option>
                <option value="HYBRID">Hybrid</option>
                <option value="CLASSICAL">Classical Symmetric</option>
              </select>

              {(searchQuery || typeFilter !== "ALL" || quantumFilter !== "ALL") && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setSearchQuery("");
                    setTypeFilter("ALL");
                    setQuantumFilter("ALL");
                  }}
                  className="h-8 text-xs text-red-600 hover:bg-red-50 hover:text-red-700 font-medium px-2"
                >
                  Reset Filters
                </Button>
              )}
            </div>
          </div>

          {/* Filter Status Summary */}
          <div className="flex items-center justify-between text-xs text-[#767676] px-1">
            <div className="flex items-center gap-2">
              <span>
                Showing <strong className="text-[#1A1A1A] font-semibold">{filteredAssets.length}</strong> of{" "}
                <strong className="text-[#1A1A1A] font-semibold">{assets.length}</strong> assets
              </span>
              {(searchQuery || typeFilter !== "ALL" || quantumFilter !== "ALL") && (
                <Badge variant="outline" className="bg-[#FAF9F6] border-[#E9EDE7] text-[10px] text-[#008031]">
                  Filter Active
                </Badge>
              )}
            </div>
            {filteredAssets.length === 0 && assets.length > 0 && (
              <span className="text-amber-700 text-[11px]">
                0 assets match your filter criteria. Try clicking &ldquo;Reset Filters&rdquo;.
              </span>
            )}
          </div>

          {/* Inventory Table */}
          <Card className="bg-white border-[#E9EDE7]">
            <CardContent className="p-0">
              <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Cryptographic assets inventory table">
                <table className="w-full text-xs text-left">
                  <thead className="bg-[#FAF9F6] text-[#767676] font-semibold border-b border-[#E9EDE7]">
                    <tr>
                      <th className="p-3.5">Asset Name</th>
                      <th className="p-3.5">Type</th>
                      <th className="p-3.5">Algorithm</th>
                      <th className="p-3.5">Provider</th>
                      <th className="p-3.5">Quantum Status</th>
                      <th className="p-3.5">Source</th>
                      <th className="p-3.5 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E9EDE7]">
                    {filteredAssets.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="p-8 text-center text-[#767676]">
                          No cryptographic assets found matching filters. Run a Discovery Scan to populate inventory.
                        </td>
                      </tr>
                    ) : (
                      filteredAssets.map((asset) => (
                        <tr key={asset.id} className="hover:bg-[#FAF9F6] transition-colors">
                          <td className="p-3.5 font-medium text-[#1A1A1A] max-w-[220px] truncate">
                            <div className="truncate font-semibold">{asset.name}</div>
                            <div className="text-[10px] text-[#767676] truncate font-mono">{asset.fingerprint || asset.id}</div>
                          </td>
                          <td className="p-3.5">
                            <Badge variant="outline" className="bg-white border-[#E9EDE7] text-[10px]">
                              {asset.assetType}
                            </Badge>
                          </td>
                          <td className="p-3.5 font-mono text-[#1A1A1A]">
                            {asset.algorithm || "—"}
                          </td>
                          <td className="p-3.5 text-[#555555]">
                            {asset.provider || "NODE_CRYPTO"}
                          </td>
                          <td className="p-3.5">
                            <Badge
                              variant="outline"
                              className={`text-[10px] ${
                                asset.quantumStatus === "PQC"
                                  ? "bg-[#EAF3EC] text-[#008031] border-[#C8E0CF]"
                                  : asset.quantumStatus === "HYBRID"
                                  ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                                  : asset.quantumStatus === "QUANTUM_VULNERABLE"
                                  ? "bg-amber-50 text-amber-700 border-amber-200"
                                  : "bg-blue-50 text-blue-700 border-blue-200"
                              }`}
                            >
                              {asset.quantumStatus}
                            </Badge>
                          </td>
                          <td className="p-3.5 text-[#767676] text-[11px]">
                            <div>{asset.source}</div>
                            <div className="text-[10px] text-[#8C928C]">Conf: {asset.confidence}</div>
                          </td>
                          <td className="p-3.5 text-right space-x-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setSelectedAsset(asset);
                                setAssetDetailsOpen(true);
                              }}
                              className="h-7 text-xs text-[#008031] hover:bg-[#EAF3EC]"
                            >
                              Details
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setSelectedImpactAssetId(asset.id);
                                handleRunImpact(asset.id);
                                setActiveTab("graph");
                              }}
                              className="h-7 text-xs text-[#767676] hover:bg-[#F3F2EE]"
                            >
                              Impact
                            </Button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* TAB 3: DEPENDENCY & IMPACT GRAPH */}
      {activeTab === "graph" && (
        <div className="space-y-6">
          <Card className="bg-white border-[#E9EDE7]">
            <CardHeader className="border-b border-[#E9EDE7] pb-3">
              <CardTitle className="text-base font-bold text-[#1A1A1A]">
                Cryptographic Impact Simulator
              </CardTitle>
              <CardDescription className="text-xs text-[#767676]">
                Simulate what happens if an algorithm, key, or Certificate Authority is deprecated or compromised.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-5 space-y-4">
              <div className="flex flex-col md:flex-row gap-3 items-end">
                <div className="w-full md:w-96 space-y-1">
                  <label className="text-xs font-semibold text-[#1A1A1A]">Select Target Cryptographic Asset:</label>
                  <select
                    value={selectedImpactAssetId}
                    onChange={(e) => setSelectedImpactAssetId(e.target.value)}
                    className="w-full p-2 rounded-lg border border-[#E9EDE7] bg-white text-xs text-[#1A1A1A]"
                  >
                    {assets.map((a) => (
                      <option key={a.id} value={a.id}>
                        [{a.assetType}] {a.name} ({a.algorithm || "N/A"})
                      </option>
                    ))}
                  </select>
                </div>

                <Button
                  onClick={() => handleRunImpact(selectedImpactAssetId)}
                  disabled={impactLoading || !selectedImpactAssetId}
                  className="bg-[#008031] hover:bg-[#006A28] text-white text-xs font-semibold"
                >
                  {impactLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : <Network className="w-3.5 h-3.5 mr-1" />}
                  Simulate Deprecation Impact
                </Button>
              </div>

              {/* Impact Simulation Result */}
              {impactData && (
                <div className="mt-6 border border-[#E9EDE7] rounded-xl p-5 bg-[#FAF9F6] space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-sm font-bold text-[#1A1A1A]">
                        Simulation Result: Deprecating &ldquo;{impactData.assetName}&rdquo;
                      </h4>
                      <p className="text-xs text-[#767676]">
                        Algorithm: <span className="font-mono">{impactData.algorithm || "N/A"}</span> • Type: {impactData.assetType}
                      </p>
                    </div>
                    <Badge
                      className={`text-xs px-2.5 py-1 ${
                        impactData.totalAffected > 0 ? "bg-amber-100 text-amber-800 border-amber-300" : "bg-[#EAF3EC] text-[#008031]"
                      }`}
                    >
                      {impactData.totalAffected} Downstream Dependents Broken
                    </Badge>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
                    <div className="p-3 bg-white rounded-lg border border-[#E9EDE7]">
                      <div className="text-[#767676] font-medium">Affected Certificates</div>
                      <div className="text-xl font-bold text-[#1A1A1A] mt-1">{impactData.affectedCertificates.length}</div>
                    </div>
                    <div className="p-3 bg-white rounded-lg border border-[#E9EDE7]">
                      <div className="text-[#767676] font-medium">Affected Keys</div>
                      <div className="text-xl font-bold text-[#1A1A1A] mt-1">{impactData.affectedKeys.length}</div>
                    </div>
                    <div className="p-3 bg-white rounded-lg border border-[#E9EDE7]">
                      <div className="text-[#767676] font-medium">Affected Applications</div>
                      <div className="text-xl font-bold text-[#1A1A1A] mt-1">{impactData.affectedApplications.length}</div>
                    </div>
                    <div className="p-3 bg-white rounded-lg border border-[#E9EDE7]">
                      <div className="text-[#767676] font-medium">Environments Impacted</div>
                      <div className="text-xl font-bold text-[#1A1A1A] mt-1">{impactData.affectedEnvironments.length || 1}</div>
                    </div>
                  </div>

                  {impactData.affectedCertificates.length > 0 && (
                    <div className="space-y-1.5 text-xs">
                      <div className="font-semibold text-[#1A1A1A]">Impacted Certificates:</div>
                      <div className="flex flex-wrap gap-1.5">
                        {impactData.affectedCertificates.map((c: any) => (
                          <Badge key={c.id} variant="outline" className="bg-white border-[#E9EDE7] text-[11px]">
                            {c.name}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {impactData.affectedKeys.length > 0 && (
                    <div className="space-y-1.5 text-xs">
                      <div className="font-semibold text-[#1A1A1A]">Impacted Keys:</div>
                      <div className="flex flex-wrap gap-1.5">
                        {impactData.affectedKeys.map((k: any) => (
                          <Badge key={k.id} variant="outline" className="bg-white border-[#E9EDE7] text-[11px]">
                            {k.name} ({k.algorithm})
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* TAB 4: FINDINGS & REMEDIATION */}
      {activeTab === "findings" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-[#1A1A1A]">Actionable Security & Policy Findings</h3>
            <select
              value={findingSeverityFilter}
              onChange={(e) => setFindingSeverityFilter(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg border border-[#E9EDE7] bg-white text-xs text-[#1A1A1A]"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="space-y-3">
            {filteredFindings.length === 0 ? (
              <Card className="bg-white border-[#E9EDE7] p-8 text-center text-[#767676] text-xs">
                No findings match the configured filter. All assets are currently compliant!
              </Card>
            ) : (
              filteredFindings.map((finding) => (
                <Card key={finding.id} className="bg-white border-[#E9EDE7] hover:border-[#C8E0CF] transition-colors">
                  <CardContent className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="space-y-1 max-w-3xl">
                      <div className="flex items-center gap-2">
                        <Badge
                          className={`text-[10px] font-semibold ${
                            finding.severity === "CRITICAL"
                              ? "bg-red-100 text-red-800 border-red-200"
                              : finding.severity === "HIGH"
                              ? "bg-orange-100 text-orange-800 border-orange-200"
                              : finding.severity === "MEDIUM"
                              ? "bg-amber-100 text-amber-800 border-amber-200"
                              : "bg-blue-100 text-blue-800 border-blue-200"
                          }`}
                        >
                          {finding.severity}
                        </Badge>
                        <span className="text-xs font-bold text-[#1A1A1A]">{finding.title}</span>
                        <Badge variant="outline" className="text-[10px] border-[#E9EDE7]">
                          {finding.status}
                        </Badge>
                      </div>
                      <p className="text-xs text-[#555555]">{finding.description}</p>
                      <div className="text-[11px] text-[#767676] flex items-center gap-2">
                        <span>Category: {finding.category}</span> •
                        <span>Policy: {finding.policySource || "NIST Standard"}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setSelectedFinding(finding);
                          setFindingModalOpen(true);
                        }}
                        className="text-xs border-[#E9EDE7]"
                      >
                        Triage & Remediate
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 5: CRYPTO-AGILITY & MIGRATIONS */}
      {activeTab === "agility" && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-[#1A1A1A]">Crypto-Agility & Post-Quantum Migration Studio</h3>
              <p className="text-xs text-[#767676]">
                Decoupled algorithm resolution and structured transition plans from classical to quantum-safe primitives.
              </p>
            </div>
            <Button
              onClick={() => setNewPlanModalOpen(true)}
              className="bg-[#008031] hover:bg-[#006A28] text-white text-xs font-semibold flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" />
              New Migration Plan
            </Button>
          </div>

          {/* Migration Recommendations Reference */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <Card className="bg-white border-[#E9EDE7]">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-bold uppercase tracking-wider text-[#767676]">
                  Digital Signatures (NIST FIPS 204)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#FAF9F6] border border-[#E9EDE7]">
                  <span className="font-semibold text-[#1A1A1A]">RSA-2048 / RSA-4096</span>
                  <ArrowRight className="w-3.5 h-3.5 text-[#767676]" />
                  <span className="font-semibold text-[#008031]">ML-DSA-65 (Dual-Run Hybrid)</span>
                </div>
                <p className="text-[11px] text-[#767676]">
                  Module-Lattice digital signatures provide Security Level 3 post-quantum authenticity. Composite signatures preserve legacy client validation.
                </p>
              </CardContent>
            </Card>

            <Card className="bg-white border-[#E9EDE7]">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-bold uppercase tracking-wider text-[#767676]">
                  Key Encapsulation / KEM (NIST FIPS 203)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#FAF9F6] border border-[#E9EDE7]">
                  <span className="font-semibold text-[#1A1A1A]">ECDH / X25519</span>
                  <ArrowRight className="w-3.5 h-3.5 text-[#767676]" />
                  <span className="font-semibold text-[#008031]">X25519 + ML-KEM-768 (Dual Combiner)</span>
                </div>
                <p className="text-[11px] text-[#767676]">
                  X-Wing / Dual-combiner hybrid key exchange provides defense-in-depth against Store-Now-Decrypt-Later (SNDL) attacks.
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Active Migration Plans */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-[#767676]">Active Migration Roadmaps</h4>
            {migrationPlans.length === 0 ? (
              <Card className="bg-white border-[#E9EDE7] p-8 text-center text-[#767676] text-xs">
                No active migration plans configured. Click &ldquo;New Migration Plan&rdquo; to plan an algorithm transition.
              </Card>
            ) : (
              migrationPlans.map((plan) => (
                <Card key={plan.id} className="bg-white border-[#E9EDE7]">
                  <CardContent className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-[#1A1A1A]">{plan.name}</span>
                        <Badge variant="outline" className="text-[10px] bg-[#EAF3EC] text-[#008031] border-[#C8E0CF]">
                          {plan.status}
                        </Badge>
                      </div>
                      <p className="text-xs text-[#555555]">
                        Migrating <span className="font-mono font-semibold">{plan.currentAlgorithm}</span> &rarr;{" "}
                        <span className="font-mono font-semibold text-[#008031]">{plan.targetAlgorithm}</span> via {plan.migrationStrategy}.
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-[11px] border-[#E9EDE7]">
                        {plan.affectedAssetIds?.length || 0} Affected Assets
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        </div>
      )}

      {/* Asset Details Modal */}
      {selectedAsset && (
        <Modal
          isOpen={assetDetailsOpen}
          onClose={() => setAssetDetailsOpen(false)}
          title={`Asset: ${selectedAsset.name}`}
        >
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-3 p-3 bg-[#FAF9F6] rounded-lg border border-[#E9EDE7]">
              <div>
                <span className="text-[#767676]">Type:</span>
                <div className="font-semibold text-[#1A1A1A]">{selectedAsset.assetType}</div>
              </div>
              <div>
                <span className="text-[#767676]">Algorithm:</span>
                <div className="font-mono font-semibold text-[#1A1A1A]">{selectedAsset.algorithm || "N/A"}</div>
              </div>
              <div>
                <span className="text-[#767676]">Provider:</span>
                <div className="font-semibold text-[#1A1A1A]">{selectedAsset.provider || "N/A"}</div>
              </div>
              <div>
                <span className="text-[#767676]">Quantum Status:</span>
                <div className="font-semibold text-[#008031]">{selectedAsset.quantumStatus}</div>
              </div>
            </div>

            <div>
              <span className="text-[#767676] font-medium">Fingerprint / Digest:</span>
              <div className="p-2 rounded bg-white border border-[#E9EDE7] font-mono text-[11px] mt-1 break-all select-all">
                {selectedAsset.fingerprint || selectedAsset.id}
              </div>
            </div>

            {selectedAsset.metadata && (
              <div>
                <span className="text-[#767676] font-medium">Asset Metadata:</span>
                <pre className="p-3 bg-[#FAF9F6] border border-[#E9EDE7] rounded-lg font-mono text-[11px] mt-1 overflow-x-auto">
                  {JSON.stringify(selectedAsset.metadata, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </Modal>
      )}

      {/* Finding Triage Modal */}
      {selectedFinding && (
        <Modal
          isOpen={findingModalOpen}
          onClose={() => setFindingModalOpen(false)}
          title={`Finding Triage: ${selectedFinding.title}`}
        >
          <div className="space-y-4 text-xs">
            <p className="text-[#555555]">{selectedFinding.description}</p>

            {selectedFinding.remediationGuidance && (
              <div className="p-3 rounded-lg bg-[#EAF3EC] border border-[#C8E0CF] text-[#008031]">
                <span className="font-semibold block mb-1">Recommended Remediation:</span>
                {selectedFinding.remediationGuidance}
              </div>
            )}

            <div className="space-y-2">
              <label className="font-semibold text-[#1A1A1A]">Audited Justification (for False Positive or Resolution):</label>
              <Input
                placeholder="Explain the technical rationale..."
                value={falsePositiveComment}
                onChange={(e) => setFalsePositiveComment(e.target.value)}
                className="text-xs"
              />
            </div>

            <div className="flex flex-wrap gap-2 pt-2 border-t border-[#E9EDE7]">
              <Button
                size="sm"
                onClick={() => handleUpdateFindingStatus(selectedFinding.id, "ACKNOWLEDGED")}
                className="text-xs bg-white border border-[#E9EDE7] text-[#1A1A1A] hover:bg-[#F3F2EE]"
              >
                Acknowledge
              </Button>

              <Button
                size="sm"
                onClick={() => handleUpdateFindingStatus(selectedFinding.id, "FALSE_POSITIVE", falsePositiveComment || "Marked false positive via dashboard")}
                className="text-xs bg-amber-50 border border-amber-200 text-amber-700 hover:bg-amber-100"
              >
                Mark False Positive
              </Button>

              <Button
                size="sm"
                onClick={() => handleUpdateFindingStatus(selectedFinding.id, "RESOLVED", falsePositiveComment || "Remediated")}
                className="text-xs bg-[#008031] text-white hover:bg-[#006A28]"
              >
                Resolve Finding
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {/* New Migration Plan Modal */}
      <Modal
        isOpen={newPlanModalOpen}
        onClose={() => setNewPlanModalOpen(false)}
        title="Create Crypto-Agility Migration Plan"
      >
        <form onSubmit={handleCreatePlan} className="space-y-4 text-xs">
          <div className="space-y-1">
            <label className="font-semibold text-[#1A1A1A]">Plan Name:</label>
            <Input
              placeholder="e.g. Core PKI RSA-to-MLDSA Migration"
              value={planName}
              onChange={(e) => setPlanName(e.target.value)}
              required
              className="text-xs"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="font-semibold text-[#1A1A1A]">Current Algorithm:</label>
              <select
                value={planCurrentAlgo}
                onChange={(e) => setPlanCurrentAlgo(e.target.value)}
                className="w-full p-2 rounded-lg border border-[#E9EDE7] bg-white text-xs"
              >
                <option value="RSA-2048">RSA-2048</option>
                <option value="RSA-4096">RSA-4096</option>
                <option value="ECDSA-P256">ECDSA-P256</option>
                <option value="ED25519">ED25519</option>
                <option value="ECDH">ECDH</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="font-semibold text-[#1A1A1A]">Target Algorithm:</label>
              <select
                value={planTargetAlgo}
                onChange={(e) => setPlanTargetAlgo(e.target.value)}
                className="w-full p-2 rounded-lg border border-[#E9EDE7] bg-white text-xs"
              >
                <option value="ML-DSA-65">ML-DSA-65 (NIST FIPS 204)</option>
                <option value="ML-DSA-87">ML-DSA-87 (High Security)</option>
                <option value="X25519+ML-KEM-768">X25519+ML-KEM-768 (Hybrid)</option>
                <option value="ML-KEM-768">ML-KEM-768 (NIST FIPS 203)</option>
              </select>
            </div>
          </div>

          <div className="space-y-1">
            <label className="font-semibold text-[#1A1A1A]">Migration Strategy:</label>
            <select
              value={planStrategy}
              onChange={(e) => setPlanStrategy(e.target.value)}
              className="w-full p-2 rounded-lg border border-[#E9EDE7] bg-white text-xs"
            >
              <option value="HYBRID_DUAL_RUN">Hybrid Dual-Run (Recommended)</option>
              <option value="DIRECT_REPLACEMENT">Direct Replacement</option>
              <option value="PHASED_ROTATION">Phased Rotation</option>
            </select>
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-[#E9EDE7]">
            <Button
              type="button"
              variant="outline"
              onClick={() => setNewPlanModalOpen(false)}
              className="text-xs border-[#E9EDE7]"
            >
              Cancel
            </Button>
            <Button type="submit" className="bg-[#008031] text-white hover:bg-[#006A28] text-xs">
              Save Migration Plan
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
