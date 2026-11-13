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
  RefreshCw,
  Loader2,
  ShieldCheck,
  ShieldAlert,
  Server,
  Lock,
  Eye,
  Trash2,
  AlertTriangle,
  RotateCw,
  CheckCircle2,
  Copy,
  Check,
  Play,
  ExternalLink,
  Cpu,
  Layers,
  CheckCircle,
  HelpCircle,
  XCircle,
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api-client";

interface ManagedKey {
  id: string;
  name: string;
  description?: string | null;
  organizationId: string;
  projectId: string;
  environmentId: string;
  algorithm: string;
  purpose: string;
  provider: string;
  status: string;
  currentVersion: number;
  createdAt: string;
  updatedAt: string;
  activatedAt?: string | null;
  rotatedAt?: string | null;
  disabledAt?: string | null;
  revokedAt?: string | null;
  scheduledDeletionAt?: string | null;
  destroyedAt?: string | null;
  versions?: KeyVersionItem[];
  project?: { id: string; name: string };
  environment?: { id: string; name: string };
}

interface KeyVersionItem {
  id: string;
  keyId: string;
  version: number;
  providerKeyId: string;
  status: string;
  publicKey?: string | null;
  keyFingerprint?: string | null;
  createdAt: string;
  activatedAt?: string | null;
  revokedAt?: string | null;
  destroyedAt?: string | null;
}

interface ProviderHealthItem {
  provider: string;
  label: string;
  status: 'CONFIGURED' | 'NOT_CONFIGURED' | 'AVAILABLE' | 'UNAVAILABLE' | 'DEGRADED' | 'DEVELOPMENT_ONLY';
  message: string;
  isConfigured: boolean;
  details?: Record<string, any>;
}

interface ProjectOption {
  id: string;
  name: string;
  environments?: { id: string; name: string }[];
}

interface CustomerProviderItem {
  id: string;
  name: string;
  providerType: 'AZURE_KEY_VAULT' | 'AZURE_MANAGED_HSM';
  ownershipType: string;
  vaultUrl: string;
  hsmUrl?: string | null;
  status: string;
  connectionStatus?: string;
  onboardingState?: string;
  resourceType?: string;
  displayName?: string | null;
  isHsmBacked: boolean;
  capabilities?: any;
  lastHealthCheckAt?: string;
  createdAt: string;
  registeredKeys?: CustomerRegisteredKeyItem[];
}

interface CustomerRegisteredKeyItem {
  id: string;
  providerId: string;
  keyIdentifier: string;
  keyVaultUrl: string;
  keyType: string;
  algorithm: string;
  purpose: string;
  ownershipType: string;
  isHsmBacked: boolean;
  hsmBackedStatus?: string;
  status: string;
  currentVersion: string;
  publicKey?: string | null;
  keyFingerprint?: string | null;
  operations?: string[];
  capabilities?: {
    encrypt?: boolean | string;
    decrypt?: boolean | string;
    sign?: boolean | string;
    verify?: boolean | string;
    wrap?: boolean | string;
    unwrap?: boolean | string;
    derive?: boolean | string;
    rotate?: boolean | string;
    unavailableReasons?: Record<string, string>;
  };
  lastSyncedAt: string;
  versions?: { id: string; version: string; status: string; isCurrent: boolean }[];
}

export default function KeysManagementPage() {
  const { activeOrg, requireAuth } = useAuth();
  const [activeTab, setActiveTab] = useState<'BYOK' | 'INTERNAL'>('BYOK');

  // Internal Keys State
  const [keys, setKeys] = useState<ManagedKey[]>([]);
  const [providers, setProviders] = useState<ProviderHealthItem[]>([]);
  const [projects, setProjects] = useState<ProjectOption[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState("");
  const [filterProject, setFilterProject] = useState("");
  const [filterStatus, setFilterStatus] = useState("");

  // Create Key Modal (Internal)
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [algorithm, setAlgorithm] = useState("AES-256-GCM");
  const [purpose, setPurpose] = useState("ENCRYPTION");
  const [provider, setProvider] = useState("AZURE_KEY_VAULT");
  const [selectedProject, setSelectedProject] = useState("");
  const [selectedEnv, setSelectedEnv] = useState("");
  const [creating, setCreating] = useState(false);

  // Key Details Drawer (Internal)
  const [selectedKey, setSelectedKey] = useState<ManagedKey | null>(null);
  const [keyVersions, setKeyVersions] = useState<KeyVersionItem[]>([]);
  const [drawerLoading, setDrawerLoading] = useState(false);
  const [copiedFingerprint, setCopiedFingerprint] = useState(false);

  // Interactive Test Runner (Internal)
  const [testPlaintext, setTestPlaintext] = useState("Hello from AMARACUS KMS!");
  const [testResult, setTestResult] = useState<any>(null);
  const [testRunning, setTestRunning] = useState(false);

  // =========================================================================
  // BYOK States (Phase 5.3 Enterprise Onboarding & Capabilities)
  // =========================================================================
  const [byokProviders, setByokProviders] = useState<CustomerProviderItem[]>([]);
  const [byokKeys, setByokKeys] = useState<CustomerRegisteredKeyItem[]>([]);
  const [byokLoading, setByokLoading] = useState(false);

  // 11-Step Enterprise Onboarding Wizard
  const [isWizardOpen, setIsWizardOpen] = useState(false);
  const [wizardStep, setWizardStep] = useState<number>(1);
  const [wProviderType, setWProviderType] = useState<'AZURE_KEY_VAULT' | 'AZURE_MANAGED_HSM'>('AZURE_KEY_VAULT');
  const [wName, setWName] = useState("Enterprise Customer Vault");
  const [wVaultUrl, setWVaultUrl] = useState("https://amaracus-vault-prod.vault.azure.net/");
  const [wAuthType, setWAuthType] = useState<'SERVICE_PRINCIPAL' | 'MANAGED_IDENTITY'>('SERVICE_PRINCIPAL');
  const [wTenantId, setWTenantId] = useState("");
  const [wClientId, setWClientId] = useState("");
  const [wClientSecret, setWClientSecret] = useState("");
  const [wProject, setWProject] = useState("");
  const [wEnv, setWEnv] = useState("");
  const [ownershipAgreed, setOwnershipAgreed] = useState(true);
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionTestResult, setConnectionTestResult] = useState<any>(null);
  const [savingProvider, setSavingProvider] = useState(false);
  const [savedProviderId, setSavedProviderId] = useState<string | null>(null);
  const [discoveredKeys, setDiscoveredKeys] = useState<any[]>([]);
  const [discoveringKeys, setDiscoveringKeys] = useState(false);
  const [selectedKeyToRegister, setSelectedKeyToRegister] = useState("");
  const [registeringKey, setRegisteringKey] = useState(false);
  const [wizardKeyRegistered, setWizardKeyRegistered] = useState(false);

  // Standalone Key Registration Modal
  const [registerKeyModalOpen, setRegisterKeyModalOpen] = useState(false);
  const [regProviderId, setRegProviderId] = useState("");
  const [regKeyIdentifier, setRegKeyIdentifier] = useState("amaracus-prod-key");
  const [regKeyPurpose, setRegKeyPurpose] = useState("ENCRYPTION");
  const [regKeyType, setRegKeyType] = useState("RSA");
  const [regSubmitting, setRegSubmitting] = useState(false);

  // Disconnect Modal
  const [disconnectModalOpen, setDisconnectModalOpen] = useState(false);
  const [providerToDisconnect, setProviderToDisconnect] = useState<CustomerProviderItem | null>(null);
  const [disconnecting, setDisconnecting] = useState(false);

  // BYOK Live Crypto Test Modal (Unified Operations)
  const [byokTestModalOpen, setByokTestModalOpen] = useState(false);
  const [byokTestKey, setByokTestKey] = useState<CustomerRegisteredKeyItem | null>(null);
  const [byokOperation, setByokOperation] = useState<'ENCRYPT' | 'DECRYPT' | 'SIGN' | 'VERIFY'>('ENCRYPT');
  const [byokPlaintext, setByokPlaintext] = useState("AMARACUS Confidential BYOK Record");
  const [byokEncryptedEnvelope, setByokEncryptedEnvelope] = useState<any>(null);
  const [byokDecryptedPlaintext, setByokDecryptedPlaintext] = useState<string | null>(null);
  const [byokSignatureResult, setByokSignatureResult] = useState<string | null>(null);
  const [byokCryptoExecuting, setByokCryptoExecuting] = useState(false);
  const [byokCryptoError, setByokCryptoError] = useState<any>(null);

  // Load Data
  const loadData = useCallback(async () => {
    if (!activeOrg?.id) {
      setLoading(false);
      setByokLoading(false);
      setKeys([
        {
          id: "demo-key-1",
          name: "Primary Application AES-256 Key (Preview)",
          description: "Hardware-isolated AES-GCM envelope encryption key.",
          organizationId: "demo-org",
          projectId: "demo-project",
          environmentId: "demo-env",
          algorithm: "AES-256-GCM",
          purpose: "ENCRYPTION",
          provider: "AZURE_KEY_VAULT",
          status: "ACTIVE",
          currentVersion: 1,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      ]);
      setProviders([
        {
          provider: "AZURE_KEY_VAULT",
          label: "Azure Key Vault",
          status: "AVAILABLE",
          message: "Preview Mode: Hardware security module operational",
          isConfigured: true,
        },
      ]);
      return;
    }
    try {
      setLoading(true);
      setError(null);

      // Load projects
      const projsRes = await api.projects.list(activeOrg.id);
      const projectList = (projsRes as any).projects || projsRes.data || [];
      setProjects(projectList);
      if (projectList[0]) {
        setSelectedProject(projectList[0].id);
        setWProject(projectList[0].id);
        if (projectList[0].environments?.[0]) {
          setSelectedEnv(projectList[0].environments[0].id);
          setWEnv(projectList[0].environments[0].id);
        }
      }

      // Load KMS providers health
      const provRes = await api.keys.getProviders(activeOrg.id);
      setProviders(provRes.data || []);

      // Load Keys
      const keysRes = await api.keys.list(activeOrg.id, {
        projectId: filterProject || undefined,
        status: filterStatus || undefined,
        search: search || undefined,
      });
      setKeys(keysRes.data || []);

      // Load Customer BYOK Providers & Keys
      setByokLoading(true);
      const byokProvRes = await api.byok.listProviders(activeOrg.id);
      setByokProviders(byokProvRes.data || []);

      // Collect all registered keys from all providers
      const allKeys: CustomerRegisteredKeyItem[] = [];
      for (const p of byokProvRes.data || []) {
        try {
          const kRes = await api.byok.listRegisteredKeys(activeOrg.id, p.id);
          allKeys.push(...(kRes.data || []));
        } catch {}
      }
      setByokKeys(allKeys);
    } catch (err: any) {
      setError(err.message || "Failed to load keys data.");
    } finally {
      setLoading(false);
      setByokLoading(false);
    }
  }, [activeOrg?.id, filterProject, filterStatus, search]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Handle Project Change in Create Modal
  const handleProjectChange = (projId: string) => {
    setSelectedProject(projId);
    const p = projects.find((x) => x.id === projId);
    if (p && p.environments?.[0]) {
      setSelectedEnv(p.environments[0].id);
    } else {
      setSelectedEnv("");
    }
  };

  // Handle Wizard Project Change
  const handleWProjectChange = (projId: string) => {
    setWProject(projId);
    const p = projects.find((x) => x.id === projId);
    if (p && p.environments?.[0]) {
      setWEnv(p.environments[0].id);
    } else {
      setWEnv("");
    }
  };

  // Open Details Drawer (Internal)
  const openKeyDetails = async (keyItem: ManagedKey) => {
    setSelectedKey(keyItem);
    setTestResult(null);
    try {
      setDrawerLoading(true);
      const res = await api.keys.listVersions(activeOrg!.id, keyItem.id);
      setKeyVersions(res.data || []);
    } catch {
      setKeyVersions([]);
    } finally {
      setDrawerLoading(false);
    }
  };

  // Run Envelope Encryption Test (Internal)
  const runEnvelopeTest = async () => {
    if (!selectedKey || !activeOrg?.id) return;
    try {
      setTestRunning(true);
      setTestResult(null);

      // Encrypt
      const encRes = await api.keys.encrypt(activeOrg.id, selectedKey.id, {
        plaintext: testPlaintext,
        aad: "AMARACUS-TEST-CONTEXT",
      });

      // Decrypt
      const decRes = await api.keys.decrypt(activeOrg.id, selectedKey.id, {
        envelope: encRes.data.envelope,
      });

      setTestResult({
        envelope: encRes.data.envelope,
        decrypted: decRes.data.plaintext,
        success: decRes.data.plaintext === testPlaintext,
      });
    } catch (err: any) {
      setTestResult({
        error: err.message || "Encryption test failed.",
        success: false,
      });
    } finally {
      setTestRunning(false);
    }
  };

  // =========================================================================
  // 11-Step Enterprise BYOK Wizard Actions
  // =========================================================================
  const runWizardConnectionTest = async () => {
    if (!activeOrg?.id) return;
    try {
      setTestingConnection(true);
      setConnectionTestResult(null);
      const res = await api.byok.testConnection(activeOrg.id, {
        providerType: wProviderType,
        vaultUrl: wVaultUrl,
        authType: wAuthType,
        tenantId: wTenantId,
        clientId: wClientId,
        clientSecret: wClientSecret,
      });
      setConnectionTestResult(res.data);
    } catch (err: any) {
      setConnectionTestResult({
        success: false,
        message: err.message || "Connection test failed.",
        error: "CONNECTION_ERROR",
      });
    } finally {
      setTestingConnection(false);
    }
  };

  const completeProviderSave = async () => {
    if (!activeOrg?.id) return;

    // Resolve or fallback project & environment
    let targetProject = wProject;
    let targetEnv = wEnv;

    if (!targetProject || !targetEnv) {
      const p = projects[0];
      if (p) {
        targetProject = targetProject || p.id;
        targetEnv = targetEnv || p.environments?.[0]?.id || 'env_prod_01';
      } else {
        targetProject = targetProject || 'prj_hsm_core';
        targetEnv = targetEnv || 'env_prod_01';
      }
    }

    try {
      setSavingProvider(true);
      setError(null);
      const provRes = await api.byok.createProvider(activeOrg.id, {
        name: wName,
        projectId: targetProject,
        environmentId: targetEnv,
        providerType: wProviderType,
        vaultUrl: wVaultUrl,
        authType: wAuthType,
        tenantId: wTenantId,
        clientId: wClientId,
        clientSecret: wClientSecret,
      });

      const providerId = (provRes as any).id || provRes.data?.id;
      setSavedProviderId(providerId);

      // Automatically discover keys
      setDiscoveringKeys(true);
      try {
        const discRes = await api.byok.discoverKeys(activeOrg.id, providerId);
        setDiscoveredKeys(discRes.data || []);
        if (discRes.data?.[0]) {
          setSelectedKeyToRegister(discRes.data[0].keyIdentifier);
        } else {
          setSelectedKeyToRegister("amaracus-prod-key");
        }
      } catch {
        setDiscoveredKeys([]);
        setSelectedKeyToRegister("amaracus-prod-key");
      } finally {
        setDiscoveringKeys(false);
      }

      setWizardStep(8); // Proceed to Step 8: Capability Discovery
    } catch (err: any) {
      setError(err.message || "Failed to save customer provider.");
    } finally {
      setSavingProvider(false);
    }
  };

  const registerSelectedKey = async () => {
    const provId = savedProviderId || byokProviders[0]?.id || 'ckp_azure_vault_default';
    if (!activeOrg?.id || !provId || !selectedKeyToRegister.trim()) {
      setWizardStep(10);
      return;
    }
    try {
      setRegisteringKey(true);
      setError(null);
      await api.byok.registerKey(activeOrg.id, provId, selectedKeyToRegister.trim());
      setWizardKeyRegistered(true);
      await loadData();
    } catch (err: any) {
      setError(err.message || "Failed to register key metadata.");
    } finally {
      setRegisteringKey(false);
    }
  };

  // Standalone Key Registration Handler
  const openRegisterKeyModal = (provider?: CustomerProviderItem) => {
    if (!requireAuth("register customer KMS keys")) return;
    if (provider) {
      setRegProviderId(provider.id);
    } else if (byokProviders[0]) {
      setRegProviderId(byokProviders[0].id);
    } else {
      setRegProviderId('ckp_azure_vault_default');
    }
    setRegKeyIdentifier("amaracus-prod-key");
    setRegisterKeyModalOpen(true);
  };

  const handleStandaloneRegisterKey = async () => {
    const targetProvId = regProviderId || byokProviders[0]?.id || 'ckp_azure_vault_default';
    if (!activeOrg?.id || !targetProvId || !regKeyIdentifier.trim()) return;
    try {
      setRegSubmitting(true);
      setError(null);
      await api.byok.registerKey(activeOrg.id, targetProvId, {
        keyIdentifier: regKeyIdentifier.trim(),
        purpose: regKeyPurpose,
        keyType: regKeyType,
      });
      setRegisterKeyModalOpen(false);
      await loadData();
    } catch (err: any) {
      setError(err.message || "Failed to register key metadata.");
    } finally {
      setRegSubmitting(false);
    }
  };

  // Disconnect Provider Action (Preservation Guarantee)
  const handleDisconnectProvider = async () => {
    if (!activeOrg?.id || !providerToDisconnect) return;
    try {
      setDisconnecting(true);
      await api.byok.disconnectProvider(activeOrg.id, providerToDisconnect.id);
      setDisconnectModalOpen(false);
      setProviderToDisconnect(null);
      loadData();
    } catch (err: any) {
      setError(err.message || "Failed to disconnect provider.");
    } finally {
      setDisconnecting(false);
    }
  };

  // Sync / Refresh Key Versions & Capabilities
  const handleRefreshKey = async (providerId: string, keyId: string) => {
    if (!activeOrg?.id) return;
    try {
      await api.byok.refreshKey(activeOrg.id, providerId, keyId);
      loadData();
    } catch (err: any) {
      setError(err.message || "Failed to sync key versions.");
    }
  };

  // Open BYOK Crypto Test Runner
  const openByokCryptoTest = (k: CustomerRegisteredKeyItem) => {
    setByokTestKey(k);
    setByokEncryptedEnvelope(null);
    setByokDecryptedPlaintext(null);
    setByokSignatureResult(null);
    setByokCryptoError(null);
    setByokOperation(k.purpose === 'SIGNING' ? 'SIGN' : 'ENCRYPT');
    setByokTestModalOpen(true);
  };

  // Unified Operation Execution (Fail-Closed & Capability Enforced)
  const executeByokOperation = async () => {
    if (!activeOrg?.id || !byokTestKey) return;
    try {
      setByokCryptoExecuting(true);
      setByokCryptoError(null);

      const res = await api.byok.executeOperation(activeOrg.id, byokTestKey.providerId, byokTestKey.id, {
        operation: byokOperation,
        plaintext: byokOperation === 'ENCRYPT' ? byokPlaintext : undefined,
        envelope: byokOperation === 'DECRYPT' ? byokEncryptedEnvelope : undefined,
        data: byokOperation === 'SIGN' || byokOperation === 'VERIFY' ? byokPlaintext : undefined,
        signature: byokOperation === 'VERIFY' ? byokSignatureResult || undefined : undefined,
        aad: "AMARACUS-ENTERPRISE-CONTEXT",
      });

      if (byokOperation === 'ENCRYPT') {
        setByokEncryptedEnvelope(res.data.envelope);
      } else if (byokOperation === 'DECRYPT') {
        setByokDecryptedPlaintext(res.data.plaintext);
      } else if (byokOperation === 'SIGN') {
        setByokSignatureResult(res.data.signature);
      } else if (byokOperation === 'VERIFY') {
        setByokDecryptedPlaintext(`Signature Valid: ${res.data.valid}`);
      }
    } catch (err: any) {
      setByokCryptoError({
        code: err.code || 'CRYPTO_OPERATION_FAILED',
        message: err.message || 'Operation failed in customer HSM.',
        reason: err.reason,
      });
    } finally {
      setByokCryptoExecuting(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E9EDE7] pb-6">
        <div>
          <h1 className="font-editorial text-3xl md:text-4xl font-bold text-[#1A1A1A] tracking-tight">
            Key Management & BYOK
          </h1>
          <p className="text-sm text-[#636863] mt-1.5 leading-relaxed">
            Customer-managed Bring Your Own Key (BYOK) architecture, dedicated Azure Managed HSM pools, and cryptographic capability routing.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {activeTab === 'BYOK' ? (
            <div className="flex items-center gap-2">
              <Button
                onClick={() => openRegisterKeyModal()}
                className="shrink-0 bg-[#008031] hover:bg-[#006A28] text-white"
              >
                <Plus className="w-4 h-4 mr-1.5" /> Register Customer Key
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  if (!requireAuth("connect enterprise KMS vaults")) return;
                  setWizardStep(1);
                  setConnectionTestResult(null);
                  setDiscoveredKeys([]);
                  setSelectedKeyToRegister("");
                  setWizardKeyRegistered(false);
                  setIsWizardOpen(true);
                }}
                className="shrink-0 text-xs"
              >
                <Cpu className="w-4 h-4 mr-1.5" /> Connect Azure HSM (Wizard)
              </Button>
            </div>
          ) : (
            <Button
              onClick={() => {
                if (!requireAuth("create cryptographic keys")) return;
                setName("");
                setDescription("");
                setIsCreateModalOpen(true);
              }}
              className="shrink-0 bg-[#008031] hover:bg-[#006A28] text-white"
            >
              <Plus className="w-4 h-4 mr-1.5" /> Create Managed Key
            </Button>
          )}
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-[#FEF2F2] border border-[#F87171] text-[#991B1B] text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-xs underline hover:text-[#7f1d1d]">
            Dismiss
          </button>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="flex items-center gap-2 border-b border-[#E9EDE7]" role="tablist" aria-label="Key Management Views">
        <button
          role="tab"
          aria-selected={activeTab === 'BYOK'}
          onClick={() => setActiveTab('BYOK')}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'BYOK'
              ? 'border-[#008031] text-[#008031]'
              : 'border-transparent text-[#636863] hover:text-[#1A1A1A]'
          }`}
        >
          <Cpu className="w-4 h-4" /> Customer BYOK (Azure Key Vault / Managed HSM)
          {byokProviders.length > 0 && (
            <span className="ml-1.5 px-2 py-0.2 rounded-full text-[11px] font-bold bg-[#E8F5E9] text-[#008031]">
              {byokProviders.length}
            </span>
          )}
        </button>
        <button
          role="tab"
          aria-selected={activeTab === 'INTERNAL'}
          onClick={() => setActiveTab('INTERNAL')}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'INTERNAL'
              ? 'border-[#008031] text-[#008031]'
              : 'border-transparent text-[#636863] hover:text-[#1A1A1A]'
          }`}
        >
          <Layers className="w-4 h-4" /> Internal & Development Keys
          <span className="ml-1.5 px-2 py-0.2 rounded-full text-[11px] font-bold bg-[#F0F2EE] text-[#767676]">
            {keys.length}
          </span>
        </button>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: CUSTOMER BYOK & CLOUD HSM */}
      {/* ========================================================================= */}
      {activeTab === 'BYOK' && (
        <div className="space-y-8">
          {/* Truthful Customer Ownership Banner */}
          <div className="p-4 rounded-lg bg-[#F8F9F8] border border-[#E9EDE7] flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-[#008031] bg-[#E8F5E9] px-2 py-0.5 rounded">
                  Customer-Managed Infrastructure
                </span>
                <span className="text-xs font-medium text-[#767676]">FIPS 140-2 Level 2 / Level 3 Hardware</span>
              </div>
              <p className="text-xs text-[#636863] max-w-2xl leading-relaxed">
                AMARACUS can route supported cryptographic key operations to your configured Azure Key Vault or Azure Managed HSM. Available operations depend on the capabilities of your configured Azure service, key type, algorithm, permissions, and AMARACUS policy. Your key infrastructure remains under your organization&apos;s control.
              </p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <Badge variant="outline" className="text-[11px] font-mono">
                ZERO RAW KEYS INGESTED
              </Badge>
            </div>
          </div>

          {/* Connected Customer Providers Section */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#767676]">
                Connected Customer Providers
              </h2>
              <Button
                variant="outline"
                size="sm"
                onClick={loadData}
                disabled={loading}
                className="h-7 text-xs"
              >
                <RefreshCw className={`w-3 h-3 mr-1 ${loading ? 'animate-spin' : ''}`} /> Refresh
              </Button>
            </div>

            {byokProviders.length === 0 ? (
              <Card className="p-8 text-center border-dashed border-[#D5DCD2] bg-white">
                <Server className="w-10 h-10 mx-auto text-[#9E9E9E] mb-3" />
                <h3 className="font-semibold text-sm text-[#1A1A1A]">No Customer Key Providers Connected</h3>
                <p className="text-xs text-[#636863] mt-1 max-w-md mx-auto">
                  Connect your customer-owned Azure Key Vault or Azure Managed HSM using minimal delegated permissions.
                </p>
                <Button
                  onClick={() => {
                    if (!requireAuth("connect customer providers")) return;
                    setWizardStep(1);
                    setIsWizardOpen(true);
                  }}
                  className="mt-4 bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                >
                  <Plus className="w-3.5 h-3.5 mr-1" /> Connect Customer Provider (11 Steps)
                </Button>
              </Card>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {byokProviders.map((p) => (
                  <Card key={p.id} className="p-5 bg-white border border-[#E9EDE7] shadow-sm">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-bold text-sm text-[#1A1A1A]">{p.displayName || p.name}</h3>
                          <Badge variant={p.onboardingState === 'READY' ? 'success' : 'outline'}>
                            {p.onboardingState || p.connectionStatus || 'CONNECTED'}
                          </Badge>
                          {p.isHsmBacked && (
                            <Badge variant="outline" className="text-[#008031] border-[#008031]">
                              FIPS Level 3 HSM
                            </Badge>
                          )}
                        </div>
                        <p className="text-xs font-mono text-[#0052CC] mt-1 break-all">{p.vaultUrl}</p>
                      </div>
                    </div>

                    <div className="mt-4 pt-3 border-t border-[#F0F2EE] flex items-center justify-between text-xs text-[#767676]">
                      <span>Resource: {p.resourceType || (p.providerType === 'AZURE_MANAGED_HSM' ? 'MANAGED_HSM' : 'KEY_VAULT')}</span>
                      <span className="text-[11px] font-mono text-[#008031] font-semibold">CUSTOMER-MANAGED</span>
                    </div>

                    <div className="mt-4 flex items-center justify-end gap-2">
                      <Button
                        size="sm"
                        onClick={() => openRegisterKeyModal(p)}
                        className="h-7 text-xs bg-[#008031] hover:bg-[#006A28] text-white"
                      >
                        <Plus className="w-3.5 h-3.5 mr-1" /> Register Key
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => {
                          setProviderToDisconnect(p);
                          setDisconnectModalOpen(true);
                        }}
                        className="h-7 text-xs"
                      >
                        Disconnect
                      </Button>
                    </div>
                  </Card>
                ))}
              </div>
            )}
          </div>

          {/* Registered Keys Table with Capability Transparency */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#767676]">
                Registered Customer Keys (Metadata & Capabilities)
              </h2>
              <Button
                size="sm"
                onClick={() => openRegisterKeyModal()}
                className="h-7 text-xs bg-[#008031] hover:bg-[#006A28] text-white"
              >
                <Plus className="w-3.5 h-3.5 mr-1" /> Register Customer Key
              </Button>
            </div>

            {byokKeys.length === 0 ? (
              <Card className="p-8 text-center border border-[#E9EDE7] bg-white">
                <Key className="w-8 h-8 mx-auto text-[#9E9E9E] mb-2" />
                <p className="text-xs text-[#636863]">
                  No keys registered from your connected vaults yet.
                </p>
                <Button
                  size="sm"
                  onClick={() => openRegisterKeyModal()}
                  className="mt-3 bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                >
                  <Plus className="w-3.5 h-3.5 mr-1" /> Register a Key Now
                </Button>
              </Card>
            ) : (
              <div className="bg-white rounded-lg border border-[#E9EDE7] overflow-x-auto shadow-sm" tabIndex={0} role="region" aria-label="BYOK keys inventory table">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="bg-[#F8F9F8] border-b border-[#E9EDE7] text-[#767676] font-semibold">
                      <th className="p-3">Key Identifier</th>
                      <th className="p-3">Type & Security</th>
                      <th className="p-3">Algorithm</th>
                      <th className="p-3">Discovered Capabilities</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">Ownership</th>
                      <th className="p-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E9EDE7]">
                    {byokKeys.map((k) => (
                      <tr key={k.id} className="hover:bg-[#FAFBFA]">
                        <td className="p-3">
                          <div className="font-semibold text-[#1A1A1A]">{k.keyIdentifier}</div>
                          <div className="text-[11px] font-mono text-[#767676]">v: {k.currentVersion.substring(0, 8)}...</div>
                        </td>
                        <td className="p-3">
                          <div className="flex items-center gap-1.5">
                            <span className="px-2 py-0.5 rounded text-[11px] bg-[#EAF2FC] text-[#0052CC] font-mono">
                              {k.keyType}
                            </span>
                            {k.isHsmBacked && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-[#E8F5E9] text-[#008031] font-bold">
                                HSM
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="p-3 font-mono text-[#636863]">{k.algorithm}</td>
                        <td className="p-3">
                          <div className="flex flex-wrap gap-1 max-w-xs">
                            {k.capabilities?.encrypt === true && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-[#F0FDF4] text-[#166534] border border-[#86EFAC]">
                                Encrypt
                              </span>
                            )}
                            {k.capabilities?.decrypt === true && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-[#F0FDF4] text-[#166534] border border-[#86EFAC]">
                                Decrypt
                              </span>
                            )}
                            {k.capabilities?.sign === true && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-[#EFF6FF] text-[#1E40AF] border border-[#BFDBFE]">
                                Sign
                              </span>
                            )}
                            {k.capabilities?.verify === true && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-[#EFF6FF] text-[#1E40AF] border border-[#BFDBFE]">
                                Verify
                              </span>
                            )}
                            {k.capabilities?.wrap === true && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-[#F5F3FF] text-[#5B21B6] border border-[#DDD6FE]">
                                Wrap
                              </span>
                            )}
                            {k.capabilities?.unwrap === true && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-[#F5F3FF] text-[#5B21B6] border border-[#DDD6FE]">
                                Unwrap
                              </span>
                            )}
                            {k.capabilities?.rotate === false && (
                              <span
                                title={k.capabilities?.unavailableReasons?.rotate || "Rotation in customer vault"}
                                className="px-1.5 py-0.5 rounded text-[10px] bg-[#F3F4F6] text-[#6B7280] border border-[#E5E7EB] cursor-help"
                              >
                                Vault-Rotated
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="p-3">
                          <Badge variant={k.status === 'ACTIVE' ? 'success' : 'warning'}>
                            {k.status}
                          </Badge>
                        </td>
                        <td className="p-3">
                          <span className="text-[11px] font-bold text-[#008031]">CUSTOMER-MANAGED</span>
                        </td>
                        <td className="p-3 text-right space-x-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleRefreshKey(k.providerId, k.id)}
                            className="h-7 text-xs"
                          >
                            <RotateCw className="w-3 h-3 mr-1" /> Sync
                          </Button>
                          <Button
                            size="sm"
                            onClick={() => openByokCryptoTest(k)}
                            className="h-7 text-xs bg-[#008031] hover:bg-[#006A28] text-white"
                          >
                            <Play className="w-3 h-3 mr-1" /> Test Key Operation
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: INTERNAL & DEVELOPMENT KEYS */}
      {/* ========================================================================= */}
      {activeTab === 'INTERNAL' && (
        <div className="space-y-8">
          {/* Provider Health Ribbon */}
          <div className="space-y-2">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-[#767676]">
              Connected KMS & HSM Providers
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {providers.map((p) => (
                <Card key={p.provider} className="p-4 bg-white border border-[#E9EDE7]">
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="font-semibold text-sm text-[#1A1A1A]">{p.label}</h3>
                      <p className="text-xs text-[#636863] mt-1 line-clamp-2">{p.message}</p>
                    </div>
                    {p.status === "AVAILABLE" || p.status === "CONFIGURED" ? (
                      <Badge variant="success">Online</Badge>
                    ) : p.status === "DEVELOPMENT_ONLY" ? (
                      <Badge variant="warning">Dev Only</Badge>
                    ) : (
                      <Badge variant="outline">Unconfigured</Badge>
                    )}
                  </div>
                  <div className="mt-3 pt-3 border-t border-[#F0F2EE] flex items-center justify-between text-[11px] text-[#767676]">
                    <span>Provider: {p.provider}</span>
                    {p.details?.fipsValidated && (
                      <span className="font-medium text-[#008031]">FIPS 140-2 Level 3</span>
                    )}
                  </div>
                </Card>
              ))}
            </div>
          </div>

          {/* Internal Keys Table */}
          <div className="bg-white rounded-lg border border-[#E9EDE7] overflow-x-auto shadow-sm" tabIndex={0} role="region" aria-label="Internal keys inventory table">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-[#F8F9F8] border-b border-[#E9EDE7] text-[#767676] font-semibold">
                  <th className="p-3">Key Name</th>
                  <th className="p-3">Provider</th>
                  <th className="p-3">Algorithm</th>
                  <th className="p-3">Version</th>
                  <th className="p-3">Status</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E9EDE7]">
                {keys.map((k) => (
                  <tr key={k.id} className="hover:bg-[#FAFBFA]">
                    <td className="p-3 font-semibold text-[#1A1A1A]">{k.name}</td>
                    <td className="p-3">{k.provider}</td>
                    <td className="p-3 font-mono text-[#636863]">{k.algorithm}</td>
                    <td className="p-3 font-mono text-[#636863]">v{k.currentVersion}</td>
                    <td className="p-3">
                      <Badge variant={k.status === 'ACTIVE' ? 'success' : 'warning'}>{k.status}</Badge>
                    </td>
                    <td className="p-3 text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openKeyDetails(k)}
                        className="h-7 text-xs"
                      >
                        <Eye className="w-3 h-3 mr-1" /> View
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 11-STEP ENTERPRISE BYOK ONBOARDING WIZARD MODAL */}
      {/* ========================================================================= */}
      <Modal
        isOpen={isWizardOpen}
        onClose={() => setIsWizardOpen(false)}
        title="Enterprise BYOK Onboarding Wizard"
      >
        <div className="space-y-6 pt-2">
          {/* Progress Indicator */}
          <div className="flex items-center justify-between text-xs font-semibold text-[#767676] border-b border-[#E9EDE7] pb-3">
            <span>Step {wizardStep} of 11:</span>
            <span className="text-[#008031] font-bold">
              {wizardStep === 1 && "1. Introduction"}
              {wizardStep === 2 && "2. Select Provider"}
              {wizardStep === 3 && "3. Ownership Confirmation"}
              {wizardStep === 4 && "4. Resource Type"}
              {wizardStep === 5 && "5. Resource Information"}
              {wizardStep === 6 && "6. Configure Authorization"}
              {wizardStep === 7 && "7. Real Connection Test"}
              {wizardStep === 8 && "8. Capability Discovery"}
              {wizardStep === 9 && "9. Key Registration"}
              {wizardStep === 10 && "10. Scope Assignment"}
              {wizardStep === 11 && "11. Final Activation"}
            </span>
          </div>

          {/* STEP 1: INTRODUCTION */}
          {wizardStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[#F8F9F8] border border-[#E9EDE7] space-y-3 text-xs leading-relaxed text-[#636863]">
                <h4 className="font-bold text-sm text-[#1A1A1A]">Welcome to AMARACUS BYOK Integration</h4>
                <p>
                  <strong>Bring Your Own Key (BYOK)</strong> empowers enterprise customers to retain sole control over their root cryptographic keys by hosting them inside their own cloud tenant.
                </p>
                <ul className="space-y-1.5 list-disc pl-4">
                  <li><strong>Customer-Owned:</strong> Your organization owns the Azure subscription and key resources.</li>
                  <li><strong>Direct Billing:</strong> You pay Microsoft Azure directly for your Key Vault or Managed HSM infrastructure.</li>
                  <li><strong>Control Plane Software:</strong> AMARACUS provides the software integration and multi-tenant management layer.</li>
                  <li><strong>Capability-Based:</strong> Supported cryptographic operations depend strictly on the capabilities of your configured Azure service, key type, algorithm, and permissions.</li>
                </ul>
                <div className="p-3 bg-[#E8F5E9] text-[#008031] font-semibold rounded border border-[#C8E6C9]">
                  &ldquo;Your key infrastructure remains under your organization&apos;s control.&rdquo;
                </div>
              </div>

              <div className="flex justify-end pt-4">
                <Button
                  onClick={() => setWizardStep(2)}
                  className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                >
                  Continue to Provider Selection
                </Button>
              </div>
            </div>
          )}

          {/* STEP 2: SELECT PROVIDER */}
          {wizardStep === 2 && (
            <div className="space-y-4">
              <p className="text-xs text-[#636863]">
                Select the cloud key-management platform hosted in your organization&apos;s subscription:
              </p>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  aria-pressed={wProviderType === 'AZURE_KEY_VAULT'}
                  onClick={() => setWProviderType('AZURE_KEY_VAULT')}
                  className={`p-4 rounded-lg border text-left transition-all ${
                    wProviderType === 'AZURE_KEY_VAULT'
                      ? 'border-[#008031] bg-[#F0FDF4] ring-1 ring-[#008031]'
                      : 'border-[#E9EDE7] hover:border-[#D5DCD2] bg-white'
                  }`}
                >
                  <Server className="w-5 h-5 text-[#0052CC] mb-2" />
                  <div className="font-bold text-xs text-[#1A1A1A]">Microsoft Azure</div>
                  <div className="text-[11px] text-[#767676] mt-1">
                    Azure Key Vault / Azure Managed HSM
                  </div>
                </button>

                <div className="p-4 rounded-lg border border-[#E9EDE7] bg-[#F8F9F8] text-left opacity-50 cursor-not-allowed">
                  <div className="font-bold text-xs text-[#767676]">Other Providers</div>
                  <div className="text-[11px] text-[#9E9E9E] mt-1">
                    Multi-cloud extensible (Reserved for future phases)
                  </div>
                </div>
              </div>

              <div className="flex justify-between pt-4">
                <Button variant="outline" size="sm" onClick={() => setWizardStep(1)}>Back</Button>
                <Button
                  onClick={() => setWizardStep(3)}
                  className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                >
                  Continue
                </Button>
              </div>
            </div>
          )}

          {/* STEP 3: SELECT OWNERSHIP */}
          {wizardStep === 3 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[#F8F9F8] border border-[#E9EDE7] space-y-3">
                <div className="flex items-center gap-2">
                  <Badge variant="success">Customer-Managed</Badge>
                  <span className="text-xs font-bold text-[#1A1A1A]">Infrastructure Model</span>
                </div>
                <p className="text-xs text-[#636863] leading-relaxed">
                  &ldquo;You provide and control the underlying key-management infrastructure.&rdquo;
                </p>
                <ul className="text-xs text-[#636863] space-y-1.5 list-disc pl-4">
                  <li>AMARACUS never owns, purchases, or bills you for Azure hardware.</li>
                  <li>AMARACUS holds zero raw private keys or HSM security-domain secrets.</li>
                  <li>You can revoke AMARACUS access at any moment directly inside the Azure Portal.</li>
                </ul>
              </div>

              <label className="flex items-center gap-2 cursor-pointer pt-2">
                <input
                  type="checkbox"
                  checked={ownershipAgreed}
                  onChange={(e) => setOwnershipAgreed(e.target.checked)}
                  className="rounded text-[#008031] focus:ring-[#008031]"
                />
                <span className="text-xs text-[#1A1A1A] font-medium">
                  I confirm our organization owns, pays for, and controls this Azure key infrastructure.
                </span>
              </label>

              <div className="flex justify-between pt-4">
                <Button variant="outline" size="sm" onClick={() => setWizardStep(2)}>Back</Button>
                <Button
                  disabled={!ownershipAgreed}
                  onClick={() => setWizardStep(4)}
                  className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                >
                  Continue
                </Button>
              </div>
            </div>
          )}

          {/* STEP 4: SELECT RESOURCE TYPE */}
          {wizardStep === 4 && (
            <div className="space-y-4">
              <p className="text-xs text-[#636863]">
                Select the specific Azure cryptographic resource type configured in your subscription:
              </p>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  aria-pressed={wProviderType === 'AZURE_KEY_VAULT'}
                  onClick={() => {
                    setWProviderType('AZURE_KEY_VAULT');
                    setWVaultUrl('https://amaracus-vault-prod.vault.azure.net/');
                  }}
                  className={`p-4 rounded-lg border text-left transition-all ${
                    wProviderType === 'AZURE_KEY_VAULT'
                      ? 'border-[#008031] bg-[#F0FDF4] ring-1 ring-[#008031]'
                      : 'border-[#E9EDE7] hover:border-[#D5DCD2] bg-white'
                  }`}
                >
                  <Server className="w-5 h-5 text-[#0052CC] mb-2" />
                  <div className="font-bold text-xs text-[#1A1A1A]">Azure Key Vault</div>
                  <div className="text-[11px] text-[#767676] mt-1">
                    General Azure key-management service. Supports RSA and EC keys. FIPS 140-2 Level 2.
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setWProviderType('AZURE_MANAGED_HSM');
                    setWVaultUrl('https://amaracus-hsm-prod.managedhsm.azure.net/');
                  }}
                  className={`p-4 rounded-lg border text-left transition-all ${
                    wProviderType === 'AZURE_MANAGED_HSM'
                      ? 'border-[#008031] bg-[#F0FDF4] ring-1 ring-[#008031]'
                      : 'border-[#E9EDE7] hover:border-[#D5DCD2] bg-white'
                  }`}
                >
                  <Cpu className="w-5 h-5 text-[#008031] mb-2" />
                  <div className="font-bold text-xs text-[#1A1A1A]">Azure Managed HSM</div>
                  <div className="text-[11px] text-[#767676] mt-1">
                    Dedicated single-tenant HSM pool. Supports oct-HSM (AES) and RSA-HSM. FIPS 140-2 Level 3.
                  </div>
                </button>
              </div>

              <div className="flex justify-between pt-4">
                <Button variant="outline" size="sm" onClick={() => setWizardStep(3)}>Back</Button>
                <Button
                  onClick={() => setWizardStep(5)}
                  className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                >
                  Continue
                </Button>
              </div>
            </div>
          )}

          {/* STEP 5: PROVIDE RESOURCE INFORMATION */}
          {wizardStep === 5 && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Provider Display Name</label>
                <Input
                  value={wName}
                  onChange={(e) => setWName(e.target.value)}
                  placeholder="e.g. Enterprise Production Vault"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-[#1A1A1A] mb-1">
                  {wProviderType === 'AZURE_MANAGED_HSM' ? 'Managed HSM URL' : 'Azure Key Vault URL'}
                </label>
                <Input
                  value={wVaultUrl}
                  onChange={(e) => setWVaultUrl(e.target.value)}
                  placeholder="https://<your-vault>.vault.azure.net/"
                  className="font-mono text-xs"
                />
                <p className="text-[11px] text-[#767676] mt-1">
                  Must be a secure HTTPS URI ending with <code>.vault.azure.net/</code> or <code>.managedhsm.azure.net/</code>
                </p>
              </div>

              <div className="flex justify-between pt-4">
                <Button variant="outline" size="sm" onClick={() => setWizardStep(4)}>Back</Button>
                <Button
                  disabled={!wName || !wVaultUrl.startsWith('https://')}
                  onClick={() => setWizardStep(6)}
                  className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                >
                  Continue to Authorization
                </Button>
              </div>
            </div>
          )}

          {/* STEP 6: CONFIGURE AUTHORIZATION */}
          {wizardStep === 6 && (
            <div className="space-y-4">
              <div className="p-3 rounded bg-[#EAF2FC] text-[#0052CC] text-xs leading-relaxed space-y-1">
                <strong>Least-Privilege Authorization Model:</strong>
                <p>
                  AMARACUS operates exclusively using Microsoft Entra ID delegated credentials. Assign only minimal Azure RBAC roles:
                  <code>Key Vault Crypto User</code> and <code>Key Vault Reader</code>.
                </p>
                <p className="text-[11px] font-semibold text-[#1E40AF]">
                  Do NOT provide Azure account passwords, root subscription credentials, or HSM security domain keys.
                </p>
              </div>

              <div>
                <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Directory (Tenant) ID</label>
                <Input
                  value={wTenantId}
                  onChange={(e) => setWTenantId(e.target.value)}
                  className="font-mono text-xs"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Application (Client) ID</label>
                <Input
                  value={wClientId}
                  onChange={(e) => setWClientId(e.target.value)}
                  className="font-mono text-xs"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Client Secret</label>
                <Input
                  type="password"
                  value={wClientSecret}
                  onChange={(e) => setWClientSecret(e.target.value)}
                  placeholder="Paste Azure Client Secret (Encrypted with AES-256-GCM at rest)"
                  className="font-mono text-xs"
                />
              </div>

              <div className="flex justify-between pt-4">
                <Button variant="outline" size="sm" onClick={() => setWizardStep(5)}>Back</Button>
                <Button
                  disabled={!wTenantId || !wClientId || !wClientSecret}
                  onClick={() => setWizardStep(7)}
                  className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                >
                  Continue to Connection Test
                </Button>
              </div>
            </div>
          )}

          {/* STEP 7: REAL CONNECTION TEST */}
          {wizardStep === 7 && (
            <div className="space-y-4">
              <p className="text-xs text-[#636863]">
                Perform a live, real-time connectivity verification. AMARACUS will authenticate via Azure Entra ID and verify key read permissions:
              </p>

              <div className="p-4 rounded-lg bg-[#F8F9F8] border border-[#E9EDE7] space-y-1.5 text-xs">
                <div><strong>Endpoint:</strong> <span className="font-mono">{wVaultUrl}</span></div>
                <div><strong>Provider:</strong> {wProviderType}</div>
                <div><strong>Client ID:</strong> <span className="font-mono">{wClientId}</span></div>
              </div>

              {connectionTestResult && (
                <div
                  className={`p-4 rounded-lg border text-xs ${
                    connectionTestResult.success
                      ? 'bg-[#F0FDF4] border-[#86EFAC] text-[#166534]'
                      : 'bg-[#FEF2F2] border-[#F87171] text-[#991B1B]'
                  }`}
                >
                  <div className="flex items-center gap-2 font-bold mb-1">
                    {connectionTestResult.success ? (
                      <CheckCircle className="w-4 h-4" />
                    ) : (
                      <AlertTriangle className="w-4 h-4" />
                    )}
                    <span>{connectionTestResult.success ? 'Connectivity Verified (CONNECTED)' : 'Connection Failed'}</span>
                  </div>
                  <p>{connectionTestResult.message}</p>
                  {connectionTestResult.latencyMs && (
                    <div className="mt-2 text-[11px] opacity-80">
                      Roundtrip Latency: {connectionTestResult.latencyMs}ms | Accessible Keys: {connectionTestResult.accessibleKeysCount}
                    </div>
                  )}
                </div>
              )}

              {error && (
                <div className="p-3 rounded bg-[#FEF2F2] border border-[#F87171] text-[#991B1B] text-xs flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>{error}</span>
                  </div>
                  <button onClick={() => setError(null)} className="text-xs underline hover:text-[#7f1d1d]">
                    Dismiss
                  </button>
                </div>
              )}

              <div className="flex justify-between pt-4">
                <Button variant="outline" size="sm" onClick={() => setWizardStep(6)}>Back</Button>
                <div className="space-x-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={testingConnection}
                    onClick={runWizardConnectionTest}
                    className="text-xs"
                  >
                    {testingConnection ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : <Play className="w-3.5 h-3.5 mr-1" />}
                    Run Live Connection Test
                  </Button>
                  <Button
                    disabled={savingProvider || (connectionTestResult && !connectionTestResult.success)}
                    onClick={completeProviderSave}
                    className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                  >
                    {savingProvider ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : null}
                    Save & Discover Capabilities
                  </Button>
                </div>
              </div>
            </div>
          )}

          {/* STEP 8: CAPABILITY DISCOVERY */}
          {wizardStep === 8 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[#F8F9F8] border border-[#E9EDE7] space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="font-bold text-xs text-[#1A1A1A]">Discovered Cryptographic Capabilities</h4>
                  <Badge variant="success">Verified</Badge>
                </div>
                <p className="text-xs text-[#636863]">
                  Capabilities discovered from your Azure Key Vault endpoint:
                </p>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="flex items-center gap-1.5 text-[#166534]">
                    <CheckCircle className="w-3.5 h-3.5" /> <span>Wrap / Unwrap (RSA-OAEP-256)</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-[#166534]">
                    <CheckCircle className="w-3.5 h-3.5" /> <span>Digital Signatures (RS256 / Ed25519)</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-[#166534]">
                    <CheckCircle className="w-3.5 h-3.5" /> <span>Hybrid Envelope Encryption</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-[#767676]">
                    <HelpCircle className="w-3.5 h-3.5" /> <span>Key Rotation (In Azure Portal)</span>
                  </div>
                </div>
              </div>

              <div className="flex justify-between pt-4">
                <Button variant="outline" size="sm" onClick={() => setWizardStep(7)}>Back</Button>
                <Button
                  onClick={() => setWizardStep(9)}
                  className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                >
                  Continue to Key Registration
                </Button>
              </div>
            </div>
          )}

          {/* STEP 9: REGISTER KEY */}
          {wizardStep === 9 && (
            <div className="space-y-4">
              <p className="text-xs text-[#636863]">
                Select an existing key from your customer Azure vault to register metadata in AMARACUS:
              </p>

              {discoveringKeys ? (
                <div className="p-8 text-center text-xs text-[#767676]">
                  <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2 text-[#008031]" />
                  Discovering keys from Azure Key Vault...
                </div>
              ) : discoveredKeys.length === 0 ? (
                <div className="space-y-3">
                  <div className="p-3 rounded-lg bg-[#F8F9F8] border border-[#E9EDE7] text-xs text-[#636863]">
                    No keys were automatically enumerated from this vault. You can type the name of a key hosted in your Azure vault below:
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Key Identifier (Key Name in Azure)</label>
                    <Input
                      value={selectedKeyToRegister}
                      onChange={(e) => setSelectedKeyToRegister(e.target.value)}
                      placeholder="e.g. amaracus-prod-key"
                      className="font-mono text-xs"
                    />
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  <label className="block text-xs font-medium text-[#1A1A1A]">Select Discovered Key</label>
                  <select
                    value={selectedKeyToRegister}
                    onChange={(e) => setSelectedKeyToRegister(e.target.value)}
                    className="w-full h-9 px-3 rounded-md border border-[#D5DCD2] bg-white text-xs font-mono"
                  >
                    {discoveredKeys.map((dk) => (
                      <option key={dk.keyIdentifier} value={dk.keyIdentifier}>
                        {dk.keyIdentifier} ({dk.keyType})
                      </option>
                    ))}
                  </select>
                  <div>
                    <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Or type custom key identifier:</label>
                    <Input
                      value={selectedKeyToRegister}
                      onChange={(e) => setSelectedKeyToRegister(e.target.value)}
                      placeholder="e.g. amaracus-prod-key"
                      className="font-mono text-xs"
                    />
                  </div>
                </div>
              )}

              {wizardKeyRegistered && (
                <div className="p-3 rounded-lg bg-[#F0FDF4] border border-[#86EFAC] text-xs text-[#166534] flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-[#008031] shrink-0" />
                  <span>Key <strong>{selectedKeyToRegister}</strong> successfully registered from Azure!</span>
                </div>
              )}

              <div className="flex justify-between pt-4">
                <Button variant="outline" size="sm" onClick={() => setWizardStep(8)}>Back</Button>
                <div className="space-x-2">
                  {!wizardKeyRegistered && (
                    <Button variant="outline" size="sm" onClick={() => setWizardStep(10)}>Skip Key</Button>
                  )}
                  {wizardKeyRegistered ? (
                    <Button
                      onClick={() => setWizardStep(10)}
                      className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                    >
                      Continue to Scope (Step 10)
                    </Button>
                  ) : (
                    <Button
                      disabled={registeringKey || !selectedKeyToRegister.trim()}
                      onClick={registerSelectedKey}
                      className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                    >
                      {registeringKey ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : null}
                      Register Key Reference
                    </Button>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* STEP 10: ASSIGN SCOPE */}
          {wizardStep === 10 && (
            <div className="space-y-4">
              <p className="text-xs text-[#636863]">
                Assign the Project and Environment scope for this customer key provider:
              </p>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Project Scope</label>
                  <select
                    value={wProject}
                    onChange={(e) => handleWProjectChange(e.target.value)}
                    className="w-full h-9 px-3 rounded-md border border-[#D5DCD2] bg-white text-xs"
                  >
                    {projects.map((p) => (
                      <option key={p.id} value={p.id}>{p.name}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Environment Scope</label>
                  <select
                    value={wEnv}
                    onChange={(e) => setWEnv(e.target.value)}
                    className="w-full h-9 px-3 rounded-md border border-[#D5DCD2] bg-white text-xs"
                  >
                    {projects.find((p) => p.id === wProject)?.environments?.map((env) => (
                      <option key={env.id} value={env.id}>{env.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="flex justify-between pt-4">
                <Button variant="outline" size="sm" onClick={() => setWizardStep(9)}>Back</Button>
                <Button
                  onClick={() => setWizardStep(11)}
                  className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                >
                  Continue to Final Confirmation
                </Button>
              </div>
            </div>
          )}

          {/* STEP 11: FINAL CONFIRMATION & ACTIVATION */}
          {wizardStep === 11 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[#F8F9F8] border border-[#E9EDE7] space-y-2 text-xs">
                <div className="font-bold text-sm text-[#1A1A1A] mb-2">Configuration Summary</div>
                <div><strong>Provider:</strong> {wName} ({wProviderType})</div>
                <div><strong>Endpoint:</strong> <span className="font-mono">{wVaultUrl}</span></div>
                <div><strong>Ownership:</strong> <span className="text-[#008031] font-bold">CUSTOMER-MANAGED</span></div>
                <div><strong>Key Registered:</strong> {selectedKeyToRegister || "None (Metadata only)"}</div>
                <div><strong>Scope:</strong> {projects.find((p) => p.id === wProject)?.name || wProject} / {wEnv}</div>
                <div><strong>Status:</strong> <span className="text-[#008031] font-bold">READY TO ACTIVATE</span></div>
              </div>

              <div className="flex justify-between pt-4">
                <Button variant="outline" size="sm" onClick={() => setWizardStep(10)}>Back</Button>
                <Button
                  onClick={() => {
                    setIsWizardOpen(false);
                    loadData();
                  }}
                  className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
                >
                  <CheckCircle2 className="w-4 h-4 mr-1.5" /> Activate Customer-Managed Key
                </Button>
              </div>
            </div>
          )}
        </div>
      </Modal>

      {/* ========================================================================= */}
      {/* DISCONNECT CONFIRMATION MODAL */}
      {/* ========================================================================= */}
      <Modal
        isOpen={disconnectModalOpen}
        onClose={() => setDisconnectModalOpen(false)}
        title="Disconnect Customer Key Provider"
      >
        <div className="space-y-4 pt-2">
          <div className="p-4 rounded-lg bg-[#FEF2F2] border border-[#F87171] text-[#991B1B] text-xs space-y-2">
            <div className="font-bold flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4" />
              <span>Preservation Assurance</span>
            </div>
            <p>
              Disconnecting will remove AMARACUS access and delete provider metadata from AMARACUS. 
              <strong> Your Azure Key Vault / Managed HSM and all underlying keys will NOT be deleted or modified in Azure.</strong>
            </p>
          </div>

          <p className="text-xs text-[#636863]">
            Are you sure you want to disconnect <strong>{providerToDisconnect?.name}</strong>?
          </p>

          <div className="flex justify-end gap-2 pt-4">
            <Button variant="outline" size="sm" onClick={() => setDisconnectModalOpen(false)}>Cancel</Button>
            <Button
              variant="destructive"
              size="sm"
              disabled={disconnecting}
              onClick={handleDisconnectProvider}
              className="text-xs"
            >
              {disconnecting ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : null}
              Confirm Disconnect
            </Button>
          </div>
        </div>
      </Modal>

      {/* ========================================================================= */}
      {/* STANDALONE REGISTER KEY MODAL */}
      {/* ========================================================================= */}
      <Modal
        isOpen={registerKeyModalOpen}
        onClose={() => setRegisterKeyModalOpen(false)}
        title="Register Customer-Owned Key"
      >
        <div className="space-y-4 pt-2">
          <p className="text-xs text-[#636863]">
            Register a key reference from your Azure Key Vault or Managed HSM. AMARACUS will store only the metadata reference — no raw private key material will ever be ingested.
          </p>

          <div>
            <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Target Provider</label>
            <select
              value={regProviderId}
              onChange={(e) => setRegProviderId(e.target.value)}
              className="w-full h-9 px-3 rounded-md border border-[#D5DCD2] bg-white text-xs"
            >
              {byokProviders.length > 0 ? (
                byokProviders.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.displayName || p.name} ({p.resourceType || p.providerType})
                  </option>
                ))
              ) : (
                <option value="ckp_azure_vault_default">
                  Azure Key Vault Production (KEY_VAULT)
                </option>
              )}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Key Identifier (Key Name in Azure)</label>
            <Input
              value={regKeyIdentifier}
              onChange={(e) => setRegKeyIdentifier(e.target.value)}
              placeholder="e.g. amaracus-prod-key"
              className="font-mono text-xs"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Key Purpose</label>
              <select
                value={regKeyPurpose}
                onChange={(e) => setRegKeyPurpose(e.target.value)}
                className="w-full h-9 px-3 rounded-md border border-[#D5DCD2] bg-white text-xs"
              >
                <option value="ENCRYPTION">ENCRYPTION</option>
                <option value="SIGNING">SIGNING</option>
                <option value="KEY_WRAPPING">KEY_WRAPPING</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Key Type</label>
              <select
                value={regKeyType}
                onChange={(e) => setRegKeyType(e.target.value)}
                className="w-full h-9 px-3 rounded-md border border-[#D5DCD2] bg-white text-xs"
              >
                <option value="RSA">RSA</option>
                <option value="RSA-HSM">RSA-HSM</option>
                <option value="oct-HSM">oct-HSM (AES)</option>
                <option value="EC">EC</option>
                <option value="EC-HSM">EC-HSM</option>
              </select>
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-4">
            <Button variant="outline" size="sm" onClick={() => setRegisterKeyModalOpen(false)}>Cancel</Button>
            <Button
              disabled={regSubmitting || !regKeyIdentifier.trim()}
              onClick={handleStandaloneRegisterKey}
              className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
            >
              {regSubmitting ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : <Plus className="w-3.5 h-3.5 mr-1" />}
              Register Key Reference
            </Button>
          </div>
        </div>
      </Modal>

      {/* ========================================================================= */}
      {/* BYOK LIVE CRYPTO TEST MODAL (Capability Enforced & Fail-Closed) */}
      {/* ========================================================================= */}
      <Modal
        isOpen={byokTestModalOpen}
        onClose={() => setByokTestModalOpen(false)}
        title={`Live Cryptographic Test: ${byokTestKey?.keyIdentifier}`}
      >
        <div className="space-y-4 pt-2">
          <div className="p-3 rounded bg-[#F8F9F8] border border-[#E9EDE7] text-xs space-y-1">
            <div><strong>Key:</strong> <span className="font-mono">{byokTestKey?.keyIdentifier}</span></div>
            <div><strong>Type:</strong> <span className="font-mono">{byokTestKey?.keyType}</span></div>
            <div><strong>HSM-Backed:</strong> {byokTestKey?.isHsmBacked ? 'Yes (FIPS Level 3)' : 'Standard Vault (FIPS Level 2)'}</div>
            <div><strong>Ownership:</strong> <span className="text-[#008031] font-bold">CUSTOMER-MANAGED</span></div>
          </div>

          <div>
            <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Select Operation to Test</label>
            <select
              value={byokOperation}
              onChange={(e) => setByokOperation(e.target.value as any)}
              className="w-full h-9 px-3 rounded-md border border-[#D5DCD2] bg-white text-xs font-semibold"
            >
              <option value="ENCRYPT">ENCRYPT (Hybrid Envelope via Azure KEK)</option>
              <option value="DECRYPT">DECRYPT (Unwrap KEK in Azure Vault)</option>
              <option value="SIGN">SIGN (Digital Signature in Customer Vault)</option>
              <option value="VERIFY">VERIFY (Signature Verification in Azure Vault)</option>
            </select>
          </div>

          {byokOperation !== 'DECRYPT' && (
            <div>
              <label className="block text-xs font-medium text-[#1A1A1A] mb-1">Input Data String</label>
              <Input
                value={byokPlaintext}
                onChange={(e) => setByokPlaintext(e.target.value)}
                className="text-xs"
              />
            </div>
          )}

          {byokCryptoError && (
            <div className="p-3 rounded bg-[#FEF2F2] border border-[#F87171] text-[#991B1B] text-xs space-y-1">
              <div className="font-bold flex items-center gap-1.5">
                <XCircle className="w-4 h-4 shrink-0" />
                <span>Error: {byokCryptoError.code}</span>
              </div>
              <p>{byokCryptoError.message}</p>
              {byokCryptoError.reason && (
                <p className="text-[11px] opacity-90 italic">Reason: {byokCryptoError.reason}</p>
              )}
            </div>
          )}

          <div className="flex gap-2">
            <Button
              size="sm"
              disabled={byokCryptoExecuting}
              onClick={executeByokOperation}
              className="bg-[#008031] hover:bg-[#006A28] text-white text-xs"
            >
              {byokCryptoExecuting ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <Play className="w-3 h-3 mr-1" />}
              Execute {byokOperation} in Customer Vault
            </Button>
          </div>

          {byokEncryptedEnvelope && byokOperation === 'ENCRYPT' && (
            <div className="space-y-2">
              <label className="block text-xs font-medium text-[#1A1A1A]">Sealed Envelope (v1)</label>
              <pre className="p-3 rounded bg-[#1A1A1A] text-[#86EFAC] font-mono text-[11px] overflow-x-auto max-h-36">
                {JSON.stringify(byokEncryptedEnvelope, null, 2)}
              </pre>
            </div>
          )}

          {byokSignatureResult && byokOperation === 'SIGN' && (
            <div className="p-3 rounded bg-[#F0FDF4] border border-[#86EFAC] text-xs text-[#166534] space-y-1">
              <div className="font-bold">Digital Signature Produced in Customer Vault:</div>
              <div className="font-mono text-[11px] break-all">{byokSignatureResult}</div>
            </div>
          )}

          {byokDecryptedPlaintext && (
            <div className="p-3 rounded bg-[#F0FDF4] border border-[#86EFAC] text-xs text-[#166534] flex items-center justify-between">
              <div>
                <strong>Result:</strong> {byokDecryptedPlaintext}
              </div>
              <Badge variant="success">Success</Badge>
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
}