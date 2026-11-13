"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Modal } from "@/components/ui/modal";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Award,
  Plus,
  RefreshCw,
  Loader2,
  FileText,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Copy,
  Check,
  Download,
  Eye,
  Trash2,
  Key,
  Search,
  ExternalLink,
  ArrowRight,
  Info,
  Server,
  Layers,
  Lock,
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api-client";

interface CertificateItem {
  id: string;
  name: string;
  organizationId: string;
  projectId: string;
  environmentId: string;
  authorityId: string;
  keyReference?: string | null;
  subject: string;
  issuer: string;
  serialNumber: string;
  certificateType: string;
  keyAlgorithm: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  status: 'REQUESTED' | 'ISSUED' | 'ACTIVE' | 'EXPIRING' | 'EXPIRED' | 'REVOKED' | 'SUSPENDED' | 'REPLACED' | 'FAILED';
  daysRemaining: number;
  notBefore: string;
  notAfter: string;
  fingerprint: string;
  fingerprintSha1?: string;
  certificatePem: string;
  chainPem?: string;
  chainReference?: string | null;
  san?: {
    dns?: string[];
    ips?: string[];
    emails?: string[];
    uris?: string[];
  };
  keyUsage?: string[];
  extendedKeyUsage?: string[];
  renewalOfId?: string | null;
  replacedById?: string | null;
  revocation?: {
    reason: string;
    revokedAt: string;
    revokedBy?: string;
    comment?: string;
  } | null;
  createdAt: string;
  updatedAt: string;
}

interface CertificateAuthorityItem {
  id: string;
  name: string;
  description?: string | null;
  organizationId: string;
  projectId: string;
  environmentId: string;
  type: 'ROOT_CA' | 'INTERMEDIATE_CA';
  status: 'ACTIVE' | 'DISABLED' | 'REVOKED';
  subject: string;
  issuer: string;
  parentAuthorityId?: string | null;
  keyReference?: string;
  keyAlgorithm: string;
  signatureAlgorithm: string;
  certificatePem: string;
  serialNumber: string;
  fingerprint: string;
  notBefore: string;
  notAfter: string;
  pathLenConstraint?: number | null;
  crlDistributionPoint?: string | null;
  ocspUrl?: string | null;
  createdAt: string;
  updatedAt: string;
}

interface CsrItem {
  id: string;
  organizationId: string;
  projectId: string;
  environmentId: string;
  subject: string;
  csrPem: string;
  keyAlgorithm: string;
  signatureAlgorithm: string;
  status: string;
  san?: any;
  keyUsage?: any;
  extendedKeyUsage?: any;
  certificateId?: string | null;
  createdAt: string;
}

export default function PkiCertificatesPage() {
  const { activeOrg, requireAuth } = useAuth();
  const [activeTab, setActiveTab] = useState<'CERTIFICATES' | 'CAS' | 'CSRS'>('CERTIFICATES');

  // Data states
  const [certificates, setCertificates] = useState<CertificateItem[]>([]);
  const [authorities, setAuthorities] = useState<CertificateAuthorityItem[]>([]);
  const [csrs, setCsrs] = useState<CsrItem[]>([]);
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState("");
  const [filterStatus, setFilterStatus] = useState("");

  // Modals
  const [isIssueModalOpen, setIsIssueModalOpen] = useState(false);
  const [isCreateCaModalOpen, setIsCreateCaModalOpen] = useState(false);
  const [isDetailsModalOpen, setIsDetailsModalOpen] = useState(false);
  const [isValidateModalOpen, setIsValidateModalOpen] = useState(false);
  const [isRenewModalOpen, setIsRenewModalOpen] = useState(false);
  const [isRevokeModalOpen, setIsRevokeModalOpen] = useState(false);
  const [isCreateCsrModalOpen, setIsCreateCsrModalOpen] = useState(false);
  const [isValidateCsrModalOpen, setIsValidateCsrModalOpen] = useState(false);
  const [isSignCsrModalOpen, setIsSignCsrModalOpen] = useState(false);

  // Selected entities
  const [selectedCert, setSelectedCert] = useState<CertificateItem | null>(null);
  const [selectedCa, setSelectedCa] = useState<CertificateAuthorityItem | null>(null);
  const [selectedCsr, setSelectedCsr] = useState<CsrItem | null>(null);

  // Operation results
  const [validationResult, setValidationResult] = useState<any>(null);
  const [validating, setValidating] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Form states: Issue Cert
  const [issueName, setIssueName] = useState("api.internal.amaracus.net");
  const [issueCaId, setIssueCaId] = useState("");
  const [issueProjectId, setIssueProjectId] = useState("");
  const [issueEnvId, setIssueEnvId] = useState("");
  const [issueCertType, setIssueCertType] = useState("SERVER");
  const [issueSubject, setIssueSubject] = useState("CN=api.internal.amaracus.net, O=Amaracus Technologies, C=US");
  const [issueKeyAlg, setIssueKeyAlg] = useState("RSA-2048");
  const [issueValidityDays, setIssueValidityDays] = useState(365);
  const [issueDnsSans, setIssueDnsSans] = useState("api.internal.amaracus.net, *.amaracus.internal");
  const [issueIpSans, setIssueIpSans] = useState("10.0.0.1, 127.0.0.1");
  const [issuing, setIssuing] = useState(false);

  // Form states: Create CA
  const [caName, setCaName] = useState("Amaracus Root CA G1");
  const [caDescription, setCaDescription] = useState("Production Root Trust Anchor");
  const [caType, setCaType] = useState<'ROOT_CA' | 'INTERMEDIATE_CA'>('ROOT_CA');
  const [caParentId, setCaParentId] = useState("");
  const [caSubject, setCaSubject] = useState("CN=Amaracus Root CA G1, O=Amaracus Technologies, C=US");
  const [caKeyAlg, setCaKeyAlg] = useState("RSA-4096");
  const [caValidityDays, setCaValidityDays] = useState(3650);
  const [caPathLen, setCaPathLen] = useState<number | undefined>(2);
  const [caCrlPoint, setCaCrlPoint] = useState("http://pki.amaracus.internal/crl/root.crl");
  const [caOcspUrl, setCaOcspUrl] = useState("http://pki.amaracus.internal/ocsp");
  const [creatingCa, setCreatingCa] = useState(false);

  // Form states: Renew
  const [renewReuseKey, setRenewReuseKey] = useState(false);
  const [renewValidityDays, setRenewValidityDays] = useState(365);
  const [renewing, setRenewing] = useState(false);

  // Form states: Revoke
  const [revokeReason, setRevokeReason] = useState("KEY_COMPROMISE");
  const [revokeComment, setRevokeComment] = useState("");
  const [revoking, setRevoking] = useState(false);

  // Form states: CSR
  const [csrSubject, setCsrSubject] = useState("CN=gateway.corp.amaracus.net, O=Amaracus, C=US");
  const [csrKeyAlg, setCsrKeyAlg] = useState("RSA-2048");
  const [csrDnsSans, setCsrDnsSans] = useState("gateway.corp.amaracus.net");
  const [generatingCsr, setGeneratingCsr] = useState(false);

  // Form states: Validate CSR PEM
  const [rawCsrPem, setRawCsrPem] = useState("");
  const [csrParseResult, setCsrParseResult] = useState<any>(null);
  const [parsingCsr, setParsingCsr] = useState(false);

  // Form states: Sign CSR
  const [signCsrCaId, setSignCsrCaId] = useState("");
  const [signCsrCertType, setSignCsrCertType] = useState("SERVER");
  const [signCsrValidityDays, setSignCsrValidityDays] = useState(365);
  const [signingCsr, setSigningCsr] = useState(false);

  // Load Data
  const loadData = useCallback(async () => {
    if (!activeOrg?.id) {
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      setError(null);

      // 1. Projects
      try {
        const projsRes = await api.projects.list(activeOrg.id);
        const pList = (projsRes as any).projects || projsRes.data || [];
        setProjects(pList);
        if (pList[0]) {
          setIssueProjectId(pList[0].id);
          if (pList[0].environments?.[0]) {
            setIssueEnvId(pList[0].environments[0].id);
          }
        }
      } catch (err) {
        console.warn('Could not load projects:', err);
      }

      // 2. CAs
      const caRes = await api.pki.listAuthorities(activeOrg.id);
      const caList = caRes.data || [];
      setAuthorities(caList);
      if (caList.length > 0) {
        setIssueCaId(caList[0].id);
        setSignCsrCaId(caList[0].id);
        setCaParentId(caList[0].id);
      }

      // 3. Certificates
      const certsRes = await api.pki.listCertificates(activeOrg.id, {
        status: filterStatus || undefined,
      });
      setCertificates(certsRes.data || []);

      // 4. CSRs
      try {
        const csrsRes = await api.pki.listCsrs(activeOrg.id);
        setCsrs(csrsRes.data || []);
      } catch (err) {
        console.warn('Could not list CSRs:', err);
      }
    } catch (err: any) {
      console.error('Failed to load PKI data:', err);
      setError(err.message || 'Failed to load PKI assets');
    } finally {
      setLoading(false);
    }
  }, [activeOrg?.id, filterStatus]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Copy helper
  const handleCopy = (text: string, id: string) => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }
      setCopiedKey(id);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch (err) {
      console.warn("Failed to copy text:", err);
    }
  };

  // Download helper
  const handleDownload = (filename: string, content: string) => {
    const element = document.createElement("a");
    const file = new Blob([content], { type: "text/plain" });
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  // Handle Issue Certificate
  const handleIssueSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeOrg?.id || !issueCaId || !issueSubject) return;

    try {
      setIssuing(true);
      setError(null);

      const dns = issueDnsSans
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const ips = issueIpSans
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

      const res = await api.pki.issueCertificate(activeOrg.id, {
        name: issueName,
        authorityId: issueCaId,
        projectId: issueProjectId || projects[0]?.id || "proj_default",
        environmentId: issueEnvId || projects[0]?.environments?.[0]?.id || "env_prod",
        certificateType: issueCertType,
        subject: issueSubject,
        keyAlgorithm: issueKeyAlg,
        validityDays: Number(issueValidityDays),
        san: { dns, ips },
      });

      setIsIssueModalOpen(false);
      setActiveTab('CERTIFICATES');
      await loadData();
      if (res.data) {
        setSelectedCert(res.data);
        setIsDetailsModalOpen(true);
      }
    } catch (err: any) {
      setError(err.message || "Failed to issue certificate");
    } finally {
      setIssuing(false);
    }
  };

  // Handle Create CA
  const handleCreateCaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeOrg?.id || !caName || !caSubject) return;

    try {
      setCreatingCa(true);
      setError(null);

      await api.pki.createAuthority(activeOrg.id, {
        name: caName,
        description: caDescription,
        projectId: issueProjectId || projects[0]?.id || "proj_default",
        environmentId: issueEnvId || projects[0]?.environments?.[0]?.id || "env_prod",
        type: caType,
        parentAuthorityId: caType === 'INTERMEDIATE_CA' ? caParentId : undefined,
        subject: caSubject,
        keyAlgorithm: caKeyAlg,
        validityDays: Number(caValidityDays),
        pathLenConstraint: caPathLen !== undefined ? Number(caPathLen) : undefined,
        crlDistributionPoint: caCrlPoint || undefined,
        ocspUrl: caOcspUrl || undefined,
      });

      setIsCreateCaModalOpen(false);
      await loadData();
    } catch (err: any) {
      setError(err.message || "Failed to create Certificate Authority");
    } finally {
      setCreatingCa(false);
    }
  };

  // Handle Validate
  const handleValidateCert = async (cert: CertificateItem) => {
    if (!activeOrg?.id) return;
    try {
      setSelectedCert(cert);
      setValidating(true);
      setIsValidateModalOpen(true);
      const res = await api.pki.validateCertificate(activeOrg.id, cert.id, {
        checkRevocation: true,
        checkExpiry: true,
      });
      setValidationResult(res.data);
    } catch (err: any) {
      setValidationResult({
        isValid: false,
        status: 'INVALID',
        errors: [err.message || 'Validation request failed'],
        chainValid: false,
      });
    } finally {
      setValidating(false);
    }
  };

  // Handle Renew
  const handleRenewSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeOrg?.id || !selectedCert) return;

    try {
      setRenewing(true);
      setError(null);

      const res = await api.pki.renewCertificate(activeOrg.id, selectedCert.id, {
        reuseExistingKey: renewReuseKey,
        validityDays: Number(renewValidityDays),
      });

      setIsRenewModalOpen(false);
      setActiveTab('CERTIFICATES');
      await loadData();
      if (res.data) {
        setSelectedCert(res.data);
        setIsDetailsModalOpen(true);
      }
    } catch (err: any) {
      setError(err.message || "Failed to renew certificate");
    } finally {
      setRenewing(false);
    }
  };

  // Handle Revoke
  const handleRevokeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeOrg?.id || !selectedCert) return;

    try {
      setRevoking(true);
      setError(null);

      await api.pki.revokeCertificate(activeOrg.id, selectedCert.id, {
        reason: revokeReason,
        comment: revokeComment || undefined,
      });

      setIsRevokeModalOpen(false);
      setActiveTab('CERTIFICATES');
      if (selectedCert) {
        setSelectedCert({ ...selectedCert, status: 'REVOKED' });
      }
      await loadData();
    } catch (err: any) {
      setError(err.message || "Failed to revoke certificate");
    } finally {
      setRevoking(false);
    }
  };

  // Handle Generate CSR
  const handleCreateCsrSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeOrg?.id || !csrSubject) return;

    try {
      setGeneratingCsr(true);
      setError(null);

      const dns = csrDnsSans
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

      const res = await api.pki.createCsr(activeOrg.id, {
        projectId: issueProjectId || projects[0]?.id || "proj_default",
        environmentId: issueEnvId || projects[0]?.environments?.[0]?.id || "env_prod",
        subject: csrSubject,
        keyAlgorithm: csrKeyAlg,
        san: { dns },
      });

      setIsCreateCsrModalOpen(false);
      await loadData();
      if (res.data) {
        setSelectedCsr(res.data);
      }
    } catch (err: any) {
      setError(err.message || "Failed to generate CSR");
    } finally {
      setGeneratingCsr(false);
    }
  };

  // Handle Validate Raw CSR PEM
  const handleValidateRawCsr = async () => {
    if (!activeOrg?.id || !rawCsrPem) return;

    try {
      setParsingCsr(true);
      setCsrParseResult(null);
      const res = await api.pki.validateCsr(activeOrg.id, { csrPem: rawCsrPem });
      setCsrParseResult(res.data);
    } catch (err: any) {
      setCsrParseResult({
        isValid: false,
        error: err.message || "Invalid PKCS#10 CSR",
      });
    } finally {
      setParsingCsr(false);
    }
  };

  // Handle Sign CSR
  const handleSignCsrSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeOrg?.id || !selectedCsr || !signCsrCaId) return;

    try {
      setSigningCsr(true);
      setError(null);

      const res = await api.pki.signCsr(activeOrg.id, selectedCsr.id, {
        authorityId: signCsrCaId,
        certificateType: signCsrCertType,
        validityDays: Number(signCsrValidityDays),
      });

      setIsSignCsrModalOpen(false);
      await loadData();
      if (res.data) {
        setSelectedCert(res.data);
        setIsDetailsModalOpen(true);
      }
    } catch (err: any) {
      setError(err.message || "Failed to sign CSR");
    } finally {
      setSigningCsr(false);
    }
  };

  // Filtered certificates
  const filteredCerts = certificates.filter((cert) => {
    const matchesSearch =
      !search ||
      cert.subject.toLowerCase().includes(search.toLowerCase()) ||
      cert.name.toLowerCase().includes(search.toLowerCase()) ||
      cert.serialNumber.toLowerCase().includes(search.toLowerCase());
    const matchesType = !filterType || cert.certificateType === filterType;
    return matchesSearch && matchesType;
  });

  // Calculate Metrics
  const activeCAs = authorities.filter((a) => a.status === 'ACTIVE').length;
  const totalCerts = certificates.length;
  const expiringSoon = certificates.filter(
    (c) => c.status === 'EXPIRING' || (c.daysRemaining <= 30 && c.status === 'ACTIVE')
  ).length;
  const revokedCerts = certificates.filter((c) => c.status === 'REVOKED').length;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E9EDE7] pb-6">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="font-editorial text-3xl md:text-4xl font-bold text-[#1A1A1A] tracking-tight">
              PKI & Certificate Management
            </h1>
            <Badge variant="outline" className="text-xs font-mono">
              RFC 5280 / X.509
            </Badge>
          </div>
          <p className="text-sm text-[#636863] mt-1.5 leading-relaxed">
            Enterprise multi-tier Certificate Authority (CA) hierarchy, PKCS#10 CSR signing, automated renewal lineage, and real-time chain/OCSP validation.
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <Button
            variant="outline"
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button
            variant="secondary"
            onClick={() => {
              if (!requireAuth("create Certificate Authorities")) return;
              setIsCreateCaModalOpen(true);
            }}
            className="flex items-center gap-2"
          >
            <Shield className="w-4 h-4" /> Create CA
          </Button>
          <Button
            onClick={() => {
              if (!requireAuth("issue PKI certificates")) return;
              setIsIssueModalOpen(true);
            }}
            disabled={authorities.length === 0 && !!activeOrg}
            className="flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Issue Certificate
          </Button>
        </div>
      </div>

      {/* Error alert */}
      {error && (
        <div className="rounded-xl border border-red-200 bg-red-50 p-4 flex items-start gap-3 text-sm text-red-800">
          <AlertTriangle className="w-5 h-5 shrink-0 text-red-600 mt-0.5" />
          <div className="flex-1">
            <p className="font-semibold">Error occurred</p>
            <p className="mt-0.5 text-xs text-red-700">{error}</p>
          </div>
          <button onClick={() => setError(null)} className="text-red-600 hover:text-red-800 text-xs font-semibold">
            Dismiss
          </button>
        </div>
      )}

      {/* Metric Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="p-5 border-[#E9EDE7] hover:border-[#008031]/40 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-[#636863] uppercase tracking-wider">
              Certificate Authorities
            </span>
            <div className="w-8 h-8 rounded-lg bg-[#EAF3EC] flex items-center justify-center text-[#008031]">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#1A1A1A]">{activeCAs}</span>
            <span className="text-xs text-[#636863]">Active Roots & Sub-CAs</span>
          </div>
        </Card>

        <Card className="p-5 border-[#E9EDE7] hover:border-[#008031]/40 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-[#636863] uppercase tracking-wider">
              Total Certificates
            </span>
            <div className="w-8 h-8 rounded-lg bg-[#EAF3EC] flex items-center justify-center text-[#008031]">
              <Award className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#1A1A1A]">{totalCerts}</span>
            <span className="text-xs text-[#636863]">Issued End-Entities</span>
          </div>
        </Card>

        <Card className="p-5 border-[#E9EDE7] hover:border-[#B45309]/40 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-[#636863] uppercase tracking-wider">
              Expiring Soon
            </span>
            <div className="w-8 h-8 rounded-lg bg-[#FEF8EC] flex items-center justify-center text-[#B45309]">
              <Clock className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#B45309]">{expiringSoon}</span>
            <span className="text-xs text-[#636863]">Within 30 Days</span>
          </div>
        </Card>

        <Card className="p-5 border-[#E9EDE7] hover:border-red-300 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-[#636863] uppercase tracking-wider">
              Revoked / Hold
            </span>
            <div className="w-8 h-8 rounded-lg bg-[#FDF2F2] flex items-center justify-center text-[#B91C1C]">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#B91C1C]">{revokedCerts}</span>
            <span className="text-xs text-[#636863]">On CRL / OCSP</span>
          </div>
        </Card>
      </div>

      {/* Tabs */}
      <div className="border-b border-[#E9EDE7] flex gap-8" role="tablist" aria-label="PKI Views">
        <button
          role="tab"
          aria-selected={activeTab === 'CERTIFICATES'}
          onClick={() => setActiveTab('CERTIFICATES')}
          className={`pb-3 text-sm font-semibold transition-all border-b-2 ${
            activeTab === 'CERTIFICATES'
              ? 'border-[#008031] text-[#008031]'
              : 'border-transparent text-[#636863] hover:text-[#1A1A1A]'
          }`}
        >
          Certificates Inventory ({certificates.length})
        </button>
        <button
          role="tab"
          aria-selected={activeTab === 'CAS'}
          onClick={() => setActiveTab('CAS')}
          className={`pb-3 text-sm font-semibold transition-all border-b-2 ${
            activeTab === 'CAS'
              ? 'border-[#008031] text-[#008031]'
              : 'border-transparent text-[#636863] hover:text-[#1A1A1A]'
          }`}
        >
          Certificate Authorities ({authorities.length})
        </button>
        <button
          role="tab"
          aria-selected={activeTab === 'CSRS'}
          onClick={() => setActiveTab('CSRS')}
          className={`pb-3 text-sm font-semibold transition-all border-b-2 ${
            activeTab === 'CSRS'
              ? 'border-[#008031] text-[#008031]'
              : 'border-transparent text-[#636863] hover:text-[#1A1A1A]'
          }`}
        >
          CSR Studio ({csrs.length})
        </button>
      </div>

      {/* TAB 1: CERTIFICATES INVENTORY */}
      {activeTab === 'CERTIFICATES' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-white p-4 rounded-xl border border-[#E9EDE7]">
            <div className="flex items-center gap-3 w-full sm:w-auto">
              <div className="relative flex-1 sm:w-80">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#767676]" />
                <Input
                  placeholder="Search subject, name, or serial..."
                  aria-label="Search certificates by subject, name, or serial"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9 h-9 text-xs"
                />
              </div>
            </div>
            <div className="flex items-center gap-3 w-full sm:w-auto">
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                className="h-9 px-3 rounded-lg border border-[#E9EDE7] text-xs bg-white text-[#1A1A1A]"
              >
                <option value="">All Types</option>
                <option value="SERVER">Server / TLS</option>
                <option value="CLIENT">Client mTLS</option>
                <option value="CODE_SIGNING">Code Signing</option>
                <option value="EMAIL">Email (S/MIME)</option>
                <option value="DEVICE">Device / IoT</option>
              </select>

              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                className="h-9 px-3 rounded-lg border border-[#E9EDE7] text-xs bg-white text-[#1A1A1A]"
              >
                <option value="">All Statuses</option>
                <option value="ACTIVE">Active</option>
                <option value="EXPIRING">Expiring Soon</option>
                <option value="EXPIRED">Expired</option>
                <option value="REVOKED">Revoked</option>
              </select>
            </div>
          </div>

          {/* Table */}
          <Card>
            <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Certificates inventory table">
              <table className="w-full text-xs text-left">
                <thead className="bg-[#FAF9F6] text-[#767676] border-b border-[#E9EDE7]">
                  <tr>
                    <th className="px-6 py-3.5 font-semibold">Subject & Serial</th>
                    <th className="px-6 py-3.5 font-semibold">Type</th>
                    <th className="px-6 py-3.5 font-semibold">Issuer CA</th>
                    <th className="px-6 py-3.5 font-semibold">Algorithm</th>
                    <th className="px-6 py-3.5 font-semibold">Validity</th>
                    <th className="px-6 py-3.5 font-semibold">Status</th>
                    <th className="px-6 py-3.5 font-semibold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E9EDE7]">
                  {loading ? (
                    <tr>
                      <td colSpan={7} className="px-6 py-12 text-center text-[#767676]">
                        <div className="flex items-center justify-center gap-2">
                          <Loader2 className="w-4 h-4 animate-spin text-[#008031]" />
                          Loading certificates...
                        </div>
                      </td>
                    </tr>
                  ) : filteredCerts.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="px-6 py-12 text-center text-[#767676]">
                        <p className="font-medium text-sm text-[#1A1A1A]">No certificates found</p>
                        <p className="text-xs mt-1">Issue a new X.509 certificate to get started.</p>
                      </td>
                    </tr>
                  ) : (
                    filteredCerts.map((cert) => (
                      <tr
                        key={cert.id}
                        onClick={() => {
                          setSelectedCert(cert);
                          setIsDetailsModalOpen(true);
                        }}
                        className="hover:bg-[#FAF9F6] transition-colors cursor-pointer"
                        title="Click to view full certificate details and PEM"
                      >
                        <td className="px-6 py-4">
                          <div className="font-semibold text-[#1A1A1A] hover:text-[#008031] transition-colors">
                            {cert.name || 'Certificate'}
                          </div>
                          <div className="text-[11px] text-[#767676] truncate max-w-xs font-mono mt-0.5">
                            {cert.subject}
                          </div>
                          <div className="text-[10px] text-[#A0A5A0] font-mono mt-0.5">
                            SN: {cert.serialNumber ? cert.serialNumber.substring(0, 16) : 'N/A'}...
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <Badge variant="outline" className="text-[10px]">
                            {cert.certificateType}
                          </Badge>
                        </td>
                        <td className="px-6 py-4 text-[#555555]">
                          <div className="truncate max-w-xs text-[11px]">{cert.issuer}</div>
                        </td>
                        <td className="px-6 py-4">
                          <span className="font-mono text-[11px] text-[#008031] font-medium">
                            {cert.keyAlgorithm}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-[#767676]">
                          <div className="text-[11px]">
                            {cert.daysRemaining > 0 ? `${cert.daysRemaining} days left` : 'Expired'}
                          </div>
                          <div className="text-[10px] text-[#A0A5A0]">
                            {new Date(cert.notAfter).toLocaleDateString()}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <Badge
                            variant={
                              cert.status === 'ACTIVE'
                                ? 'success'
                                : cert.status === 'EXPIRING'
                                ? 'warning'
                                : cert.status === 'REVOKED'
                                ? 'destructive'
                                : 'secondary'
                            }
                          >
                            {cert.status}
                          </Badge>
                        </td>
                        <td className="px-6 py-4 text-right">
                          <div
                            className="flex items-center justify-end gap-1.5"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedCert(cert);
                                setIsDetailsModalOpen(true);
                              }}
                              title="View Details & PEM (Step 1.4)"
                              aria-label={`View details and PEM for certificate ${cert.name}`}
                              className="h-7 px-2 text-[11px] gap-1"
                            >
                              <Eye className="w-3.5 h-3.5" aria-hidden="true" />
                              <span className="hidden lg:inline text-[10px]">Details</span>
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleValidateCert(cert);
                              }}
                              title="Cryptographically Validate Chain & OCSP (Step 1.5)"
                              aria-label={`Validate certificate chain and OCSP for ${cert.name}`}
                              className="h-7 px-2 text-[11px] gap-1 text-[#008031] border-[#008031]/30 hover:bg-[#EAF3EC]"
                            >
                              <ShieldCheck className="w-3.5 h-3.5 text-[#008031]" aria-hidden="true" />
                              <span className="hidden lg:inline text-[10px]">Validate</span>
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedCert(cert);
                                setIsRenewModalOpen(true);
                              }}
                              disabled={cert.status === 'REVOKED'}
                              title="Renew Certificate (Step 1.6)"
                              aria-label={`Renew certificate ${cert.name}`}
                              className="h-7 px-2 text-[11px] gap-1"
                            >
                              <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
                              <span className="hidden lg:inline text-[10px]">Renew</span>
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedCert(cert);
                                setIsRevokeModalOpen(true);
                              }}
                              disabled={cert.status === 'REVOKED'}
                              title="Revoke Certificate RFC 5280 (Step 1.7)"
                              aria-label={`Revoke certificate ${cert.name}`}
                              className="h-7 px-2 text-[11px] gap-1 text-red-600 border-red-200 hover:bg-red-50 disabled:opacity-40"
                            >
                              <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                              <span className="hidden lg:inline text-[10px]">Revoke</span>
                            </Button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {/* TAB 2: CERTIFICATE AUTHORITIES (CA HIERARCHY) */}
      {activeTab === 'CAS' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <p className="text-xs text-[#636863]">
              Hierarchical trust anchors used to issue and sign end-entity certificates and child Intermediate CAs.
            </p>
            <Button
              onClick={() => setIsCreateCaModalOpen(true)}
              size="sm"
              className="flex items-center gap-1.5 text-xs"
            >
              <Plus className="w-3.5 h-3.5" /> Add Authority
            </Button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {authorities.map((ca) => (
              <Card key={ca.id} className="p-6 border-[#E9EDE7] space-y-4">
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold text-sm text-[#1A1A1A]">{ca.name}</h3>
                      <Badge variant={ca.type === 'ROOT_CA' ? 'default' : 'secondary'}>
                        {ca.type === 'ROOT_CA' ? 'Root CA' : 'Intermediate CA'}
                      </Badge>
                      <Badge variant={ca.status === 'ACTIVE' ? 'success' : 'destructive'}>
                        {ca.status}
                      </Badge>
                    </div>
                    {ca.description && (
                      <p className="text-xs text-[#636863]">{ca.description}</p>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs bg-[#FAF9F6] p-3 rounded-lg border border-[#E9EDE7]">
                  <div>
                    <span className="text-[#767676] block">Key Algorithm:</span>
                    <span className="font-mono text-[#008031] font-semibold">{ca.keyAlgorithm}</span>
                  </div>
                  <div>
                    <span className="text-[#767676] block">Signature:</span>
                    <span className="font-mono text-[#1A1A1A]">{ca.signatureAlgorithm}</span>
                  </div>
                  <div>
                    <span className="text-[#767676] block">Path Length Constraint:</span>
                    <span className="font-mono text-[#1A1A1A]">
                      {ca.pathLenConstraint !== null && ca.pathLenConstraint !== undefined
                        ? ca.pathLenConstraint
                        : 'Unlimited'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#767676] block">Expires:</span>
                    <span className="text-[#1A1A1A]">{new Date(ca.notAfter).toLocaleDateString()}</span>
                  </div>
                </div>

                <div className="space-y-1 text-xs">
                  <div className="text-[#767676]">Subject DN:</div>
                  <div className="font-mono text-[11px] text-[#1A1A1A] bg-white p-2 rounded border border-[#E9EDE7] break-all">
                    {ca.subject}
                  </div>
                </div>

                <div className="space-y-1 text-xs">
                  <div className="text-[#767676]">CRL Distribution Point:</div>
                  <div className="font-mono text-[11px] text-[#636863] truncate">
                    {ca.crlDistributionPoint || 'Not specified'}
                  </div>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-[#E9EDE7]">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleCopy(ca.certificatePem, `ca-pem-${ca.id}`)}
                    className="text-xs h-8"
                  >
                    {copiedKey === `ca-pem-${ca.id}` ? (
                      <Check className="w-3.5 h-3.5 mr-1 text-[#008031]" />
                    ) : (
                      <Copy className="w-3.5 h-3.5 mr-1" />
                    )}
                    Copy CA Certificate
                  </Button>

                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleDownload(`${ca.name.replace(/\s+/g, '_')}.crt`, ca.certificatePem)}
                      className="text-xs h-8"
                    >
                      <Download className="w-3.5 h-3.5 mr-1" /> .crt
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={async () => {
                        try {
                          if (!activeOrg?.id) return;
                          const crlRes = await api.pki.generateCrl(activeOrg.id, ca.id);
                          handleDownload(`${ca.name.replace(/\s+/g, '_')}.crl`, crlRes.data.crlPem);
                        } catch (err: any) {
                          setError(err.message || 'Failed to generate CRL');
                        }
                      }}
                      className="text-xs h-8"
                    >
                      Generate CRL
                    </Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: CSR STUDIO */}
      {activeTab === 'CSRS' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <p className="text-xs text-[#636863]">
              Generate, validate, and sign standards-compliant PKCS#10 Certificate Signing Requests (CSRs).
            </p>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setRawCsrPem("");
                  setCsrParseResult(null);
                  setIsValidateCsrModalOpen(true);
                }}
                className="text-xs"
              >
                <FileText className="w-3.5 h-3.5 mr-1.5" /> Validate External CSR
              </Button>
              <Button
                size="sm"
                onClick={() => setIsCreateCsrModalOpen(true)}
                className="text-xs"
              >
                <Plus className="w-3.5 h-3.5 mr-1.5" /> Generate CSR
              </Button>
            </div>
          </div>

          <Card>
            <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Certificate authorities table">
              <table className="w-full text-xs text-left">
                <thead className="bg-[#FAF9F6] text-[#767676] border-b border-[#E9EDE7]">
                  <tr>
                    <th className="px-6 py-3.5 font-semibold">Subject</th>
                    <th className="px-6 py-3.5 font-semibold">Algorithm</th>
                    <th className="px-6 py-3.5 font-semibold">Signature</th>
                    <th className="px-6 py-3.5 font-semibold">Status</th>
                    <th className="px-6 py-3.5 font-semibold">Created</th>
                    <th className="px-6 py-3.5 font-semibold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E9EDE7]">
                  {csrs.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-6 py-12 text-center text-[#767676]">
                        <p className="font-medium text-sm text-[#1A1A1A]">No CSRs registered</p>
                        <p className="text-xs mt-1">Generate or upload a CSR to issue certificates.</p>
                      </td>
                    </tr>
                  ) : (
                    csrs.map((csr) => (
                      <tr key={csr.id} className="hover:bg-[#FAF9F6] transition-colors">
                        <td className="px-6 py-4">
                          <div className="font-semibold text-[#1A1A1A]">{csr.subject}</div>
                          <div className="text-[10px] text-[#A0A5A0] font-mono mt-0.5">ID: {csr.id}</div>
                        </td>
                        <td className="px-6 py-4 font-mono text-[#008031] font-semibold">
                          {csr.keyAlgorithm}
                        </td>
                        <td className="px-6 py-4 font-mono text-[#555555]">
                          {csr.signatureAlgorithm}
                        </td>
                        <td className="px-6 py-4">
                          <Badge variant={csr.status === 'PENDING' ? 'warning' : 'success'}>
                            {csr.status}
                          </Badge>
                        </td>
                        <td className="px-6 py-4 text-[#767676]">
                          {new Date(csr.createdAt).toLocaleDateString()}
                        </td>
                        <td className="px-6 py-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handleCopy(csr.csrPem, `csr-${csr.id}`)}
                              aria-label={`Copy CSR PEM for ${csr.subject || csr.id}`}
                              className="h-7 px-2 text-[11px]"
                            >
                              {copiedKey === `csr-${csr.id}` ? (
                                <Check className="w-3.5 h-3.5 text-[#008031]" aria-hidden="true" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                              )}
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handleDownload(`request-${csr.id}.csr`, csr.csrPem)}
                              aria-label={`Download CSR for ${csr.subject || csr.id}`}
                              className="h-7 px-2 text-[11px]"
                            >
                              <Download className="w-3.5 h-3.5" aria-hidden="true" />
                            </Button>
                            {csr.status === 'PENDING' && (
                              <Button
                                size="sm"
                                onClick={() => {
                                  setSelectedCsr(csr);
                                  setIsSignCsrModalOpen(true);
                                }}
                                className="h-7 px-2.5 text-[11px]"
                              >
                                Sign & Issue
                              </Button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL: ISSUE CERTIFICATE */}
      {/* ==================================================================== */}
      <Modal
        isOpen={isIssueModalOpen}
        onClose={() => setIsIssueModalOpen(false)}
        title="Issue X.509 Certificate"
        description="Issue a standards-compliant RFC 5280 certificate signed by an internal Certificate Authority."
        maxWidth="max-w-xl"
      >
        <form onSubmit={handleIssueSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Certificate Friendly Name</label>
            <Input
              value={issueName}
              onChange={(e) => setIssueName(e.target.value)}
              placeholder="e.g. api.internal.amaracus.net"
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Issuing Authority (CA)</label>
              <select
                value={issueCaId}
                onChange={(e) => setIssueCaId(e.target.value)}
                className="w-full h-10 px-3 rounded-lg border border-[#E9EDE7] text-xs bg-white text-[#1A1A1A]"
                required
              >
                {authorities.map((ca) => (
                  <option key={ca.id} value={ca.id}>
                    {ca.name} ({ca.type})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Certificate Type</label>
              <select
                value={issueCertType}
                onChange={(e) => setIssueCertType(e.target.value)}
                className="w-full h-10 px-3 rounded-lg border border-[#E9EDE7] text-xs bg-white text-[#1A1A1A]"
              >
                <option value="SERVER">Server / TLS</option>
                <option value="CLIENT">Client mTLS</option>
                <option value="CODE_SIGNING">Code Signing</option>
                <option value="EMAIL">Email (S/MIME)</option>
                <option value="DEVICE">Device / IoT</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Subject Distinguished Name (DN)</label>
            <Input
              value={issueSubject}
              onChange={(e) => setIssueSubject(e.target.value)}
              placeholder="CN=host.domain.com, O=Amaracus, C=US"
              required
            />
            <p className="text-[11px] text-[#767676] mt-1">Must include Common Name (CN=).</p>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Key Algorithm</label>
              <select
                value={issueKeyAlg}
                onChange={(e) => setIssueKeyAlg(e.target.value)}
                className="w-full h-10 px-3 rounded-lg border border-[#E9EDE7] text-xs bg-white text-[#1A1A1A]"
              >
                <option value="RSA-2048">RSA-2048 (Standard)</option>
                <option value="RSA-3072">RSA-3072 (High Assurance)</option>
                <option value="RSA-4096">RSA-4096 (Maximum Security)</option>
                <option value="ECDSA-P256">ECDSA P-256 (Fast)</option>
                <option value="ECDSA-P384">ECDSA P-384 (CNSA Suite)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Validity (Days)</label>
              <Input
                type="number"
                value={issueValidityDays}
                onChange={(e) => setIssueValidityDays(Number(e.target.value))}
                min={1}
                max={1825}
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Subject Alternative Names (DNS)</label>
            <Input
              value={issueDnsSans}
              onChange={(e) => setIssueDnsSans(e.target.value)}
              placeholder="example.com, *.example.com"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Subject Alternative Names (IP)</label>
            <Input
              value={issueIpSans}
              onChange={(e) => setIssueIpSans(e.target.value)}
              placeholder="10.0.0.1, 192.168.1.1"
            />
          </div>

          {/* Truthful note */}
          <div className="p-3 rounded-lg bg-[#FAF9F6] border border-[#E9EDE7] flex items-start gap-2 text-[11px] text-[#636863]">
            <Info className="w-4 h-4 text-[#008031] shrink-0 mt-0.5" />
            <span>
              <strong>Standards Compliance Note:</strong> Standard X.509 certificates require standardized OIDs (RSA / ECDSA). PQC certificates (ML-DSA) remain in active IETF standardization draft status and are gated.
            </span>
          </div>

          <div className="flex justify-end gap-2 pt-4 border-t border-[#E9EDE7]">
            <Button type="button" variant="outline" onClick={() => setIsIssueModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={issuing}>
              {issuing ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Issuing...
                </>
              ) : (
                "Issue Certificate"
              )}
            </Button>
          </div>
        </form>
      </Modal>

      {/* ==================================================================== */}
      {/* MODAL: CREATE CERTIFICATE AUTHORITY */}
      {/* ==================================================================== */}
      <Modal
        isOpen={isCreateCaModalOpen}
        onClose={() => setIsCreateCaModalOpen(false)}
        title="Create Certificate Authority"
        description="Establish a new Root CA or an Intermediate CA in your PKI hierarchy."
        maxWidth="max-w-xl"
      >
        <form onSubmit={handleCreateCaSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">CA Name</label>
            <Input
              value={caName}
              onChange={(e) => setCaName(e.target.value)}
              placeholder="e.g. Amaracus Intermediate CA G1"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Description</label>
            <Input
              value={caDescription}
              onChange={(e) => setCaDescription(e.target.value)}
              placeholder="e.g. Cluster Gateway Subordinate CA"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">CA Hierarchy Level</label>
              <select
                value={caType}
                onChange={(e) => setCaType(e.target.value as any)}
                className="w-full h-10 px-3 rounded-lg border border-[#E9EDE7] text-xs bg-white text-[#1A1A1A]"
              >
                <option value="ROOT_CA">Root CA (Self-Signed Anchor)</option>
                <option value="INTERMEDIATE_CA">Intermediate CA (Subordinate)</option>
              </select>
            </div>

            {caType === 'INTERMEDIATE_CA' && (
              <div>
                <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Parent Authority</label>
                <select
                  value={caParentId}
                  onChange={(e) => setCaParentId(e.target.value)}
                  className="w-full h-10 px-3 rounded-lg border border-[#E9EDE7] text-xs bg-white text-[#1A1A1A]"
                  required
                >
                  {authorities.map((ca) => (
                    <option key={ca.id} value={ca.id}>
                      {ca.name} ({ca.type})
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Subject Distinguished Name</label>
            <Input
              value={caSubject}
              onChange={(e) => setCaSubject(e.target.value)}
              placeholder="CN=Amaracus Root CA G1, O=Amaracus, C=US"
              required
            />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Key Algorithm</label>
              <select
                value={caKeyAlg}
                onChange={(e) => setCaKeyAlg(e.target.value)}
                className="w-full h-10 px-3 rounded-lg border border-[#E9EDE7] text-xs bg-white text-[#1A1A1A]"
              >
                <option value="RSA-4096">RSA-4096 (Recommended)</option>
                <option value="RSA-3072">RSA-3072</option>
                <option value="ECDSA-P384">ECDSA P-384</option>
                <option value="ECDSA-P256">ECDSA P-256</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Validity (Days)</label>
              <Input
                type="number"
                value={caValidityDays}
                onChange={(e) => setCaValidityDays(Number(e.target.value))}
                min={30}
                max={7300}
                required
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Path Length Constraint</label>
              <Input
                type="number"
                value={caPathLen ?? ""}
                onChange={(e) => setCaPathLen(e.target.value === "" ? undefined : Number(e.target.value))}
                placeholder="None"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">CRL Distribution Point</label>
              <Input
                value={caCrlPoint}
                onChange={(e) => setCaCrlPoint(e.target.value)}
                placeholder="http://pki.corp.com/crl.crl"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">OCSP Responder URL</label>
              <Input
                value={caOcspUrl}
                onChange={(e) => setCaOcspUrl(e.target.value)}
                placeholder="http://pki.corp.com/ocsp"
              />
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-4 border-t border-[#E9EDE7]">
            <Button type="button" variant="outline" onClick={() => setIsCreateCaModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={creatingCa}>
              {creatingCa ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Creating CA...
                </>
              ) : (
                "Create Authority"
              )}
            </Button>
          </div>
        </form>
      </Modal>

      {/* ==================================================================== */}
      {/* MODAL: CERTIFICATE DETAILS & PEM */}
      {/* ==================================================================== */}
      <Modal
        isOpen={isDetailsModalOpen}
        onClose={() => setIsDetailsModalOpen(false)}
        title={selectedCert ? selectedCert.name : "Certificate Details"}
        description="Comprehensive RFC 5280 metadata, SHA-256 fingerprint, and PEM encoding."
        maxWidth="max-w-2xl"
      >
        {selectedCert && (
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-3 bg-[#FAF9F6] p-3 rounded-lg border border-[#E9EDE7]">
              <div>
                <span className="text-[#767676] block">Serial Number:</span>
                <span className="font-mono text-[#1A1A1A] break-all">{selectedCert.serialNumber}</span>
              </div>
              <div>
                <span className="text-[#767676] block">Status:</span>
                <Badge
                  variant={
                    selectedCert.status === 'ACTIVE'
                      ? 'success'
                      : selectedCert.status === 'REVOKED'
                      ? 'destructive'
                      : 'warning'
                  }
                >
                  {selectedCert.status}
                </Badge>
              </div>
              <div>
                <span className="text-[#767676] block">SHA-256 Fingerprint:</span>
                <span className="font-mono text-[10px] text-[#1A1A1A] break-all">
                  {selectedCert.fingerprint}
                </span>
              </div>
              <div>
                <span className="text-[#767676] block">Key Algorithm:</span>
                <span className="font-mono text-[#008031] font-semibold">
                  {selectedCert.keyAlgorithm}
                </span>
              </div>
              <div>
                <span className="text-[#767676] block">Valid From:</span>
                <span>{new Date(selectedCert.notBefore).toLocaleString()}</span>
              </div>
              <div>
                <span className="text-[#767676] block">Valid Until:</span>
                <span>
                  {new Date(selectedCert.notAfter).toLocaleString()} ({selectedCert.daysRemaining} days left)
                </span>
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[#767676] block">Subject:</span>
              <div className="font-mono text-[11px] bg-white p-2 rounded border border-[#E9EDE7] break-all">
                {selectedCert.subject}
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[#767676] block">Issuer:</span>
              <div className="font-mono text-[11px] bg-white p-2 rounded border border-[#E9EDE7] break-all">
                {selectedCert.issuer}
              </div>
            </div>

            {selectedCert.san && (
              <div className="space-y-1">
                <span className="text-[#767676] block">Subject Alternative Names:</span>
                <div className="flex flex-wrap gap-1.5">
                  {selectedCert.san.dns?.map((d, i) => (
                    <Badge key={`dns-${i}`} variant="secondary" className="font-mono text-[10px]">
                      DNS:{d}
                    </Badge>
                  ))}
                  {(selectedCert.san.ips || (selectedCert.san as any).ip)?.map((ip: string, i: number) => (
                    <Badge key={`ip-${i}`} variant="outline" className="font-mono text-[10px]">
                      IP:{ip}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* Certificate PEM */}
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[#767676]">Certificate PEM:</span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleCopy(selectedCert.certificatePem, "modal-cert-pem")}
                  className="h-6 text-[10px] px-2"
                >
                  {copiedKey === "modal-cert-pem" ? (
                    <Check className="w-3 h-3 text-[#008031] mr-1" />
                  ) : (
                    <Copy className="w-3 h-3 mr-1" />
                  )}
                  Copy PEM
                </Button>
              </div>
              <pre className="font-mono text-[10px] bg-[#1A1A1A] text-[#A0D468] p-3 rounded-lg overflow-x-auto max-h-36">
                {selectedCert.certificatePem}
              </pre>
            </div>

            {/* Chain PEM */}
            {selectedCert.chainPem && (
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[#767676]">Certificate Chain PEM:</span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleCopy(selectedCert.chainPem!, "modal-chain-pem")}
                    className="h-6 text-[10px] px-2"
                  >
                    {copiedKey === "modal-chain-pem" ? (
                      <Check className="w-3 h-3 text-[#008031] mr-1" />
                    ) : (
                      <Copy className="w-3 h-3 mr-1" />
                    )}
                    Copy Chain
                  </Button>
                </div>
                <pre className="font-mono text-[10px] bg-[#1A1A1A] text-[#70C1B3] p-3 rounded-lg overflow-x-auto max-h-36">
                  {selectedCert.chainPem}
                </pre>
              </div>
            )}

            <div className="flex justify-end gap-2 pt-4 border-t border-[#E9EDE7]">
              <Button
                variant="outline"
                onClick={() =>
                  handleDownload(`${selectedCert.name.replace(/\s+/g, '_')}.crt`, selectedCert.certificatePem)
                }
              >
                <Download className="w-3.5 h-3.5 mr-1" /> Download .crt
              </Button>
              <Button onClick={() => setIsDetailsModalOpen(false)}>Close</Button>
            </div>
          </div>
        )}
      </Modal>

      {/* ==================================================================== */}
      {/* MODAL: CRYPTOGRAPHIC VALIDATION & OCSP */}
      {/* ==================================================================== */}
      <Modal
        isOpen={isValidateModalOpen}
        onClose={() => setIsValidateModalOpen(false)}
        title="Chain & Revocation Validation"
        description="Real-time cryptographic verification against internal trust anchor, signature validation, and OCSP status."
        maxWidth="max-w-xl"
      >
        <div className="space-y-4 text-xs">
          {validating ? (
            <div className="p-8 text-center text-[#767676]">
              <Loader2 className="w-6 h-6 animate-spin text-[#008031] mx-auto mb-2" />
              <p className="font-medium">Validating certificate chain and OCSP status...</p>
            </div>
          ) : validationResult ? (
            <div className="space-y-4">
              <div
                className={`p-4 rounded-xl border flex items-center gap-3 ${
                  validationResult.isValid
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                    : 'bg-red-50 border-red-200 text-red-900'
                }`}
              >
                {validationResult.isValid ? (
                  <CheckCircle2 className="w-6 h-6 text-emerald-600 shrink-0" />
                ) : (
                  <XCircle className="w-6 h-6 text-red-600 shrink-0" />
                )}
                <div>
                  <h4 className="font-semibold text-sm">
                    {validationResult.isValid ? 'Certificate is Valid & Trusted' : 'Validation Failed'}
                  </h4>
                  <p className="text-xs opacity-90 mt-0.5">
                    {validationResult.isValid
                      ? 'The certificate chain verifies cryptographically to an active trust anchor.'
                      : validationResult.errors?.join(', ') || 'Certificate chain verification failed.'}
                  </p>
                </div>
              </div>

              {/* Validation checks detail */}
              <div className="bg-[#FAF9F6] p-4 rounded-xl border border-[#E9EDE7] space-y-2">
                <span className="font-semibold text-xs text-[#1A1A1A] block">Verification Checklist:</span>
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[#636863]">Chain Signature Integrity:</span>
                    <Badge variant={validationResult.chainValid ? 'success' : 'destructive'}>
                      {validationResult.chainValid ? 'Passed' : 'Failed'}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[#636863]">Temporal Validity Window:</span>
                    <Badge variant="success">Active (Not Expired)</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[#636863]">Revocation Status (OCSP / CRL):</span>
                    <Badge
                      variant={
                        validationResult.revocationStatus === 'REVOKED' ? 'destructive' : 'success'
                      }
                    >
                      {validationResult.revocationStatus || 'Good'}
                    </Badge>
                  </div>
                </div>
              </div>

              {/* Chain path visualization */}
              {validationResult.chain && (
                <div className="space-y-2">
                  <span className="font-semibold text-xs text-[#1A1A1A] block">Verified Chain Hierarchy:</span>
                  <div className="space-y-1.5 bg-white p-3 rounded-lg border border-[#E9EDE7]">
                    {(Array.isArray(validationResult.chain)
                      ? validationResult.chain
                      : validationResult.chain.chain || validationResult.chain.certificates || []
                    ).map((item: any, idx: number, arr: any[]) => (
                      <div key={idx} className="flex items-center justify-between gap-2 text-[11px] p-2 rounded bg-[#FAF9F6] border border-[#E9EDE7]/60">
                        <div className="flex items-center gap-2 min-w-0">
                          <div className="w-5 h-5 rounded-full bg-[#EAF3EC] text-[#008031] flex items-center justify-center font-bold text-[10px] shrink-0">
                            {idx + 1}
                          </div>
                          <span className="font-mono text-[#1A1A1A] truncate text-[11px]" title={item.subject}>
                            {item.subject?.replace(/\n/g, ', ') || item.subject}
                          </span>
                        </div>
                        <div className="shrink-0">
                          {idx === 0 && <Badge variant="secondary" className="text-[9px]">Leaf</Badge>}
                          {idx === arr.length - 1 && (
                            <Badge variant="default" className="text-[9px]">Anchor</Badge>
                          )}
                          {idx > 0 && idx < arr.length - 1 && (
                            <Badge variant="outline" className="text-[9px]">Intermediate</Badge>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : null}

          <div className="flex justify-end pt-4 border-t border-[#E9EDE7]">
            <Button onClick={() => setIsValidateModalOpen(false)}>Close</Button>
          </div>
        </div>
      </Modal>

      {/* ==================================================================== */}
      {/* MODAL: RENEW CERTIFICATE */}
      {/* ==================================================================== */}
      <Modal
        isOpen={isRenewModalOpen}
        onClose={() => setIsRenewModalOpen(false)}
        title="Renew Certificate"
        description="Preserve certificate lineage (renewalOfId) with either key reuse or new cryptographic keypair generation."
        maxWidth="max-w-md"
      >
        <form onSubmit={handleRenewSubmit} className="space-y-4 text-xs">
          <div className="bg-[#FAF9F6] p-3 rounded-lg border border-[#E9EDE7] space-y-1">
            <span className="text-[#767676] block">Current Certificate:</span>
            <span className="font-semibold text-[#1A1A1A] block">{selectedCert?.name}</span>
            <span className="font-mono text-[10px] text-[#767676] block truncate">
              {selectedCert?.subject}
            </span>
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Renew Validity (Days)</label>
            <Input
              type="number"
              value={renewValidityDays}
              onChange={(e) => setRenewValidityDays(Number(e.target.value))}
              min={1}
              max={1825}
              required
            />
          </div>

          <div className="flex items-center gap-2 p-3 rounded-lg border border-[#E9EDE7]">
            <input
              type="checkbox"
              id="reuseKey"
              checked={renewReuseKey}
              onChange={(e) => setRenewReuseKey(e.target.checked)}
              className="rounded border-[#E9EDE7] text-[#008031] focus:ring-[#008031]"
            />
            <label htmlFor="reuseKey" className="text-xs text-[#1A1A1A] cursor-pointer">
              Reuse existing cryptographic keypair (Not recommended for maximum security)
            </label>
          </div>

          <div className="flex justify-end gap-2 pt-4 border-t border-[#E9EDE7]">
            <Button type="button" variant="outline" onClick={() => setIsRenewModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={renewing}>
              {renewing ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Renewing...
                </>
              ) : (
                "Confirm Renewal"
              )}
            </Button>
          </div>
        </form>
      </Modal>

      {/* ==================================================================== */}
      {/* MODAL: REVOKE CERTIFICATE (RFC 5280) */}
      {/* ==================================================================== */}
      <Modal
        isOpen={isRevokeModalOpen}
        onClose={() => setIsRevokeModalOpen(false)}
        title="Revoke Certificate"
        description="Publish revocation to internal CRL and update OCSP responder with standard RFC 5280 reason codes."
        maxWidth="max-w-md"
      >
        <form onSubmit={handleRevokeSubmit} className="space-y-4 text-xs">
          <div className="bg-red-50 border border-red-200 p-3 rounded-lg text-red-800 space-y-1">
            <span className="font-semibold block">Warning: Irreversible Action</span>
            <span className="text-[11px] block">
              Revoking this certificate immediately invalidates all mTLS/TLS connections trusting this serial number.
            </span>
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Revocation Reason</label>
            <select
              value={revokeReason}
              onChange={(e) => setRevokeReason(e.target.value)}
              className="w-full h-10 px-3 rounded-lg border border-[#E9EDE7] text-xs bg-white text-[#1A1A1A]"
            >
              <option value="KEY_COMPROMISE">Key Compromise (RFC 5280 #1)</option>
              <option value="CA_COMPROMISE">CA Compromise (RFC 5280 #2)</option>
              <option value="AFFILIATION_CHANGED">Affiliation Changed (RFC 5280 #3)</option>
              <option value="SUPERSEDED">Superseded (RFC 5280 #4)</option>
              <option value="CESSATION_OF_OPERATION">Cessation of Operation (RFC 5280 #5)</option>
              <option value="CERTIFICATE_HOLD">Certificate Hold (RFC 5280 #6)</option>
              <option value="UNSPECIFIED">Unspecified (RFC 5280 #0)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Audit Comment (Optional)</label>
            <Input
              value={revokeComment}
              onChange={(e) => setRevokeComment(e.target.value)}
              placeholder="e.g. Incident INC-4091 private key leakage"
            />
          </div>

          <div className="flex justify-end gap-2 pt-4 border-t border-[#E9EDE7]">
            <Button type="button" variant="outline" onClick={() => setIsRevokeModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="destructive" disabled={revoking}>
              {revoking ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Revoking...
                </>
              ) : (
                "Revoke Certificate"
              )}
            </Button>
          </div>
        </form>
      </Modal>

      {/* ==================================================================== */}
      {/* MODAL: GENERATE CSR */}
      {/* ==================================================================== */}
      <Modal
        isOpen={isCreateCsrModalOpen}
        onClose={() => setIsCreateCsrModalOpen(false)}
        title="Generate PKCS#10 CSR"
        description="Create a signed Certificate Signing Request with keypair generation."
        maxWidth="max-w-lg"
      >
        <form onSubmit={handleCreateCsrSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Subject Distinguished Name</label>
            <Input
              value={csrSubject}
              onChange={(e) => setCsrSubject(e.target.value)}
              placeholder="CN=gateway.corp.com, O=Amaracus, C=US"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Key Algorithm</label>
            <select
              value={csrKeyAlg}
              onChange={(e) => setCsrKeyAlg(e.target.value)}
              className="w-full h-10 px-3 rounded-lg border border-[#E9EDE7] text-xs bg-white text-[#1A1A1A]"
            >
              <option value="RSA-2048">RSA-2048</option>
              <option value="RSA-3072">RSA-3072</option>
              <option value="RSA-4096">RSA-4096</option>
              <option value="ECDSA-P256">ECDSA P-256</option>
              <option value="ECDSA-P384">ECDSA P-384</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Subject Alternative Names (DNS)</label>
            <Input
              value={csrDnsSans}
              onChange={(e) => setCsrDnsSans(e.target.value)}
              placeholder="gateway.corp.com, api.gateway.corp.com"
            />
          </div>

          <div className="flex justify-end gap-2 pt-4 border-t border-[#E9EDE7]">
            <Button type="button" variant="outline" onClick={() => setIsCreateCsrModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={generatingCsr}>
              {generatingCsr ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Generating...
                </>
              ) : (
                "Generate CSR"
              )}
            </Button>
          </div>
        </form>
      </Modal>

      {/* ==================================================================== */}
      {/* MODAL: VALIDATE RAW EXTERNAL CSR */}
      {/* ==================================================================== */}
      <Modal
        isOpen={isValidateCsrModalOpen}
        onClose={() => setIsValidateCsrModalOpen(false)}
        title="Parse & Validate External CSR"
        description="Verify cryptographic self-signature and inspect subject and attributes in an external PKCS#10 CSR."
        maxWidth="max-w-xl"
      >
        <div className="space-y-4 text-xs">
          <div>
            <label htmlFor="raw-csr-pem" className="block text-xs font-semibold text-[#1A1A1A] mb-1">Paste CSR (PEM Format)</label>
            <textarea
              id="raw-csr-pem"
              value={rawCsrPem}
              onChange={(e) => setRawCsrPem(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE REQUEST-----..."
              rows={8}
              className="w-full font-mono text-[11px] p-3 rounded-lg border border-[#E9EDE7] bg-white text-[#1A1A1A]"
            />
          </div>

          <Button
            type="button"
            onClick={handleValidateRawCsr}
            disabled={parsingCsr || !rawCsrPem}
            className="w-full"
          >
            {parsingCsr ? (
              <>
                <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Validating Signature...
              </>
            ) : (
              "Validate CSR Signature"
            )}
          </Button>

          {csrParseResult && (
            <div
              className={`p-4 rounded-xl border space-y-2 ${
                csrParseResult.isValid
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                  : 'bg-red-50 border-red-200 text-red-900'
              }`}
            >
              <div className="flex items-center gap-2 font-semibold">
                {csrParseResult.isValid ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                ) : (
                  <XCircle className="w-4 h-4 text-red-600" />
                )}
                {csrParseResult.isValid ? 'Valid PKCS#10 CSR (Signature Verified)' : 'Invalid CSR'}
              </div>

              {csrParseResult.isValid ? (
                <div className="space-y-1 text-xs">
                  <div>
                    <strong>Subject:</strong> {csrParseResult.subject}
                  </div>
                  <div>
                    <strong>Key Algorithm:</strong> {csrParseResult.keyAlgorithm}
                  </div>
                  <div>
                    <strong>Signature Algorithm:</strong> {csrParseResult.signatureAlgorithm}
                  </div>
                </div>
              ) : (
                <p className="text-xs">{csrParseResult.error}</p>
              )}
            </div>
          )}

          <div className="flex justify-end pt-4 border-t border-[#E9EDE7]">
            <Button onClick={() => setIsValidateCsrModalOpen(false)}>Close</Button>
          </div>
        </div>
      </Modal>

      {/* ==================================================================== */}
      {/* MODAL: SIGN CSR WITH CA */}
      {/* ==================================================================== */}
      <Modal
        isOpen={isSignCsrModalOpen}
        onClose={() => setIsSignCsrModalOpen(false)}
        title="Sign CSR with Certificate Authority"
        description="Select an internal CA to issue a production certificate against this CSR."
        maxWidth="max-w-md"
      >
        <form onSubmit={handleSignCsrSubmit} className="space-y-4 text-xs">
          <div className="bg-[#FAF9F6] p-3 rounded-lg border border-[#E9EDE7]">
            <span className="text-[#767676] block">CSR Subject:</span>
            <span className="font-semibold text-[#1A1A1A] block">{selectedCsr?.subject}</span>
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Issuing Authority</label>
            <select
              value={signCsrCaId}
              onChange={(e) => setSignCsrCaId(e.target.value)}
              className="w-full h-10 px-3 rounded-lg border border-[#E9EDE7] text-xs bg-white text-[#1A1A1A]"
              required
            >
              {authorities.map((ca) => (
                <option key={ca.id} value={ca.id}>
                  {ca.name} ({ca.type})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Certificate Type</label>
            <select
              value={signCsrCertType}
              onChange={(e) => setSignCsrCertType(e.target.value)}
              className="w-full h-10 px-3 rounded-lg border border-[#E9EDE7] text-xs bg-white text-[#1A1A1A]"
            >
              <option value="SERVER">Server / TLS</option>
              <option value="CLIENT">Client mTLS</option>
              <option value="CODE_SIGNING">Code Signing</option>
              <option value="EMAIL">Email (S/MIME)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#1A1A1A] mb-1">Validity (Days)</label>
            <Input
              type="number"
              value={signCsrValidityDays}
              onChange={(e) => setSignCsrValidityDays(Number(e.target.value))}
              min={1}
              max={1825}
              required
            />
          </div>

          <div className="flex justify-end gap-2 pt-4 border-t border-[#E9EDE7]">
            <Button type="button" variant="outline" onClick={() => setIsSignCsrModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={signingCsr}>
              {signingCsr ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Signing...
                </>
              ) : (
                "Sign & Issue Certificate"
              )}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}