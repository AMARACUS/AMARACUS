"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Modal } from "@/components/ui/modal";
import {
  Cpu,
  Shield,
  Zap,
  Lock,
  RefreshCw,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Layers,
  FileCode,
  Users,
  Key,
  Binary,
  ArrowRight,
  Info,
  Check,
  Copy,
  Sliders,
  Play
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api-client";
import { PreviewBanner } from "@/components/preview-banner";

type TabKey = "zk" | "fhe" | "mpc" | "threshold" | "providers";

export default function AdvancedCryptoPage() {
  const { activeOrg, requireAuth } = useAuth();
  const [activeTab, setActiveTab] = useState<TabKey>("zk");
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // --- ZK State ---
  const [circuits, setCircuits] = useState<any[]>([]);
  const [selectedCircuit, setSelectedCircuit] = useState<any | null>(null);
  const [zkStatementCommitment, setZkStatementCommitment] = useState("");
  const [zkWitnessSecret, setZkWitnessSecret] = useState("");
  const [generatedProof, setGeneratedProof] = useState<any | null>(null);
  const [zkVerificationResult, setZkVerificationResult] = useState<any | null>(null);
  const [zkProverError, setZkProverError] = useState<string | null>(null);
  const [registerCircuitOpen, setRegisterCircuitOpen] = useState(false);
  const [newCircuit, setNewCircuit] = useState({
    id: `circ_${Date.now()}`,
    name: "Commitment Preimage Verification",
    version: "1.0.0",
    description: "Fiat-Shamir transformed NIZK Schnorr/Pedersen over Ed25519",
    provingSystem: "NIZK_SCHNORR_PEDERSEN",
    constraintsDescription: "C == x * G",
  });

  // --- FHE State ---
  const [fheLimits, setFheLimits] = useState<any | null>(null);
  const [fheKeys, setFheKeys] = useState<any[]>([]);
  const [activeFheKeyId, setActiveFheKeyId] = useState<string>("");
  const [fhePlaintextA, setFhePlaintextA] = useState<number>(15);
  const [fhePlaintextB, setFhePlaintextB] = useState<number>(25);
  const [cipherA, setCipherA] = useState<string>("");
  const [cipherB, setCipherB] = useState<string>("");
  const [fheOperation, setFheOperation] = useState<string>("ADD");
  const [evalResultCipher, setEvalResultCipher] = useState<string>("");
  const [decryptedFheValue, setDecryptedFheValue] = useState<number | null>(null);
  const [fheEvaluationMeta, setFheEvaluationMeta] = useState<any | null>(null);

  // --- MPC State ---
  const [mpcSessions, setMpcSessions] = useState<any[]>([]);
  const [activeMpcSession, setActiveMpcSession] = useState<any | null>(null);
  const [newMpcTitle, setNewMpcTitle] = useState("Private Multi-Party Salary Aggregation");
  const [newMpcParties, setNewMpcParties] = useState(2);
  const [partyInputValues, setPartyInputValues] = useState<{ [partyId: string]: number }>({
    "party-alice": 100,
    "party-bob": 250,
  });
  const [mpcResult, setMpcResult] = useState<any | null>(null);

  // --- Threshold State ---
  const [thresholdKeys, setThresholdKeys] = useState<any[]>([]);
  const [activeThresholdKey, setActiveThresholdKey] = useState<any | null>(null);
  const [newThreshName, setNewThreshName] = useState("Treasury M-of-N Key");
  const [newThreshM, setNewThreshM] = useState(3);
  const [newThreshN, setNewThreshN] = useState(5);
  const [activeThresholdSession, setActiveThresholdSession] = useState<any | null>(null);
  const [thresholdMessage, setThresholdMessage] = useState("Authorize Fund Transfer: $1,000,000 to Cold Vault");

  // --- Providers State ---
  const [providers, setProviders] = useState<any[]>([]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  useEffect(() => {
    if (success) {
      const timer = setTimeout(() => setSuccess(null), 6000);
      return () => clearTimeout(timer);
    }
  }, [success]);

  const loadData = useCallback(async () => {
    if (!activeOrg?.id) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      // Load Providers
      const provRes = await api.advanced.getProviders(activeOrg.id).catch(() => ({ data: [] }));
      setProviders(provRes.data || []);

      // Load ZK Circuits
      const zkRes = await api.advanced.listCircuits(activeOrg.id).catch(() => ({ data: [] }));
      setCircuits(zkRes.data || []);
      if (zkRes.data?.length > 0 && !selectedCircuit) {
        setSelectedCircuit(zkRes.data[0]);
      }

      // Load FHE Limits & Keys
      const limitsRes = await api.advanced.getLimits(activeOrg.id).catch(() => ({ data: null }));
      setFheLimits(limitsRes.data);
      const keysRes = await api.advanced.listFheKeys(activeOrg.id).catch(() => ({ data: [] }));
      setFheKeys(keysRes.data || []);
      if (keysRes.data?.length > 0 && !activeFheKeyId) {
        setActiveFheKeyId(keysRes.data[0].id);
      }

      // Load MPC Sessions
      const mpcRes = await api.advanced.listMpcSessions(activeOrg.id).catch(() => ({ data: [] }));
      setMpcSessions(mpcRes.data || []);
      if (mpcRes.data?.length > 0 && !activeMpcSession) {
        setActiveMpcSession(mpcRes.data[0]);
      }

      // Load Threshold Keys
      const threshRes = await api.advanced.listThresholdKeys(activeOrg.id).catch(() => ({ data: [] }));
      setThresholdKeys(threshRes.data || []);
      if (threshRes.data?.length > 0 && !activeThresholdKey) {
        setActiveThresholdKey(threshRes.data[0]);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load advanced cryptographic data");
    } finally {
      setLoading(false);
    }
  }, [activeOrg?.id, selectedCircuit, activeFheKeyId, activeMpcSession, activeThresholdKey]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // =========================================================================
  // ZK Handlers
  // =========================================================================
  const handleRegisterCircuit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeOrg?.id) return;
    setActionLoading(true);
    setError(null);
    try {
      const res = await api.advanced.createCircuit(activeOrg.id, newCircuit);
      setSuccess(`Circuit '${res.data.name}' registered successfully`);
      setRegisterCircuitOpen(false);
      await loadData();
    } catch (err: any) {
      setError(err.message || "Failed to register ZK circuit");
    } finally {
      setActionLoading(false);
    }
  };

  const handleGenerateZkProof = async () => {
    if (!activeOrg?.id || !selectedCircuit) return;
    if (!zkStatementCommitment || !zkWitnessSecret) {
      const msg = "Please provide both statement public commitment and private witness secret";
      setError(msg);
      setZkProverError(msg);
      return;
    }
    setActionLoading(true);
    setError(null);
    setZkProverError(null);
    setGeneratedProof(null);
    setZkVerificationResult(null);
    try {
      const res = await api.advanced.prove(activeOrg.id, {
        circuitId: selectedCircuit.id,
        version: selectedCircuit.version,
        statement: {
          circuitId: selectedCircuit.id,
          version: selectedCircuit.version,
          publicInputs: { commitment: zkStatementCommitment.trim() },
        },
        witness: {
          circuitId: selectedCircuit.id,
          privateInputs: { secretValue: zkWitnessSecret.trim() },
        },
      });
      setGeneratedProof(res.data);
      setSuccess("Zero-Knowledge proof generated successfully (Witness remained confidential)");
    } catch (err: any) {
      setGeneratedProof(null);
      setZkVerificationResult(null);
      const msg = err.message || "Proof generation failed";
      setError(msg);
      setZkProverError(msg);
    } finally {
      setActionLoading(false);
    }
  };

  const handleVerifyZkProof = async () => {
    if (!activeOrg?.id || !selectedCircuit || !generatedProof) return;
    setActionLoading(true);
    setError(null);
    try {
      const res = await api.advanced.verify(activeOrg.id, {
        circuitId: selectedCircuit.id,
        version: selectedCircuit.version,
        statement: {
          circuitId: selectedCircuit.id,
          version: selectedCircuit.version,
          publicInputs: generatedProof.publicInputs,
        },
        proof: generatedProof,
      });
      setZkVerificationResult(res.data);
      if (res.data.valid) {
        setSuccess(`Proof verified as VALID in ${res.data.durationMs}ms`);
      } else {
        setError(`Proof rejected: ${res.data.error || "Verification failed"}`);
      }
    } catch (err: any) {
      setError(err.message || "Verification failed");
    } finally {
      setActionLoading(false);
    }
  };

  // =========================================================================
  // FHE Handlers
  // =========================================================================
  const handleGenerateFheKey = async () => {
    if (!activeOrg?.id) return;
    setActionLoading(true);
    setError(null);
    try {
      const res = await api.advanced.generateFheKey(activeOrg.id, {
        scheme: "BFV",
        polyModulusDegree: 4096,
      });
      setActiveFheKeyId(res.data.id);
      setSuccess(`Generated Microsoft SEAL BFV keypair (${res.data.id})`);
      await loadData();
    } catch (err: any) {
      setError(err.message || "Failed to generate FHE key");
    } finally {
      setActionLoading(false);
    }
  };

  const handleEncryptFheValues = async () => {
    if (!activeOrg?.id || !activeFheKeyId) {
      setError("Please generate or select an FHE key first");
      return;
    }
    setActionLoading(true);
    setError(null);
    try {
      const resA = await api.advanced.encryptFhe(activeOrg.id, {
        keyId: activeFheKeyId,
        value: Number(fhePlaintextA),
      });
      setCipherA(resA.data.ciphertextBase64);

      const resB = await api.advanced.encryptFhe(activeOrg.id, {
        keyId: activeFheKeyId,
        value: Number(fhePlaintextB),
      });
      setCipherB(resB.data.ciphertextBase64);

      setSuccess(`Encrypted integers ${fhePlaintextA} and ${fhePlaintextB} into real SEAL BFV ciphertexts`);
    } catch (err: any) {
      setError(err.message || "FHE encryption failed");
    } finally {
      setActionLoading(false);
    }
  };

  const handleEvaluateFhe = async () => {
    if (!activeOrg?.id || !activeFheKeyId || !cipherA || !cipherB) {
      setError("Please encrypt inputs A and B first");
      return;
    }
    setActionLoading(true);
    setError(null);
    setDecryptedFheValue(null);
    try {
      const res = await api.advanced.evaluateFhe(activeOrg.id, {
        keyId: activeFheKeyId,
        operation: fheOperation,
        ciphertexts: [cipherA, cipherB],
      });
      setEvalResultCipher(res.data.resultCiphertextBase64);
      setFheEvaluationMeta(res.data);
      setSuccess(`Homomorphic ${fheOperation} evaluated directly on ciphertexts in ${res.data.durationMs}ms`);
    } catch (err: any) {
      setError(err.message || "Homomorphic evaluation failed");
    } finally {
      setActionLoading(false);
    }
  };

  const handleDecryptFheResult = async () => {
    if (!activeOrg?.id || !activeFheKeyId || !evalResultCipher) {
      setError("No evaluated ciphertext available for decryption");
      return;
    }
    setActionLoading(true);
    setError(null);
    try {
      const res = await api.advanced.decryptFhe(activeOrg.id, {
        keyId: activeFheKeyId,
        ciphertextBase64: evalResultCipher,
      });
      setDecryptedFheValue(res.data.value);
      setSuccess(`Decrypted homomorphic result: ${res.data.value}`);
    } catch (err: any) {
      setError(err.message || "FHE decryption failed");
    } finally {
      setActionLoading(false);
    }
  };

  // =========================================================================
  // MPC Handlers
  // =========================================================================
  const handleCreateMpcSession = async () => {
    if (!activeOrg?.id) return;
    setActionLoading(true);
    setError(null);
    try {
      const res = await api.advanced.createMpcSession(activeOrg.id, {
        title: newMpcTitle,
        operation: "SECURE_SUM",
        requiredParties: Number(newMpcParties),
        threshold: Number(newMpcParties),
      });
      setActiveMpcSession(res.data);
      setMpcResult(null);
      setSuccess(`MPC session '${res.data.title}' created (${res.data.id})`);
      await loadData();
    } catch (err: any) {
      setError(err.message || "Failed to create MPC session");
    } finally {
      setActionLoading(false);
    }
  };

  const handleSimulateMpcFlow = async () => {
    if (!activeOrg?.id || !activeMpcSession) return;
    setActionLoading(true);
    setError(null);
    try {
      // 1. Join Party Alice & Bob
      await api.advanced.joinMpcSession(activeOrg.id, activeMpcSession.id, {
        partyId: "party-alice",
        name: "Alice Corp",
        role: "INPUT_PARTY",
      });
      await api.advanced.joinMpcSession(activeOrg.id, activeMpcSession.id, {
        partyId: "party-bob",
        name: "Bob Inc",
        role: "INPUT_PARTY",
      });

      // 2. Submit blinded inputs
      await api.advanced.submitMpcInput(activeOrg.id, activeMpcSession.id, {
        partyId: "party-alice",
        input: partyInputValues["party-alice"] || 100,
      });
      await api.advanced.submitMpcInput(activeOrg.id, activeMpcSession.id, {
        partyId: "party-bob",
        input: partyInputValues["party-bob"] || 250,
      });

      // 3. Execute Round
      const execRes = await api.advanced.executeMpcRound(activeOrg.id, activeMpcSession.id);
      setActiveMpcSession(execRes.data);
      setMpcResult(execRes.data.result);
      setSuccess(`MPC secure aggregation complete! Computed Sum: ${execRes.data.result.computedValue}`);
    } catch (err: any) {
      setError(err.message || "MPC execution failed");
    } finally {
      setActionLoading(false);
    }
  };

  // =========================================================================
  // Threshold Handlers
  // =========================================================================
  const handleCreateThresholdKey = async () => {
    if (!activeOrg?.id) return;
    setActionLoading(true);
    setError(null);
    try {
      const res = await api.advanced.createThresholdKey(activeOrg.id, {
        name: newThreshName,
        threshold: Number(newThreshM),
        totalParticipants: Number(newThreshN),
      });
      setActiveThresholdKey(res.data);
      setSuccess(`Generated ${res.data.threshold}-of-${res.data.totalParticipants} Threshold Key`);
      await loadData();
    } catch (err: any) {
      setError(err.message || "Failed to create threshold key");
    } finally {
      setActionLoading(false);
    }
  };

  const handleCreateThresholdSession = async () => {
    if (!activeOrg?.id || !activeThresholdKey) return;
    setActionLoading(true);
    setError(null);
    try {
      const res = await api.advanced.createThresholdSession(activeOrg.id, {
        keyId: activeThresholdKey.id,
        operation: "THRESHOLD_SIGN",
        messageToSign: thresholdMessage,
      });
      setActiveThresholdSession(res.data);
      setSuccess(`Created threshold signing session for: "${thresholdMessage}"`);
    } catch (err: any) {
      setError(err.message || "Failed to create threshold session");
    } finally {
      setActionLoading(false);
    }
  };

  const handleApproveThresholdSession = async (participantId: string) => {
    if (!activeOrg?.id || !activeThresholdSession) return;
    setActionLoading(true);
    setError(null);
    try {
      const res = await api.advanced.approveThresholdSession(activeOrg.id, activeThresholdSession.id, {
        participantId,
      });
      setActiveThresholdSession(res.data);
      setSuccess(`Participant '${participantId}' approved session. Total: ${res.data.approvals.length}/${res.data.threshold}`);
    } catch (err: any) {
      setError(err.message || "Approval submission failed");
    } finally {
      setActionLoading(false);
    }
  };

  const handleExecuteThresholdSession = async () => {
    if (!activeOrg?.id || !activeThresholdSession) return;
    setActionLoading(true);
    setError(null);
    try {
      const res = await api.advanced.executeThresholdSession(activeOrg.id, activeThresholdSession.id);
      setActiveThresholdSession(res.data);
      setSuccess("Threshold signature successfully computed without key reassembly!");
    } catch (err: any) {
      setError(err.message || "Threshold execution failed");
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="space-y-6 pb-12 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#E9EDE7] pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-50 text-amber-800 border border-amber-200 uppercase tracking-wider">
              Preview
            </span>
          </div>
          <h1 className="font-editorial text-2xl md:text-3xl font-bold tracking-tight text-[#1A1A1A] mt-1">
            Advanced Cryptography
          </h1>
          <p className="text-xs md:text-sm text-[#767676] mt-0.5">
            Experimental Zero-Knowledge Proofs (Schnorr/Pedersen), FHE (Microsoft SEAL), additive MPC and threshold signing.
          </p>
          <div className="mt-3">
            <PreviewBanner>
              Zero-knowledge proofs support Schnorr/Pedersen statements only (no Groth16 or PLONK). FHE
              keys are generated and held by the AMARACUS server, so data is not hidden from us. MPC and
              threshold signing run inside one server process and have not been independently audited.
            </PreviewBanner>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Button
            variant="outline"
            size="sm"
            onClick={loadData}
            disabled={loading}
            className="text-xs gap-1.5 border-[#E9EDE7] bg-white hover:bg-[#F8F7F4]"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh Telemetry
          </Button>
        </div>
      </div>

      {/* Floating Toast Notifications */}
      {error && (
        <div className="fixed top-5 right-5 z-50 max-w-md p-4 rounded-xl shadow-2xl bg-red-50/95 backdrop-blur-md border border-red-200 text-red-900 text-xs flex items-start gap-3 animate-in fade-in slide-in-from-top-3">
          <AlertTriangle className="w-4 h-4 shrink-0 text-red-600 mt-0.5" aria-hidden="true" />
          <div className="flex-1 leading-relaxed font-medium">{error}</div>
          <button 
            onClick={() => setError(null)} 
            aria-label="Dismiss error notification"
            className="text-red-500 hover:text-red-800 text-base leading-none font-bold"
          >
            <span aria-hidden="true">×</span>
          </button>
        </div>
      )}

      {success && (
        <div className="fixed top-5 right-5 z-50 max-w-md p-4 rounded-xl shadow-2xl bg-[#EAF3EC]/95 backdrop-blur-md border border-[#C8E0CF] text-[#008031] text-xs flex items-start gap-3 animate-in fade-in slide-in-from-top-3">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-[#008031] mt-0.5" aria-hidden="true" />
          <div className="flex-1 leading-relaxed font-medium">{success}</div>
          <button 
            onClick={() => setSuccess(null)} 
            aria-label="Dismiss success notification"
            className="text-[#008031] hover:text-[#005a22] text-base leading-none font-bold"
          >
            <span aria-hidden="true">×</span>
          </button>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex items-center gap-1 border-b border-[#E9EDE7] overflow-x-auto pb-px" role="tablist" aria-label="Advanced Cryptography Modules">
        {[
          { key: "zk", label: "Zero-Knowledge Proofs", icon: <Shield className="w-3.5 h-3.5" /> },
          { key: "fhe", label: "Fully Homomorphic Encryption", icon: <Cpu className="w-3.5 h-3.5" /> },
          { key: "mpc", label: "Multi-Party Computation", icon: <Users className="w-3.5 h-3.5" /> },
          { key: "threshold", label: "Threshold Cryptography", icon: <Key className="w-3.5 h-3.5" /> },
          { key: "providers", label: "Provider Capabilities", icon: <Layers className="w-3.5 h-3.5" /> },
        ].map((tab) => {
          const isActive = activeTab === tab.key;
          return (
            <button
              key={tab.key}
              role="tab"
              aria-selected={isActive}
              onClick={() => {
                setActiveTab(tab.key as TabKey);
                setError(null);
                setSuccess(null);
              }}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 whitespace-nowrap ${
                isActive
                  ? "border-[#008031] text-[#008031] bg-white"
                  : "border-transparent text-[#767676] hover:text-[#1A1A1A] hover:bg-white/50"
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* ===================================================================== */}
      {/* TAB 1: ZERO-KNOWLEDGE PROOFS */}
      {/* ===================================================================== */}
      {activeTab === "zk" && (
        <div className="space-y-6">
          {/* Summary Banner */}
          <div className="p-4 rounded-xl border border-[#C8E0CF] bg-[#FAFDFB] flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-[#008031]" />
                <h3 className="text-sm font-bold text-[#1A1A1A]">Non-Interactive Zero-Knowledge (NIZK) Engine</h3>
                <Badge variant="outline" className="text-[10px] bg-[#EAF3EC] text-[#008031] border-[#C8E0CF]">
                  Fiat-Shamir Transformed
                </Badge>
              </div>
              <p className="text-xs text-[#767676]">
                Prove knowledge of secret values satisfying public commitments without leaking witnesses. Strict circuit versioning and constraint isolation.
              </p>
            </div>
            <Button
              onClick={() => setRegisterCircuitOpen(true)}
              size="sm"
              className="bg-[#008031] hover:bg-[#006e2a] text-white text-xs gap-1.5 shrink-0"
            >
              Register Circuit
            </Button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left Col: Circuit Registry */}
            <Card className="border-[#E9EDE7] shadow-xs bg-white">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-[#1A1A1A]">Registered Circuits</CardTitle>
                <CardDescription className="text-xs text-[#767676]">
                  Active arithmetic constraint systems
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {circuits.length === 0 ? (
                  <div className="p-6 text-center text-xs text-[#767676] border border-dashed rounded-lg">
                    No circuits registered yet.
                  </div>
                ) : (
                  circuits.map((circ) => {
                    const isSelected = selectedCircuit?.id === circ.id;
                    return (
                      <div
                        key={`${circ.id}:${circ.version}`}
                        onClick={() => setSelectedCircuit(circ)}
                        role="button"
                        tabIndex={0}
                        aria-pressed={isSelected}
                        aria-label={`Select circuit ${circ.name}`}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            setSelectedCircuit(circ);
                          }
                        }}
                        className={`p-3 rounded-xl border cursor-pointer transition-all text-xs ${
                          isSelected
                            ? "border-[#008031] bg-[#FAFDFB] ring-1 ring-[#008031]"
                            : "border-[#E9EDE7] hover:border-[#D1D5DB]"
                        }`}
                      >
                        <div className="flex items-center justify-between font-semibold text-[#1A1A1A]">
                          <span className="truncate">{circ.name}</span>
                          <span className="font-mono text-[10px] text-[#767676]">v{circ.version}</span>
                        </div>
                        <div className="text-[11px] font-mono text-[#008031] mt-0.5 truncate">{circ.id}</div>
                        <div className="text-[11px] text-[#767676] mt-1 line-clamp-2">{circ.description}</div>
                        <div className="mt-2 flex items-center gap-1.5">
                          <span className="px-1.5 py-0.5 rounded text-[9px] bg-slate-100 text-slate-700 font-mono">
                            {circ.provingSystem}
                          </span>
                        </div>
                      </div>
                    );
                  })
                )}
              </CardContent>
            </Card>

            {/* Middle & Right Col: Prover & Verifier Studios */}
            <div className="lg:col-span-2 space-y-6">
              {/* Prover Studio */}
              <Card className="border-[#E9EDE7] shadow-xs bg-white">
                <CardHeader className="pb-3 border-b border-[#F0F2EE]">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-sm font-semibold text-[#1A1A1A]">Interactive Prover Studio</CardTitle>
                      <CardDescription className="text-xs text-[#767676]">
                        Generate non-interactive ZK proof without exposing secret witness
                      </CardDescription>
                    </div>
                    {selectedCircuit && (
                      <Badge variant="outline" className="font-mono text-[10px] text-[#008031] bg-[#EAF3EC]">
                        {selectedCircuit.id}:v{selectedCircuit.version}
                      </Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent className="space-y-4 pt-4">
                  <div className="p-3 rounded-lg bg-amber-50/70 border border-amber-200 text-amber-900 text-xs flex items-start gap-2">
                    <Info className="w-4 h-4 shrink-0 text-amber-600 mt-0.5" />
                    <div>
                      <span className="font-semibold">Zero-Knowledge Confidentiality Principle:</span> The private witness is processed locally. Only cryptographic points and Fiat-Shamir scalars are published.
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold text-[#1A1A1A]">Public Commitment (Statement)</label>
                      <Input
                        value={zkStatementCommitment}
                        onChange={(e) => setZkStatementCommitment(e.target.value)}
                        placeholder="e.g. ce1a32994e835c193e2bf339..."
                        className="font-mono text-xs"
                      />
                      <p className="text-[10px] text-[#767676]">Publicly visible curve point or hash commitment</p>
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold text-[#1A1A1A]">Private Witness (Secret Scalar)</label>
                      <Input
                        type="password"
                        value={zkWitnessSecret}
                        onChange={(e) => setZkWitnessSecret(e.target.value)}
                        placeholder="e.g. 42"
                        className="font-mono text-xs"
                      />
                      <p className="text-[10px] text-[#767676]">Private secret known only to the prover</p>
                    </div>
                  </div>

                  <div className="flex items-center justify-end gap-2 pt-2">
                    <Button
                      onClick={handleGenerateZkProof}
                      disabled={actionLoading || !zkStatementCommitment || !zkWitnessSecret}
                      size="sm"
                      className="bg-[#008031] hover:bg-[#006e2a] text-white text-xs gap-1.5"
                    >
                      {actionLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                      Generate ZK Proof
                    </Button>
                  </div>

                  {/* Inline Error Alert if proof generation rejected */}
                  {zkProverError && (
                    <div className="mt-3 p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-900 text-xs flex items-start justify-between animate-in fade-in">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 shrink-0 text-red-600 mt-0.5" />
                        <div>
                          <div className="font-bold text-red-800">Proof Generation Rejected</div>
                          <div className="text-[11px] text-red-700 mt-0.5">{zkProverError}</div>
                        </div>
                      </div>
                      <button 
                        onClick={() => setZkProverError(null)} 
                        aria-label="Dismiss proof generation error"
                        className="text-red-500 hover:text-red-800 text-sm font-bold ml-2"
                      >
                        <span aria-hidden="true">×</span>
                      </button>
                    </div>
                  )}

                  {/* Proof Artifact Output */}
                  {generatedProof && (
                    <div className="mt-4 p-3.5 rounded-xl bg-slate-900 text-slate-200 space-y-2 border border-slate-800 animate-in fade-in">
                      <div className="flex items-center justify-between text-xs font-semibold text-slate-300">
                        <span className="flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          Non-Interactive ZK Proof Generated
                        </span>
                        <button
                          onClick={() => copyToClipboard(JSON.stringify(generatedProof, null, 2), "proof")}
                          className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-white"
                        >
                          {copiedId === "proof" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          Copy JSON
                        </button>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[11px] font-mono pt-1">
                        <div>
                          <span className="text-slate-500">Commitment Point A:</span>
                          <div className="truncate text-emerald-400">{generatedProof.proofData?.commitmentPointA}</div>
                        </div>
                        <div>
                          <span className="text-slate-500">Response Scalar S:</span>
                          <div className="truncate text-emerald-400">{generatedProof.proofData?.responseScalarS}</div>
                        </div>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Verifier Studio */}
              <Card className="border-[#E9EDE7] shadow-xs bg-white">
                <CardHeader className="pb-3 border-b border-[#F0F2EE]">
                  <CardTitle className="text-sm font-semibold text-[#1A1A1A]">Verifier Validator Studio</CardTitle>
                  <CardDescription className="text-xs text-[#767676]">
                    Verify proof authenticity against public statement and circuit constraint version
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4 pt-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-[#767676]">
                      Proof Status: {generatedProof ? "Loaded from Prover Studio" : "No active proof generated"}
                    </span>
                    <Button
                      onClick={handleVerifyZkProof}
                      disabled={actionLoading || !generatedProof}
                      size="sm"
                      variant="outline"
                      className="border-[#008031] text-[#008031] hover:bg-[#EAF3EC] text-xs gap-1.5"
                    >
                      {actionLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                      Verify Proof Authenticity
                    </Button>
                  </div>

                  {zkVerificationResult && (
                    <div
                      className={`p-3 rounded-xl border text-xs flex items-center justify-between ${
                        zkVerificationResult.valid
                          ? "bg-emerald-50 border-emerald-200 text-emerald-800"
                          : "bg-red-50 border-red-200 text-red-800"
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        {zkVerificationResult.valid ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-600 shrink-0" />
                        )}
                        <div>
                          <div className="font-bold">
                            {zkVerificationResult.valid ? "VALID PROOF" : "INVALID PROOF"}
                          </div>
                          <div className="text-[11px] opacity-80">
                            {zkVerificationResult.valid
                              ? `Statement satisfied in ${zkVerificationResult.durationMs}ms without revealing witness`
                              : zkVerificationResult.error || "Proof does not satisfy constraint equation"}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* TAB 2: FULLY HOMOMORPHIC ENCRYPTION */}
      {/* ===================================================================== */}
      {activeTab === "fhe" && (
        <div className="space-y-6">
          {/* SEAL BFV Banner */}
          <div className="p-4 rounded-xl border border-blue-200 bg-blue-50/40 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-blue-700" />
                <h3 className="text-sm font-bold text-[#1A1A1A]">Microsoft SEAL BFV Engine</h3>
                <Badge variant="outline" className="text-[10px] bg-blue-100/80 text-blue-800 border-blue-300">
                  Exact Integer Homomorphic
                </Badge>
              </div>
              <p className="text-xs text-[#767676]">
                Performs additions, subtractions, multiplications, and negations directly on ciphertexts without server-side decryption.
              </p>
            </div>
            <Button
              onClick={handleGenerateFheKey}
              disabled={actionLoading}
              size="sm"
              className="bg-blue-600 hover:bg-blue-700 text-white text-xs gap-1.5 shrink-0"
            >
              {actionLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Key className="w-3.5 h-3.5" />}
              Generate BFV Keypair
            </Button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left: Operational Boundaries */}
            <Card className="border-[#E9EDE7] shadow-xs bg-white">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-[#1A1A1A]">Operational Boundaries</CardTitle>
                <CardDescription className="text-xs text-[#767676]">
                  Parameter constraints &amp; noise budget limits
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 text-xs">
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                  <div className="text-[11px] text-slate-500 font-medium">Scheme Type</div>
                  <div className="font-mono font-semibold text-slate-800">BFV (Brakerski/Fan-Vercauteren)</div>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                  <div className="text-[11px] text-slate-500 font-medium">Max Poly Modulus Degree</div>
                  <div className="font-mono font-semibold text-slate-800">
                    {fheLimits?.maxPolyModulusDegree || 8192} (128-bit Security)
                  </div>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                  <div className="text-[11px] text-slate-500 font-medium">Max Multiplicative Depth</div>
                  <div className="font-mono font-semibold text-slate-800">
                    {fheLimits?.maxMultiplicationDepth || 4} Operations
                  </div>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                  <div className="text-[11px] text-slate-500 font-medium">Active Key ID</div>
                  <div className="font-mono text-[11px] text-blue-700 truncate">
                    {activeFheKeyId || "No key generated"}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Right: Ciphertext Computation Playground */}
            <div className="lg:col-span-2 space-y-6">
              <Card className="border-[#E9EDE7] shadow-xs bg-white">
                <CardHeader className="pb-3 border-b border-[#F0F2EE]">
                  <CardTitle className="text-sm font-semibold text-[#1A1A1A]">
                    Homomorphic Arithmetic Playground
                  </CardTitle>
                  <CardDescription className="text-xs text-[#767676]">
                    Demonstrate Decrypt(Evaluate(Enc(A), Enc(B))) == A op B
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4 pt-4">
                  {/* Inputs */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold text-[#1A1A1A]">Plaintext Integer A</label>
                      <Input
                        type="number"
                        value={fhePlaintextA}
                        onChange={(e) => setFhePlaintextA(Number(e.target.value))}
                        className="font-mono text-xs"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold text-[#1A1A1A]">Plaintext Integer B</label>
                      <Input
                        type="number"
                        value={fhePlaintextB}
                        onChange={(e) => setFhePlaintextB(Number(e.target.value))}
                        className="font-mono text-xs"
                      />
                    </div>
                  </div>

                  {/* Ciphertext Status Indicator */}
                  {cipherA && cipherB && (
                    <div className="p-3 rounded-lg bg-blue-50/80 border border-blue-200 text-blue-900 text-xs flex items-center justify-between animate-in fade-in">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-blue-600 shrink-0" />
                        <div>
                          <span className="font-semibold">Ciphertexts Ready for Computation:</span>{" "}
                          <span className="font-mono text-[11px] text-blue-700">
                            Enc(A) [{(cipherA.length / 1024).toFixed(1)} KB] &amp; Enc(B) [{(cipherB.length / 1024).toFixed(1)} KB]
                          </span>
                        </div>
                      </div>
                      <Badge variant="outline" className="bg-blue-100 text-blue-800 border-blue-300 text-[10px] font-mono">
                        SEAL BFV
                      </Badge>
                    </div>
                  )}

                  <div className="flex items-center justify-between pt-2 border-t border-[#F0F2EE]">
                    <Button
                      onClick={handleEncryptFheValues}
                      disabled={actionLoading || !activeFheKeyId}
                      size="sm"
                      variant="outline"
                      className="text-xs gap-1.5"
                    >
                      Encrypt Plaintexts A &amp; B
                    </Button>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-[#1A1A1A]">Op:</span>
                      {["ADD", "SUBTRACT", "MULTIPLY"].map((op) => (
                        <button
                          key={op}
                          onClick={() => setFheOperation(op)}
                          className={`px-2.5 py-1 rounded-md text-xs font-mono font-semibold transition-colors ${
                            fheOperation === op
                              ? "bg-blue-600 text-white"
                              : "bg-slate-100 text-slate-700 hover:bg-slate-200"
                          }`}
                        >
                          {op}
                        </button>
                      ))}
                      <Button
                        onClick={handleEvaluateFhe}
                        disabled={actionLoading || !cipherA || !cipherB}
                        size="sm"
                        className="bg-blue-600 hover:bg-blue-700 text-white text-xs gap-1.5"
                      >
                        Evaluate Homomorphic {fheOperation}
                      </Button>
                    </div>
                  </div>

                  {/* Ciphertext artifacts */}
                  {evalResultCipher && (
                    <div className="p-3.5 rounded-xl bg-slate-900 text-slate-200 space-y-3 border border-slate-800 animate-in fade-in">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold text-blue-400 flex items-center gap-1.5">
                          <Cpu className="w-3.5 h-3.5" />
                          Homomorphic Result Ciphertext Computed
                        </span>
                        <span className="font-mono text-[10px] text-slate-400">
                          Depth: {fheEvaluationMeta?.operationDepth} | {fheEvaluationMeta?.durationMs}ms
                        </span>
                      </div>
                      <div className="p-2 rounded bg-slate-950 font-mono text-[10px] text-slate-300 truncate">
                        {evalResultCipher.substring(0, 80)}... ({evalResultCipher.length} chars)
                      </div>
                      <div className="flex items-center justify-between pt-1">
                        <div className="text-xs text-slate-300">
                          Decrypted Plaintext Value:{" "}
                          <span className="font-mono font-bold text-emerald-400 text-sm">
                            {decryptedFheValue !== null ? decryptedFheValue : "Pending decryption"}
                          </span>
                        </div>
                        <Button
                          onClick={handleDecryptFheResult}
                          disabled={actionLoading}
                          size="sm"
                          className="bg-emerald-600 hover:bg-emerald-700 text-white text-xs gap-1"
                        >
                          Decrypt Result
                        </Button>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* TAB 3: MULTI-PARTY COMPUTATION */}
      {/* ===================================================================== */}
      {activeTab === "mpc" && (
        <div className="space-y-6">
          <div className="p-4 rounded-xl border border-purple-200 bg-purple-50/40 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Users className="w-4 h-4 text-purple-700" />
                <h3 className="text-sm font-bold text-[#1A1A1A]">Additive Secret Sharing MPC</h3>
                <Badge variant="outline" className="text-[10px] bg-purple-100 text-purple-800 border-purple-300">
                  Zero Input Leakage
                </Badge>
              </div>
              <p className="text-xs text-[#767676]">
                Parties submit blinded shares into a finite prime field. Neither central coordinator nor other parties ever receive raw inputs.
              </p>
            </div>
            <Button
              onClick={handleCreateMpcSession}
              disabled={actionLoading}
              size="sm"
              className="bg-purple-600 hover:bg-purple-700 text-white text-xs gap-1.5 shrink-0"
            >
              New 2-Party Session
            </Button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="border-[#E9EDE7] shadow-xs bg-white">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-[#1A1A1A]">MPC Sessions</CardTitle>
                <CardDescription className="text-xs text-[#767676]">Active coordinator sessions</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {mpcSessions.length === 0 ? (
                  <div className="p-6 text-center text-xs text-[#767676] border border-dashed rounded-lg">
                    No active sessions.
                  </div>
                ) : (
                  mpcSessions.map((sess) => (
                    <div
                      key={sess.id}
                      onClick={() => setActiveMpcSession(sess)}
                      role="button"
                      tabIndex={0}
                      aria-pressed={activeMpcSession?.id === sess.id}
                      aria-label={`Select MPC session ${sess.title}`}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          setActiveMpcSession(sess);
                        }
                      }}
                      className={`p-3 rounded-xl border cursor-pointer text-xs transition-all ${
                        activeMpcSession?.id === sess.id
                          ? "border-purple-600 bg-purple-50/30 ring-1 ring-purple-600"
                          : "border-[#E9EDE7] hover:border-[#D1D5DB]"
                      }`}
                    >
                      <div className="flex items-center justify-between font-semibold text-[#1A1A1A]">
                        <span className="truncate">{sess.title}</span>
                        <Badge variant="outline" className="text-[9px] font-mono">
                          {sess.status}
                        </Badge>
                      </div>
                      <div className="text-[10px] text-purple-700 font-mono mt-0.5 truncate">{sess.id}</div>
                      <div className="text-[11px] text-[#767676] mt-1">
                        Parties: {sess.requiredParties} | Op: {sess.operation}
                      </div>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>

            <div className="lg:col-span-2 space-y-6">
              <Card className="border-[#E9EDE7] shadow-xs bg-white">
                <CardHeader className="pb-3 border-b border-[#F0F2EE]">
                  <CardTitle className="text-sm font-semibold text-[#1A1A1A]">Multi-Party Simulator</CardTitle>
                  <CardDescription className="text-xs text-[#767676]">
                    Simulate Alice (100) and Bob (250) submitting secret shares
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4 pt-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="p-3.5 rounded-xl border border-[#E9EDE7] space-y-2 bg-[#FAFDFB]">
                      <div className="flex items-center justify-between text-xs font-semibold text-[#1A1A1A]">
                        <span>Party 1: Alice Corp</span>
                        <Badge variant="outline" className="text-[9px]">INPUT_PARTY</Badge>
                      </div>
                      <Input
                        type="number"
                        value={partyInputValues["party-alice"] || 100}
                        onChange={(e) =>
                          setPartyInputValues({ ...partyInputValues, "party-alice": Number(e.target.value) })
                        }
                        className="font-mono text-xs"
                      />
                      <p className="text-[10px] text-[#767676]">Private salary input: 100</p>
                    </div>

                    <div className="p-3.5 rounded-xl border border-[#E9EDE7] space-y-2 bg-[#FAFDFB]">
                      <div className="flex items-center justify-between text-xs font-semibold text-[#1A1A1A]">
                        <span>Party 2: Bob Inc</span>
                        <Badge variant="outline" className="text-[9px]">INPUT_PARTY</Badge>
                      </div>
                      <Input
                        type="number"
                        value={partyInputValues["party-bob"] || 250}
                        onChange={(e) =>
                          setPartyInputValues({ ...partyInputValues, "party-bob": Number(e.target.value) })
                        }
                        className="font-mono text-xs"
                      />
                      <p className="text-[10px] text-[#767676]">Private salary input: 250</p>
                    </div>
                  </div>

                  <div className="flex items-center justify-end gap-2 pt-2">
                    <Button
                      onClick={handleSimulateMpcFlow}
                      disabled={actionLoading || !activeMpcSession}
                      size="sm"
                      className="bg-purple-600 hover:bg-purple-700 text-white text-xs gap-1.5"
                    >
                      {actionLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                      Execute End-to-End MPC Round
                    </Button>
                  </div>

                  {mpcResult && (
                    <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-900 space-y-1 animate-in fade-in text-xs">
                      <div className="font-bold flex items-center gap-1.5 text-emerald-700">
                        <CheckCircle2 className="w-4 h-4" />
                        Joint Computation Result: {mpcResult.computedValue}
                      </div>
                      <div className="text-[11px] text-emerald-800">
                        Participating parties: {mpcResult.participatingParties?.join(", ")}
                      </div>
                      <div className="text-[10px] text-emerald-700 font-mono">
                        Computed securely without revealing raw party inputs.
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* TAB 4: THRESHOLD CRYPTOGRAPHY */}
      {/* ===================================================================== */}
      {activeTab === "threshold" && (
        <div className="space-y-6">
          <div className="p-4 rounded-xl border border-rose-200 bg-rose-50/40 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Key className="w-4 h-4 text-rose-700" />
                <h3 className="text-sm font-bold text-[#1A1A1A]">M-of-N Threshold Key Engine</h3>
                <Badge variant="outline" className="text-[10px] bg-rose-100 text-rose-800 border-rose-300">
                  FROST &amp; Shamir Quorum
                </Badge>
              </div>
              <p className="text-xs text-[#767676]">
                Requires M-of-N independent participants to approve any cryptographic operation. Fails closed when quorum is not met.
              </p>
            </div>
            <Button
              onClick={handleCreateThresholdKey}
              disabled={actionLoading}
              size="sm"
              className="bg-rose-600 hover:bg-rose-700 text-white text-xs gap-1.5 shrink-0"
            >
              Generate 3-of-5 Key
            </Button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="border-[#E9EDE7] shadow-xs bg-white">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold text-[#1A1A1A]">Threshold Keys</CardTitle>
                <CardDescription className="text-xs text-[#767676]">M-of-N shared keys</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {thresholdKeys.length === 0 ? (
                  <div className="p-6 text-center text-xs text-[#767676] border border-dashed rounded-lg">
                    No threshold keys created.
                  </div>
                ) : (
                  thresholdKeys.map((k) => (
                    <div
                      key={k.id}
                      onClick={() => setActiveThresholdKey(k)}
                      role="button"
                      tabIndex={0}
                      aria-pressed={activeThresholdKey?.id === k.id}
                      aria-label={`Select threshold key ${k.name}`}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          setActiveThresholdKey(k);
                        }
                      }}
                      className={`p-3 rounded-xl border cursor-pointer text-xs transition-all ${
                        activeThresholdKey?.id === k.id
                          ? "border-rose-600 bg-rose-50/30 ring-1 ring-rose-600"
                          : "border-[#E9EDE7] hover:border-[#D1D5DB]"
                      }`}
                    >
                      <div className="flex items-center justify-between font-semibold text-[#1A1A1A]">
                        <span className="truncate">{k.name}</span>
                        <Badge variant="outline" className="text-[9px] font-mono">
                          {k.threshold}-of-{k.totalParticipants}
                        </Badge>
                      </div>
                      <div className="text-[10px] text-rose-700 font-mono mt-0.5 truncate">{k.id}</div>
                      <div className="text-[11px] text-[#767676] mt-1 font-mono truncate">
                        Pub: {k.groupPublicKey}
                      </div>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>

            <div className="lg:col-span-2 space-y-6">
              <Card className="border-[#E9EDE7] shadow-xs bg-white">
                <CardHeader className="pb-3 border-b border-[#F0F2EE]">
                  <CardTitle className="text-sm font-semibold text-[#1A1A1A]">
                    Threshold Authorization Quorum
                  </CardTitle>
                  <CardDescription className="text-xs text-[#767676]">
                    Collect participant signatures until quorum (M=3) is satisfied
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4 pt-4">
                  <div className="flex items-center gap-2">
                    <Input
                      value={thresholdMessage}
                      onChange={(e) => setThresholdMessage(e.target.value)}
                      placeholder="Message or transaction to authorize..."
                      className="text-xs font-mono"
                    />
                    <Button
                      onClick={handleCreateThresholdSession}
                      disabled={actionLoading || !activeThresholdKey}
                      size="sm"
                      variant="outline"
                      className="text-xs shrink-0"
                    >
                      Create Session
                    </Button>
                  </div>

                  {activeThresholdSession && (
                    <div className="space-y-3 pt-2">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold text-[#1A1A1A]">
                          Approvals: {activeThresholdSession.approvals?.length || 0} /{" "}
                          {activeThresholdSession.threshold} Required
                        </span>
                        <Badge
                          variant="outline"
                          className={
                            activeThresholdSession.status === "READY" || activeThresholdSession.status === "EXECUTED"
                              ? "bg-emerald-100 text-emerald-800"
                              : "bg-amber-100 text-amber-800"
                          }
                        >
                          {activeThresholdSession.status}
                        </Badge>
                      </div>

                      {/* Participants list */}
                      <div className="space-y-2">
                        {activeThresholdKey?.participants?.map((p: any) => {
                          const isApproved = activeThresholdSession.approvals?.some(
                            (a: any) => a.participantId === p.participantId
                          );
                          return (
                            <div
                              key={p.participantId}
                              className="flex items-center justify-between p-2.5 rounded-lg border border-[#E9EDE7] bg-white text-xs"
                            >
                              <div>
                                <span className="font-semibold text-[#1A1A1A]">{p.name}</span>
                                <span className="font-mono text-[10px] text-[#767676] ml-2">{p.participantId}</span>
                              </div>
                              {isApproved ? (
                                <Badge variant="outline" className="text-[10px] bg-emerald-50 text-emerald-700 border-emerald-200">
                                  Approved
                                </Badge>
                              ) : (
                                <Button
                                  onClick={() => handleApproveThresholdSession(p.participantId)}
                                  disabled={actionLoading || activeThresholdSession.status === "EXECUTED"}
                                  size="sm"
                                  variant="outline"
                                  className="text-[11px] h-7 px-2.5"
                                >
                                  Sign / Approve
                                </Button>
                              )}
                            </div>
                          );
                        })}
                      </div>

                      <div className="flex items-center justify-end pt-2">
                        <Button
                          onClick={handleExecuteThresholdSession}
                          disabled={
                            actionLoading ||
                            activeThresholdSession.approvals?.length < activeThresholdSession.threshold ||
                            activeThresholdSession.status === "EXECUTED"
                          }
                          size="sm"
                          className="bg-rose-600 hover:bg-rose-700 text-white text-xs gap-1.5"
                        >
                          {actionLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                          Execute Threshold Signing
                        </Button>
                      </div>

                      {activeThresholdSession.combinedResult && (
                        <div className="p-3.5 rounded-xl bg-slate-900 text-slate-200 space-y-1 font-mono text-xs border border-slate-800 animate-in fade-in">
                          <div className="text-emerald-400 font-bold">Distributed Signature Output:</div>
                          <div className="truncate text-[11px] text-slate-300">
                            {activeThresholdSession.combinedResult.signature}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* TAB 5: PROVIDER CAPABILITIES */}
      {/* ===================================================================== */}
      {activeTab === "providers" && (
        <div className="space-y-4">
          <Card className="border-[#E9EDE7] shadow-xs bg-white">
            <CardHeader className="pb-3 border-b border-[#F0F2EE]">
              <CardTitle className="text-sm font-semibold text-[#1A1A1A]">Advanced Cryptographic Provider Registry</CardTitle>
              <CardDescription className="text-xs text-[#767676]">
                Verified libraries, supported schemes, operations, and readiness statuses
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <div className="divide-y divide-[#F0F2EE]">
                {providers.map((p) => (
                  <div key={p.providerId} className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-[10px] font-mono uppercase bg-slate-50">
                          {p.family}
                        </Badge>
                        <span className="text-sm font-bold text-[#1A1A1A]">{p.name}</span>
                        <span className="text-xs font-mono text-[#767676]">v{p.version}</span>
                      </div>
                      <p className="text-xs text-[#767676]">{p.description}</p>
                      <div className="flex items-center gap-2 text-[11px] font-mono text-slate-600 pt-1">
                        <span>Impl: {p.implementation}</span>
                        <span>•</span>
                        <span>Schemes: {p.supportedSchemes?.join(", ")}</span>
                        <span>•</span>
                        <span>Ops: {p.supportedOperations?.join(", ")}</span>
                      </div>
                    </div>
                    <Badge
                      variant="outline"
                      className={`text-xs font-bold uppercase shrink-0 ${
                        p.status === "SUPPORTED"
                          ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                          : "bg-amber-50 text-amber-700 border-amber-200"
                      }`}
                    >
                      {p.status}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Register Circuit Modal */}
      <Modal
        isOpen={registerCircuitOpen}
        onClose={() => setRegisterCircuitOpen(false)}
        title="Register Zero-Knowledge Circuit"
      >
        <form onSubmit={handleRegisterCircuit} className="space-y-4 text-xs">
          <div className="space-y-1.5">
            <label className="font-semibold text-[#1A1A1A]">Circuit Identifier</label>
            <Input
              value={newCircuit.id}
              onChange={(e) => setNewCircuit({ ...newCircuit, id: e.target.value })}
              className="font-mono text-xs"
              required
            />
          </div>
          <div className="space-y-1.5">
            <label className="font-semibold text-[#1A1A1A]">Circuit Name</label>
            <Input
              value={newCircuit.name}
              onChange={(e) => setNewCircuit({ ...newCircuit, name: e.target.value })}
              className="text-xs"
              required
            />
          </div>
          <div className="space-y-1.5">
            <label className="font-semibold text-[#1A1A1A]">Description</label>
            <Input
              value={newCircuit.description}
              onChange={(e) => setNewCircuit({ ...newCircuit, description: e.target.value })}
              className="text-xs"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="font-semibold text-[#1A1A1A]">Proving System</label>
              <Input
                value={newCircuit.provingSystem}
                onChange={(e) => setNewCircuit({ ...newCircuit, provingSystem: e.target.value })}
                className="font-mono text-xs"
                disabled
              />
            </div>
            <div className="space-y-1.5">
              <label className="font-semibold text-[#1A1A1A]">Version</label>
              <Input
                value={newCircuit.version}
                onChange={(e) => setNewCircuit({ ...newCircuit, version: e.target.value })}
                className="font-mono text-xs"
              />
            </div>
          </div>
          <div className="flex items-center justify-end gap-2 pt-3 border-t border-[#E9EDE7]">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setRegisterCircuitOpen(false)}
              className="text-xs"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              size="sm"
              disabled={actionLoading}
              className="bg-[#008031] hover:bg-[#006e2a] text-white text-xs gap-1.5"
            >
              {actionLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null}
              Register Circuit
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
