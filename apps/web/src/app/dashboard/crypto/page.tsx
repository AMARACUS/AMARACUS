"use client";

import React, { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Shield,
  ShieldCheck,
  Lock,
  Unlock,
  Key,
  Hash,
  FileCheck2,
  Cpu,
  Zap,
  Copy,
  Check,
  Loader2,
  AlertCircle,
  RefreshCw,
  ArrowRightLeft,
  Sparkles,
} from "lucide-react";
import { api } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-context";

type PlaygroundTab = "hash" | "hmac" | "encrypt" | "sign" | "key_agreement" | "random";

export default function CryptoPlaygroundPage() {
  const { activeOrg } = useAuth();
  const [tab, setTab] = useState<PlaygroundTab>("hash");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // --- HASH STATE ---
  const [hashAlg, setHashAlg] = useState("SHA-256");
  const [hashInput, setHashInput] = useState("hello");
  const [hashResult, setHashResult] = useState<{ digest: string; byteLength: number; timingMs: number } | null>(null);

  // --- HMAC STATE ---
  const [hmacAlg, setHmacAlg] = useState("HMAC-SHA-256");
  const [hmacKey, setHmacKey] = useState("my-super-secret-password");
  const [hmacInput, setHmacInput] = useState("Transfer $500 to Alice");
  const [hmacResult, setHmacResult] = useState<{ mac: string; timingMs: number; verified?: boolean } | null>(null);

  // --- ENCRYPT / DECRYPT STATE ---
  const [encAlg, setEncAlg] = useState("AES-256-GCM");
  const [encKeyHex, setEncKeyHex] = useState("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  const [plaintext, setPlaintext] = useState("My secret password is: Dragon123!");
  const [aad, setAad] = useState("Org:Amaracus,Classification:Restricted");
  const [encEnvelope, setEncEnvelope] = useState<any | null>(null);
  const [decryptedText, setDecryptedText] = useState<string | null>(null);
  const [encTiming, setEncTiming] = useState<number | null>(null);

  // --- SIGNATURE STATE ---
  const [signMessage, setSignMessage] = useState("I approve this transaction of $10,000.");
  const [signKeyPair, setSignKeyPair] = useState<{ publicKey: string; privateKey: string } | null>(null);
  const [signSignature, setSignSignature] = useState<string | null>(null);
  const [verifyStatus, setVerifyStatus] = useState<boolean | null>(null);
  const [signTiming, setSignTiming] = useState<number | null>(null);

  // --- KEY AGREEMENT (X25519) STATE ---
  const [aliceKeys, setAliceKeys] = useState<{ publicKey: string; privateKey: string } | null>(null);
  const [bobKeys, setBobKeys] = useState<{ publicKey: string; privateKey: string } | null>(null);
  const [aliceSecret, setAliceSecret] = useState<string | null>(null);
  const [bobSecret, setBobSecret] = useState<string | null>(null);
  const [kaTiming, setKaTiming] = useState<number | null>(null);

  // --- CSPRNG RANDOM STATE ---
  const [randomLen, setRandomLen] = useState(32);
  const [randomEncoding, setRandomEncoding] = useState<"hex" | "base64">("hex");
  const [randomOutput, setRandomOutput] = useState<string | null>(null);

  const orgId = activeOrg?.id || "default";

  // Preload Ed25519 and X25519 keys
  useEffect(() => {
    if (activeOrg) {
      api.crypto.generateKeypair(activeOrg.id, "ED25519").then((res) => setSignKeyPair(res.data)).catch(() => {});
      api.crypto.generateKeypair(activeOrg.id, "X25519").then((res) => setAliceKeys(res.data)).catch(() => {});
      api.crypto.generateKeypair(activeOrg.id, "X25519").then((res) => setBobKeys(res.data)).catch(() => {});
    }
  }, [activeOrg]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // --- 1. RUN HASH ---
  const handleRunHash = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.crypto.hash(orgId, {
        algorithm: hashAlg,
        data: hashInput,
        outputEncoding: "hex",
      });
      setHashResult({
        digest: res.data.digest,
        byteLength: res.data.byteLength,
        timingMs: res.meta.executionTimingMs,
      });
    } catch (err: any) {
      setError(err.message || "Failed to compute cryptographic hash");
    } finally {
      setLoading(false);
    }
  };

  // --- 2. RUN HMAC ---
  const handleRunHmac = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.crypto.hmac(orgId, {
        algorithm: hmacAlg,
        key: hmacKey,
        data: hmacInput,
        outputEncoding: "hex",
      });
      const verifyRes = await api.crypto.verifyHmac(orgId, {
        algorithm: hmacAlg,
        key: hmacKey,
        data: hmacInput,
        mac: res.data.mac,
      });
      setHmacResult({
        mac: res.data.mac,
        timingMs: res.meta.executionTimingMs,
        verified: verifyRes.data.valid,
      });
    } catch (err: any) {
      setError(err.message || "Failed to compute HMAC");
    } finally {
      setLoading(false);
    }
  };

  // --- 3. GENERATE RANDOM 256-BIT KEY ---
  const handleGenerateRandomKey = async () => {
    setLoading(true);
    try {
      const res = await api.crypto.random(orgId, 32, "hex");
      if (res?.data?.random) {
        setEncKeyHex(res.data.random);
      }
    } catch {
      const bytes = Array.from(crypto.getRandomValues(new Uint8Array(32)))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      setEncKeyHex(bytes);
    } finally {
      setLoading(false);
    }
  };

  // --- 3. RUN ENCRYPT ---
  const handleRunEncrypt = async () => {
    setLoading(true);
    setError(null);
    setDecryptedText(null);
    try {
      const res = await api.crypto.encrypt(orgId, {
        algorithm: encAlg,
        key: encKeyHex,
        keyEncoding: "hex",
        plaintext,
        aad: aad || undefined,
      });
      setEncEnvelope(res.data);
      setEncTiming(res.meta.executionTimingMs);
    } catch (err: any) {
      setError(err.message || "Encryption failed");
    } finally {
      setLoading(false);
    }
  };

  const handleRunDecrypt = async () => {
    if (!encEnvelope) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.crypto.decrypt(orgId, {
        envelope: encEnvelope,
        key: encKeyHex,
        keyEncoding: "hex",
      });
      setDecryptedText(res.data.plaintext);
    } catch (err: any) {
      setError(err.message || "Decryption authentication failed");
    } finally {
      setLoading(false);
    }
  };

  // --- 4. RUN SIGN & VERIFY ---
  const handleGenerateSignKeys = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.crypto.generateKeypair(orgId, "ED25519");
      setSignKeyPair(res.data);
      setSignSignature(null);
      setVerifyStatus(null);
    } catch (err: any) {
      setError(err.message || "Keypair generation failed");
    } finally {
      setLoading(false);
    }
  };

  const handleRunSign = async () => {
    setLoading(true);
    setError(null);
    try {
      let kp = signKeyPair;
      if (!kp) {
        const genRes = await api.crypto.generateKeypair(orgId, "ED25519");
        kp = genRes.data;
        setSignKeyPair(kp);
      }

      const res = await api.crypto.sign(orgId, {
        algorithm: "ED25519",
        privateKey: kp!.privateKey,
        message: signMessage,
      });
      setSignSignature(res.data.signature);
      setSignTiming(res.meta.executionTimingMs);

      // Verify
      const vRes = await api.crypto.verify(orgId, {
        algorithm: "ED25519",
        publicKey: kp!.publicKey,
        message: signMessage,
        signature: res.data.signature,
      });
      setVerifyStatus(vRes.data.valid);
    } catch (err: any) {
      setError(err.message || "Digital signing failed");
    } finally {
      setLoading(false);
    }
  };

  // --- 5. RUN KEY AGREEMENT (X25519) ---
  const handleGenerateKaKeys = async () => {
    setLoading(true);
    try {
      const [resA, resB] = await Promise.all([
        api.crypto.generateKeypair(orgId, "X25519"),
        api.crypto.generateKeypair(orgId, "X25519"),
      ]);
      setAliceKeys(resA.data);
      setBobKeys(resB.data);
      setAliceSecret(null);
      setBobSecret(null);
    } catch (err: any) {
      setError(err.message || "Keypair generation failed");
    } finally {
      setLoading(false);
    }
  };

  const handleRunKeyAgreement = async () => {
    setLoading(true);
    setError(null);
    try {
      let aKeys = aliceKeys;
      let bKeys = bobKeys;
      if (!aKeys) {
        const resA = await api.crypto.generateKeypair(orgId, "X25519");
        aKeys = resA.data;
        setAliceKeys(aKeys);
      }
      if (!bKeys) {
        const resB = await api.crypto.generateKeypair(orgId, "X25519");
        bKeys = resB.data;
        setBobKeys(bKeys);
      }

      // Alice derives secret using Bob's public key
      const aRes = await api.crypto.keyAgreement(orgId, {
        algorithm: "X25519",
        privateKey: aKeys!.privateKey,
        publicKey: bKeys!.publicKey,
      });
      // Bob derives secret using Alice's public key
      const bRes = await api.crypto.keyAgreement(orgId, {
        algorithm: "X25519",
        privateKey: bKeys!.privateKey,
        publicKey: aKeys!.publicKey,
      });
      setAliceSecret(aRes.data.sharedSecret);
      setBobSecret(bRes.data.sharedSecret);
      setKaTiming(aRes.meta.executionTimingMs + bRes.meta.executionTimingMs);
    } catch (err: any) {
      setError(err.message || "Key agreement failed");
    } finally {
      setLoading(false);
    }
  };

  // --- 6. RUN CSPRNG ---
  const handleRunRandom = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.crypto.random(orgId, randomLen, randomEncoding);
      setRandomOutput(res.data.random);
    } catch (err: any) {
      setError(err.message || "CSPRNG generation failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="border-b border-[#E9EDE7] pb-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-[#EAF3EC] text-[#008031] text-[11px] font-semibold mb-2">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>AMARACUS Phase 4 — Core Cryptography Engine</span>
            </div>
            <h1 className="font-editorial text-3xl md:text-4xl font-bold text-[#1A1A1A] tracking-tight">
              Cryptography Playground
            </h1>
            <p className="text-xs md:text-sm text-[#636863] mt-1.5 leading-relaxed max-w-2xl">
              Server-side cryptography using standard algorithms (AES-GCM, SHA-2/3, Ed25519, ML-KEM, ML-DSA) through Node.js crypto and the audited noble libraries, with every operation recorded in your organization&apos;s audit log. Not a FIPS 140-3 validated module.
            </p>
          </div>

          <div className="flex items-center gap-2 self-start md:self-auto">
            <Badge variant="default" className="bg-[#EAF3EC] text-[#008031] border-[#C8E0CF]">
              Live Engine: OpenSSL 3 / Node.js
            </Badge>
            <Badge variant="outline" className="border-[#E9EDE7] text-[#636863]">
              Active Org: {activeOrg?.name || "Workspace"}
            </Badge>
          </div>
        </div>
      </div>

      {/* Operation Tabs */}
      <div className="flex gap-2 border-b border-[#E9EDE7] pb-3 overflow-x-auto text-xs font-medium" role="tablist" aria-label="Cryptographic Operations">
        {[
          { id: "hash", label: "Cryptographic Hashing", icon: Hash },
          { id: "hmac", label: "HMAC Authentication", icon: Shield },
          { id: "encrypt", label: "AES-256-GCM (AEAD)", icon: Lock },
          { id: "sign", label: "Ed25519 Signatures", icon: FileCheck2 },
          { id: "key_agreement", label: "X25519 Key Agreement", icon: ArrowRightLeft },
          { id: "random", label: "Secure CSPRNG", icon: Sparkles },
        ].map((t) => {
          const Icon = t.icon;
          const isActive = tab === t.id;
          return (
            <button
              key={t.id}
              role="tab"
              aria-selected={isActive}
              onClick={() => {
                setTab(t.id as PlaygroundTab);
                setError(null);
              }}
              className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg transition-all whitespace-nowrap ${
                isActive
                  ? "bg-[#EAF3EC] text-[#008031] font-semibold border border-[#C8E0CF]"
                  : "text-[#555555] hover:bg-white border border-transparent"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{t.label}</span>
            </button>
          );
        })}
      </div>

      {/* Global Error Banner */}
      {error && (
        <div className="p-3.5 rounded-xl border border-red-200 bg-red-50 text-red-700 flex items-center gap-2.5 text-xs">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* TAB CONTENT */}
      <div className="grid lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Form Controls */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-base font-semibold text-[#1A1A1A]">
                {tab === "hash" && "Deterministic Cryptographic Digest"}
                {tab === "hmac" && "Keyed-Hash Message Authentication Code"}
                {tab === "encrypt" && "Authenticated Envelope Encryption (AES-256-GCM)"}
                {tab === "sign" && "Asymmetric Edwards-Curve Signatures (Ed25519)"}
                {tab === "key_agreement" && "Diffie-Hellman Shared Secret Negotiation (X25519)"}
                {tab === "random" && "Cryptographically Secure Pseudorandom Number Generator"}
              </CardTitle>
              <Badge variant="outline" className="text-[10px] text-[#008031] bg-[#EAF3EC] border-[#C8E0CF]">
                Real Server Operation
              </Badge>
            </div>
            <CardDescription className="text-xs text-[#636863]">
              {tab === "hash" && "Compute cryptographic collision-resistant digests using NIST SHA-2 and SHA-3 Keccak algorithms."}
              {tab === "hmac" && "Authenticate messages and verify tamper-resistance with constant-time equality comparisons."}
              {tab === "encrypt" && "NIST SP 800-38D authenticated encryption with 96-bit CSPRNG IVs, 128-bit tags, and optional AAD."}
              {tab === "sign" && "Sign arbitrary messages and verify signatures using RFC 8032 Edwards-curve digital signatures."}
              {tab === "key_agreement" && "Negotiate identical 256-bit symmetric shared secrets between two parties across an untrusted channel."}
              {tab === "random" && "Generate high-entropy random bytes from operating system entropy pools for keys, nonces, and salts."}
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4 text-xs">
            {/* 1. HASH TAB */}
            {tab === "hash" && (
              <>
                <div className="grid sm:grid-cols-2 gap-4">
                  <div>
                    <label className="font-medium text-[#1A1A1A] block mb-1.5">Algorithm</label>
                    <select
                      value={hashAlg}
                      onChange={(e) => setHashAlg(e.target.value)}
                      className="w-full h-9 rounded-lg border border-[#E9EDE7] bg-white px-3 text-xs text-[#1A1A1A] focus:outline-none focus:border-[#008031]"
                    >
                      <option value="SHA-256">SHA-256 (NIST FIPS 180-4 - Recommended)</option>
                      <option value="SHA-384">SHA-384 (NIST FIPS 180-4)</option>
                      <option value="SHA-512">SHA-512 (NIST FIPS 180-4)</option>
                      <option value="SHA3-256">SHA3-256 (NIST FIPS 202 Keccak)</option>
                      <option value="SHA3-384">SHA3-384 (NIST FIPS 202)</option>
                      <option value="SHA3-512">SHA3-512 (NIST FIPS 202)</option>
                    </select>
                  </div>
                  <div>
                    <label className="font-medium text-[#1A1A1A] block mb-1.5">Digest Encoding</label>
                    <input
                      disabled
                      value="Hexadecimal (Lower-case)"
                      className="w-full h-9 rounded-lg border border-[#E9EDE7] bg-[#F8F7F4] px-3 text-xs text-[#636863]"
                    />
                  </div>
                </div>

                <div>
                  <label htmlFor="hash-input" className="font-medium text-[#1A1A1A] block mb-1.5">Input Payload</label>
                  <textarea
                    id="hash-input"
                    rows={3}
                    value={hashInput}
                    onChange={(e) => setHashInput(e.target.value)}
                    className="w-full rounded-lg border border-[#E9EDE7] bg-white p-3 text-xs text-[#1A1A1A] font-mono focus:outline-none focus:border-[#008031]"
                    placeholder="Enter string or raw data..."
                  />
                </div>

                <Button
                  onClick={handleRunHash}
                  disabled={loading}
                  className="bg-[#008031] hover:bg-[#006e2a] text-white text-xs h-9 px-4"
                >
                  {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : <Zap className="w-3.5 h-3.5 mr-1.5" />}
                  Compute Cryptographic Hash
                </Button>
              </>
            )}

            {/* 2. HMAC TAB */}
            {tab === "hmac" && (
              <>
                <div className="grid sm:grid-cols-2 gap-4">
                  <div>
                    <label className="font-medium text-[#1A1A1A] block mb-1.5">Algorithm</label>
                    <select
                      value={hmacAlg}
                      onChange={(e) => setHmacAlg(e.target.value)}
                      className="w-full h-9 rounded-lg border border-[#E9EDE7] bg-white px-3 text-xs text-[#1A1A1A] focus:outline-none focus:border-[#008031]"
                    >
                      <option value="HMAC-SHA-256">HMAC-SHA-256 (RFC 2104 - Recommended)</option>
                      <option value="HMAC-SHA-384">HMAC-SHA-384 (RFC 2104)</option>
                      <option value="HMAC-SHA-512">HMAC-SHA-512 (RFC 2104)</option>
                    </select>
                  </div>
                  <div>
                    <label className="font-medium text-[#1A1A1A] block mb-1.5">HMAC Secret Key</label>
                    <Input
                      value={hmacKey}
                      onChange={(e) => setHmacKey(e.target.value)}
                      className="font-mono text-xs h-9"
                    />
                  </div>
                </div>

                <div>
                  <label htmlFor="hmac-input" className="font-medium text-[#1A1A1A] block mb-1.5">Payload Data (Message to Authenticate)</label>
                  <textarea
                    id="hmac-input"
                    rows={2}
                    value={hmacInput}
                    onChange={(e) => setHmacInput(e.target.value)}
                    className="w-full rounded-lg border border-[#E9EDE7] bg-white p-3 text-xs text-[#1A1A1A] font-mono focus:outline-none focus:border-[#008031]"
                    placeholder="Enter payload to authenticate..."
                  />
                </div>

                <Button
                  onClick={handleRunHmac}
                  disabled={loading}
                  className="bg-[#008031] hover:bg-[#006e2a] text-white text-xs h-9 px-4"
                >
                  {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : <Shield className="w-3.5 h-3.5 mr-1.5" />}
                  Generate & Verify HMAC
                </Button>
              </>
            )}

            {/* 3. ENCRYPTION TAB */}
            {tab === "encrypt" && (
              <>
                <div className="grid sm:grid-cols-2 gap-4">
                  <div>
                    <label className="font-medium text-[#1A1A1A] block mb-1.5">Algorithm</label>
                    <Input disabled value="AES-256-GCM (NIST SP 800-38D AEAD)" className="text-xs h-9 bg-[#F8F7F4]" />
                  </div>
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <label className="font-medium text-[#1A1A1A]">Symmetric Key (32-byte Hex)</label>
                      <button
                        type="button"
                        onClick={handleGenerateRandomKey}
                        className="text-[10px] text-[#008031] hover:underline font-semibold flex items-center gap-1"
                      >
                        <Sparkles className="w-3 h-3" /> Generate Random 256-bit Key
                      </button>
                    </div>
                    <Input
                      value={encKeyHex}
                      onChange={(e) => setEncKeyHex(e.target.value)}
                      className="font-mono text-[11px] h-9"
                    />
                  </div>
                </div>

                <div>
                  <label className="font-medium text-[#1A1A1A] block mb-1.5">Associated Authenticated Data (AAD)</label>
                  <Input
                    value={aad}
                    onChange={(e) => setAad(e.target.value)}
                    placeholder="Context / metadata bound cryptographically to ciphertext..."
                    className="font-mono text-xs h-9"
                  />
                </div>

                <div>
                  <label htmlFor="plaintext-input" className="font-medium text-[#1A1A1A] block mb-1.5">Plaintext Data</label>
                  <textarea
                    id="plaintext-input"
                    rows={2}
                    value={plaintext}
                    onChange={(e) => setPlaintext(e.target.value)}
                    className="w-full rounded-lg border border-[#E9EDE7] bg-white p-3 text-xs text-[#1A1A1A] font-mono focus:outline-none focus:border-[#008031]"
                    placeholder="Type confidential data to encrypt..."
                  />
                </div>

                <div className="flex gap-2">
                  <Button
                    onClick={handleRunEncrypt}
                    disabled={loading}
                    className="bg-[#008031] hover:bg-[#006e2a] text-white text-xs h-9 px-4"
                  >
                    {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : <Lock className="w-3.5 h-3.5 mr-1.5" />}
                    Encrypt with AES-256-GCM
                  </Button>
                  {encEnvelope && (
                    <Button
                      variant="outline"
                      onClick={handleRunDecrypt}
                      disabled={loading}
                      className="text-xs h-9 border-[#E9EDE7]"
                    >
                      <Unlock className="w-3.5 h-3.5 mr-1.5 text-[#008031]" />
                      Decrypt Envelope
                    </Button>
                  )}
                </div>
              </>
            )}

            {/* 4. SIGNATURE TAB */}
            {tab === "sign" && (
              <>
                <div className="flex items-center justify-between p-3.5 rounded-xl border border-[#E9EDE7] bg-[#F8F7F4]">
                  <div>
                    <div className="font-semibold text-[#1A1A1A]">Ed25519 Keypair (RFC 8032)</div>
                    <div className="text-[11px] text-[#636863]">Edwards-curve digital signature keys</div>
                  </div>
                  <Button
                    variant="outline"
                    onClick={handleGenerateSignKeys}
                    disabled={loading}
                    className="text-xs h-8 border-[#C8E0CF] text-[#008031] bg-white hover:bg-[#EAF3EC]"
                  >
                    <RefreshCw className="w-3 h-3 mr-1.5" /> Generate Fresh Keypair
                  </Button>
                </div>

                <div className="grid sm:grid-cols-2 gap-4">
                  <div>
                    <label className="font-medium text-[#1A1A1A] block mb-1.5">Public Key (RFC 8032 - Hex)</label>
                    <Input
                      readOnly
                      value={signKeyPair?.publicKey || "Click Generate Fresh Keypair above"}
                      className="font-mono text-[10px] h-9 bg-[#F8F7F4] text-[#1A1A1A]"
                    />
                  </div>
                  <div>
                    <label className="font-medium text-[#1A1A1A] block mb-1.5">Private Key (Secret - Hex)</label>
                    <Input
                      readOnly
                      value={signKeyPair?.privateKey || "Click Generate Fresh Keypair above"}
                      className="font-mono text-[10px] h-9 bg-[#F8F7F4] text-[#636863]"
                    />
                  </div>
                </div>

                <div>
                  <label htmlFor="sign-input" className="font-medium text-[#1A1A1A] block mb-1.5">Message to Sign</label>
                  <textarea
                    id="sign-input"
                    rows={2}
                    value={signMessage}
                    onChange={(e) => setSignMessage(e.target.value)}
                    className="w-full rounded-lg border border-[#E9EDE7] bg-white p-3 text-xs text-[#1A1A1A] font-mono focus:outline-none focus:border-[#008031]"
                    placeholder="Enter document or transaction message..."
                  />
                </div>

                <Button
                  onClick={handleRunSign}
                  disabled={loading}
                  className="bg-[#008031] hover:bg-[#006e2a] text-white text-xs h-9 px-4"
                >
                  {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : <FileCheck2 className="w-3.5 h-3.5 mr-1.5" />}
                  Sign Message & Verify Signature
                </Button>
              </>
            )}

            {/* 5. KEY AGREEMENT TAB */}
            {tab === "key_agreement" && (
              <>
                <div className="p-3.5 rounded-xl border border-[#E9EDE7] bg-[#F8F7F4] space-y-2">
                  <div className="font-semibold text-[#1A1A1A] flex items-center justify-between">
                    <span>X25519 Diffie-Hellman Protocol</span>
                    <Badge variant="outline" className="text-[10px] text-[#008031] bg-white">RFC 7748</Badge>
                  </div>
                  <p className="text-[11px] text-[#636863]">
                    Alice and Bob independently generate ephemeral X25519 keypairs. Alice uses Bob&apos;s public key + her private key; Bob uses Alice&apos;s public key + his private key. Both arrive at the exact same 32-byte shared secret without transmitting it.
                  </p>
                </div>

                <div className="grid sm:grid-cols-2 gap-4">
                  <div className="p-3 rounded-lg border border-[#E9EDE7] bg-white space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-[#1A1A1A]">Alice&apos;s Public Key</span>
                      <Badge variant="outline" className="text-[9px]">Curve25519</Badge>
                    </div>
                    <div className="text-[10px] text-[#636863] font-mono break-all">
                      {aliceKeys?.publicKey || "Ready to generate on run"}
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border border-[#E9EDE7] bg-white space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-[#1A1A1A]">Bob&apos;s Public Key</span>
                      <Badge variant="outline" className="text-[9px]">Curve25519</Badge>
                    </div>
                    <div className="text-[10px] text-[#636863] font-mono break-all">
                      {bobKeys?.publicKey || "Ready to generate on run"}
                    </div>
                  </div>
                </div>

                <div className="flex gap-2">
                  <Button
                    onClick={handleRunKeyAgreement}
                    disabled={loading}
                    className="bg-[#008031] hover:bg-[#006e2a] text-white text-xs h-9 px-4"
                  >
                    {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : <ArrowRightLeft className="w-3.5 h-3.5 mr-1.5" />}
                    Run Key Agreement Simulation
                  </Button>
                  <Button
                    variant="outline"
                    onClick={handleGenerateKaKeys}
                    disabled={loading}
                    className="text-xs h-9 border-[#E9EDE7]"
                  >
                    <RefreshCw className="w-3.5 h-3.5 mr-1" /> New Keypairs
                  </Button>
                </div>
              </>
            )}

            {/* 6. RANDOM TAB */}
            {tab === "random" && (
              <>
                <div className="grid sm:grid-cols-2 gap-4">
                  <div>
                    <label className="font-medium text-[#1A1A1A] block mb-1.5">Length (Bytes)</label>
                    <select
                      value={randomLen}
                      onChange={(e) => setRandomLen(parseInt(e.target.value, 10))}
                      className="w-full h-9 rounded-lg border border-[#E9EDE7] bg-white px-3 text-xs text-[#1A1A1A] focus:outline-none focus:border-[#008031]"
                    >
                      <option value={16}>16 Bytes (128 bits - Nonces / Salts)</option>
                      <option value={24}>24 Bytes (192 bits)</option>
                      <option value={32}>32 Bytes (256 bits - Standard Key Size)</option>
                      <option value={64}>64 Bytes (512 bits - High Entropy)</option>
                    </select>
                  </div>
                  <div>
                    <label className="font-medium text-[#1A1A1A] block mb-1.5">Output Format</label>
                    <select
                      value={randomEncoding}
                      onChange={(e) => setRandomEncoding(e.target.value as any)}
                      className="w-full h-9 rounded-lg border border-[#E9EDE7] bg-white px-3 text-xs text-[#1A1A1A] focus:outline-none focus:border-[#008031]"
                    >
                      <option value="hex">Hexadecimal</option>
                      <option value="base64">Base64</option>
                    </select>
                  </div>
                </div>

                <Button
                  onClick={handleRunRandom}
                  disabled={loading}
                  className="bg-[#008031] hover:bg-[#006e2a] text-white text-xs h-9 px-4"
                >
                  {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : <Sparkles className="w-3.5 h-3.5 mr-1.5" />}
                  Generate Secure Random Bytes
                </Button>
              </>
            )}
          </CardContent>
        </Card>

        {/* Right 1 Col: Live Cryptographic Telemetry Panel */}
        <Card className="flex flex-col bg-white">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold text-[#1A1A1A] flex items-center gap-1.5">
                <Cpu className="w-4 h-4 text-[#008031]" />
                <span>Engine Telemetry</span>
              </CardTitle>
              <Badge variant="outline" className="text-[10px] text-[#008031] bg-[#EAF3EC] border-[#C8E0CF]">
                Verified
              </Badge>
            </div>
            <CardDescription className="text-xs text-[#636863]">
              Real-time cryptographic execution outputs and timing telemetry.
            </CardDescription>
          </CardHeader>

          <CardContent className="flex-1 flex flex-col justify-between space-y-4 text-xs">
            <div className="p-3.5 rounded-xl border border-[#E9EDE7] bg-[#1A1A1A] text-[#E0E0E0] font-mono text-[11px] leading-relaxed break-all space-y-3 min-h-[220px]">
              {tab === "hash" && hashResult && (
                <>
                  <div className="text-emerald-400 font-semibold text-[10px]">
                    ALGORITHM: {hashAlg} ({hashResult.byteLength} bytes)
                  </div>
                  <div>{hashResult.digest}</div>
                  <div className="text-gray-400 text-[10px] pt-2 border-t border-gray-800">
                    Execution Timing: {hashResult.timingMs}ms
                  </div>
                </>
              )}

              {tab === "hmac" && hmacResult && (
                <>
                  <div className="text-emerald-400 font-semibold text-[10px]">
                    MAC DIGEST ({hmacAlg})
                  </div>
                  <div>{hmacResult.mac}</div>
                  <div className="text-gray-400 text-[10px] pt-2 border-t border-gray-800 flex justify-between">
                    <span>Constant-Time Verification:</span>
                    <span className="text-emerald-400 font-bold">{hmacResult.verified ? "VERIFIED (100%)" : "FAILED"}</span>
                  </div>
                </>
              )}

              {tab === "encrypt" && encEnvelope && (
                <>
                  <div className="text-emerald-400 font-semibold text-[10px]">
                    ENVELOPE (v{encEnvelope.v} {encEnvelope.alg})
                  </div>
                  <div>
                    <span className="text-gray-400">IV: </span>{encEnvelope.iv}
                  </div>
                  <div>
                    <span className="text-gray-400">Tag: </span>{encEnvelope.tag}
                  </div>
                  <div>
                    <span className="text-gray-400">Ciphertext: </span>{encEnvelope.ct}
                  </div>
                  {decryptedText && (
                    <div className="pt-2 border-t border-gray-800 text-emerald-300">
                      <span className="text-gray-400">Decrypted: </span>{decryptedText}
                    </div>
                  )}
                </>
              )}

              {tab === "sign" && signSignature && (
                <>
                  <div className="text-emerald-400 font-semibold text-[10px]">
                    ED25519 SIGNATURE (64 bytes)
                  </div>
                  <div>{signSignature}</div>
                  <div className="text-gray-400 text-[10px] pt-2 border-t border-gray-800 flex justify-between">
                    <span>Signature Verification:</span>
                    <span className="text-emerald-400 font-bold">{verifyStatus ? "VALID (RFC 8032)" : "INVALID"}</span>
                  </div>
                </>
              )}

              {tab === "key_agreement" && aliceSecret && bobSecret && (
                <>
                  <div className="text-emerald-400 font-semibold text-[10px]">
                    X25519 SHARED SECRET (32 bytes)
                  </div>
                  <div>
                    <span className="text-gray-400">Alice derived: </span>{aliceSecret}
                  </div>
                  <div>
                    <span className="text-gray-400">Bob derived: </span>{bobSecret}
                  </div>
                  <div className="text-gray-400 text-[10px] pt-2 border-t border-gray-800 flex justify-between">
                    <span>Secrets Match:</span>
                    <span className="text-emerald-400 font-bold">
                      {aliceSecret === bobSecret ? "EXACT MATCH (100%)" : "MISMATCH"}
                    </span>
                  </div>
                </>
              )}

              {tab === "random" && randomOutput && (
                <>
                  <div className="text-emerald-400 font-semibold text-[10px]">
                    CSPRNG OUTPUT ({randomLen} bytes / {randomEncoding})
                  </div>
                  <div>{randomOutput}</div>
                </>
              )}

              {!hashResult && !hmacResult && !encEnvelope && !signSignature && !aliceSecret && !randomOutput && (
                <div className="h-full flex items-center justify-center text-gray-500 text-center text-xs">
                  Select parameters and click the execute button to run real cryptographic operations.
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-[#E9EDE7] flex items-center justify-between text-[11px] text-[#636863]">
              <span>Hardware Acceleration: OpenSSL ASM</span>
              <span className="text-emerald-600 font-medium">Constant-Time Mode</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
