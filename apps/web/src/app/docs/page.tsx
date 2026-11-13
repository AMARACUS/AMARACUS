"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { PublicHeader } from "@/components/public-header";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { PublicFooter } from "@/components/public-footer";
import { CodeBlock } from "@/components/ui/code-block";
import { Badge } from "@/components/ui/badge";
import { CryptoPlayground } from "@/components/crypto-playground";
import { API_BASE_URL } from "@/lib/api-base";
import { DocsPlanNote, DocsBillingFact } from "@/components/cloud/docs-copy";
import { 
  BookOpen, 
  Key, 
  Shield, 
  Terminal, 
  ArrowRight, 
  Lock, 
  Cpu, 
  FileCode, 
  HelpCircle, 
  Building2, 
  Users, 
  Zap, 
  Activity, 
  CreditCard, 
  CheckCircle2,
  RefreshCw,
  Bot,
  Sparkles 
} from "lucide-react";

export default function DocsPage() {
  const [activeTab, setActiveTab] = useState<"plain-english" | "developer">("plain-english");

  useEffect(() => {
    if (typeof window !== "undefined" && window.location.hash) {
      const devHashes = [
        "#universal-api-guide",
        "#authentication",
        "#quickstart",
        "#pqc",
        "#managed-ops",
        "#health-probes",
        "#webhooks-api",
        "#migration-api",
        "#os-api",
        "#intelligence-api",
        "#compliance-api",
        "#tutorial-developer",
        "#ai-prompting"
      ];
      if (devHashes.includes(window.location.hash)) {
        setActiveTab("developer");
      }
    }
  }, []);

  return (
    <div className="min-h-screen flex flex-col bg-[#F8F7F4]">
      <PublicHeader />
      <Breadcrumbs items={[{ name: "Documentation", path: "/docs/" }]} />

      <div className="flex-1 max-w-6xl w-full mx-auto px-6 py-10 flex flex-col md:flex-row gap-10">
        {/* Docs Sidebar */}
        <aside className="w-full md:w-64 shrink-0 space-y-6">
          {/* Mode Switcher */}
          <div className="p-3 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
            <span className="text-[11px] font-bold uppercase tracking-wider text-[#767676]">Reading Mode</span>
            <div className="grid grid-cols-2 gap-1.5 p-1 bg-[#F8F7F4] rounded-lg text-xs font-semibold">
              <button
                onClick={() => setActiveTab("plain-english")}
                className={`py-1.5 px-2 rounded-md transition-all text-center ${
                  activeTab === "plain-english" ? "bg-white text-[#008031] shadow-xs" : "text-[#767676] hover:text-[#1A1A1A]"
                }`}
              >
                User Guide
              </button>
              <button
                onClick={() => setActiveTab("developer")}
                className={`py-1.5 px-2 rounded-md transition-all text-center ${
                  activeTab === "developer" ? "bg-white text-[#008031] shadow-xs" : "text-[#767676] hover:text-[#1A1A1A]"
                }`}
              >
                Developer API
              </button>
            </div>
          </div>

          <div className={activeTab === "plain-english" ? "" : "hidden"}>
            <div className="space-y-4">
              <div className="pb-4 border-b border-[#E9EDE7]">
                <span className="text-xs font-bold uppercase tracking-wider text-[#767676]">User Manual</span>
                <ul className="mt-3 space-y-1 text-sm font-medium">
                  <li><Link href="#analogy" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">The Bank Vault Analogy</Link></li>
                  <li><Link href="#universal-guide" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#008031] font-semibold flex items-center gap-1.5"><span>⚡</span> Universal Integration Guide</Link></li>
                  <li><Link href="#orgs-projects" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Projects & Environments</Link></li>
                  <li><Link href="#roles" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Team Roles & Permissions</Link></li>
                  <li><Link href="#api-keys" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">API Keys (Digital Badges)</Link></li>
                  <li><Link href="#workbench" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Cryptography Playground</Link></li>
                  <li><Link href="#rotation" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Key Management & HSMs</Link></li>
                  <li><Link href="#policies-simple" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Security Rulebooks (Policies)</Link></li>
                  <li><Link href="#pqc-simple" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Post-Quantum Cryptography</Link></li>
                  <li><Link href="#posture-score" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Health Score & CBOM</Link></li>
                  <li><Link href="#audit-simple" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Audit Logs (Black Box)</Link></li>
                  <li><Link href="#production-infra" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Global Production & Reliability</Link></li>
                  <li><Link href="#ecosystem-simple" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Connecting Apps & Webhooks</Link></li>
                  <li><Link href="#migration-simple" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Cryptographic Migration</Link></li>
                  <li><Link href="#os-simple" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Cryptographic Control Plane</Link></li>
                  <li><Link href="#intelligence-simple" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Cryptographic Intelligence</Link></li>
                  <li><Link href="#compliance-simple" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Trust, Compliance & Assurance</Link></li>
                  <li><Link href="#tutorial-simple" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#008031] font-semibold flex items-center gap-1.5"><span>★</span> Step-by-Step Tutorial</Link></li>
                  <li><Link href="#ai-prompting-simple" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#008031] font-semibold flex items-center gap-1.5"><span>🤖</span> AI Prompts &amp; Workflows</Link></li>
                </ul>
              </div>
            </div>
          </div>
          <div className={activeTab === "developer" ? "" : "hidden"}>
            <div className="space-y-4">
              <div className="pb-4 border-b border-[#E9EDE7]">
                <span className="text-xs font-bold uppercase tracking-wider text-[#767676]">API Reference</span>
                <ul className="mt-3 space-y-1 text-sm font-medium">
                  <li><Link href="#universal-api-guide" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#008031] font-semibold flex items-center gap-1.5"><span>⚡</span> Universal API Quickstart</Link></li>
                  <li><Link href="#crypto-playground" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#008031] font-semibold flex items-center gap-1.5"><span>✨</span> Live Crypto Playground</Link></li>
                  <li><Link href="#authentication" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Authentication</Link></li>
                  <li><Link href="#quickstart" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Quickstart: Encryption</Link></li>
                  <li><Link href="#pqc" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Post-Quantum KEM</Link></li>
                  <li><Link href="#managed-ops" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Managed Operations</Link></li>
                  <li><Link href="#health-probes" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Probes & Prometheus Metrics</Link></li>
                  <li><Link href="#webhooks-api" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Webhooks & SDK Adapters</Link></li>
                  <li><Link href="#migration-api" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Migration Platform</Link></li>
                  <li><Link href="#os-api" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Control Plane & Workflows</Link></li>
                  <li><Link href="#intelligence-api" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Intelligence & Optimization</Link></li>
                  <li><Link href="#compliance-api" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#555555]">Trust, Compliance & Assurance</Link></li>
                  <li><Link href="#tutorial-developer" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#008031] font-semibold flex items-center gap-1.5"><span>★</span> End-to-End Dev Tutorial</Link></li>
                  <li><Link href="#ai-prompting" className="block px-3 py-1.5 rounded-md hover:bg-white text-[#008031] font-semibold flex items-center gap-1.5"><span>🤖</span> Implementing with AI &amp; LLMs</Link></li>
                </ul>
              </div>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 min-w-0 max-w-3xl space-y-12">
          <div className={activeTab === "plain-english" ? "" : "hidden"}>
            <div className="space-y-10">
              <section id="analogy" className="space-y-4">
                <div className="flex items-center gap-2 text-xs text-[#767676]">
                  <span>User Guide</span>
                  <span>/</span>
                  <span className="text-[#008031] font-medium">The Bank Vault Analogy</span>
                </div>
                <h1 className="font-editorial text-4xl font-bold text-[#1A1A1A] tracking-tight">
                  What is AMARACUS?
                </h1>
                <p className="text-base text-[#555555] leading-relaxed">
                  Imagine your company owns valuable secrets—customer payment records, medical files, and confidential designs. In most companies, developers build their own locks and hide keys in random file drawers. If a key is lost or stolen, customer data is compromised.
                </p>
                <div className="p-5 bg-white border border-[#E9EDE7] rounded-xl space-y-3">
                  <h3 className="font-semibold text-sm text-[#1A1A1A] flex items-center gap-2">
                    <Shield className="w-4 h-4 text-[#008031]" /> AMARACUS is your Central Automated Bank Vault
                  </h3>
                  <ul className="text-xs text-[#636863] space-y-2 list-disc pl-5">
                    <li><strong>Standardized High-Security Locks:</strong> Instead of inventing locks, AMARACUS provides standardized NIST-approved AES-256-GCM, ChaCha20-Poly1305, and FIPS 203 ML-KEM algorithms out of the box.</li>
                    <li><strong>Key Protection:</strong> Managed keys are stored encrypted under an AMARACUS platform master key and never returned by the API. If you need keys held in hardware you control, bring your own Azure Key Vault or Managed HSM (preview).</li>
                    <li><strong>Automated Security Guards:</strong> AMARACUS checks company rulebooks (Policies) before allowing anyone to lock or unlock data.</li>
                    <li><strong>Immutable Flight Recorder:</strong> Every lock, key, and action is permanently recorded in an unalterable audit log.</li>
                  </ul>
                </div>
              </section>

              <section id="universal-guide" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-[#EAF3EC] text-[#008031] border border-[#C8E0CF]">Universal Architecture</span>
                  <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                    <Zap className="w-5 h-5 text-[#008031]" /> Universal Cryptographic Integration Guide
                  </h2>
                </div>
                <p className="text-sm text-[#555555] leading-relaxed">
                  How any modern platform, AI ecosystem (e.g. Gemini, OpenAI), fintech, or healthcare application secures passwords, conversations, and customer records using AMARACUS in 4 simple steps:
                </p>

                <div className="space-y-3">
                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-[#008031]" /> Step 1: Create a Dedicated Project in AMARACUS
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      Every sensitive data domain gets its own isolated project boundary. For example, create <strong>&ldquo;User Passwords&rdquo;</strong> for credential hashing and <strong>&ldquo;AI Chat Conversations&rdquo;</strong> for message encryption. This enforces strict multi-tenant isolation so that billing allowances, audit trails, and security keys remain segregated by project.
                    </p>
                  </div>

                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                      <Key className="w-4 h-4 text-[#008031]" /> Step 2: Issue an API Credential (Digital Security Badge)
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      Navigate to <strong>Build → API Credentials</strong> and generate a secret key (e.g. <code className="bg-[#F3F4F6] px-1 py-0.5 rounded text-[11px] font-mono">am_live_a1b2c3d4...</code>). Copy and save this credential in your server environment variables (<code className="bg-[#F3F4F6] px-1 py-0.5 rounded text-[11px] font-mono">AMARACUS_API_KEY</code>). Client web browsers never see this key.
                    </p>
                  </div>

                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                      <Shield className="w-4 h-4 text-[#008031]" /> Step 3: Choose the Right Cryptographic Pattern
                    </h3>
                    <div className="text-xs text-[#555555] space-y-2 leading-relaxed">
                      <div className="p-2.5 bg-[#F8F7F4] rounded-lg border border-[#E9EDE7]">
                        <strong className="text-[#1A1A1A] block mb-1">A. For Passwords (One-Way Hashing):</strong>
                        <span>Passwords must NEVER be reversibly encrypted. AMARACUS does not offer password hashing: hash passwords in your own server with a password-hashing library (Argon2id, scrypt or bcrypt) and a unique random salt. Do not use the SHA-2/SHA-3 hash endpoint for passwords; it is too fast to resist guessing.</span>
                      </div>
                      <div className="p-2.5 bg-[#F8F7F4] rounded-lg border border-[#E9EDE7]">
                        <strong className="text-[#1A1A1A] block mb-1">B. For Chat Transcripts & PII (Envelope Encryption):</strong>
                        <span>For large payloads, generate a random 256-bit Data Encryption Key (DEK) in your server, encrypt the data locally with AES-256-GCM, and send only the DEK to AMARACUS <code className="font-mono text-[11px]">POST /v1/encrypt</code> with a managed key. Store the returned envelope next to your ciphertext and unwrap it with <code className="font-mono text-[11px]">POST /v1/decrypt</code> when you need to read the data.</span>
                      </div>
                      <div className="p-2.5 bg-[#F8F7F4] rounded-lg border border-[#E9EDE7]">
                        <strong className="text-[#1A1A1A] block mb-1">C. For Audit Records & Autonomous AI (Digital Signatures):</strong>
                        <span>Stamp critical system actions, agent choices, or contracts using Ed25519 digital signatures. Verifiers can confirm the author without ever accessing secret signing keys.</span>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-[#008031]" /> Step 4: Call the Universal API in Your Codebase
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      Whether your backend is written in TypeScript, Python, Go, Java, or Rust, interact with the AMARACUS REST API or official SDK with just 5 lines of code. Every operation is recorded in your organization&apos;s audit log.
                    </p>
                  </div>
                </div>
              </section>

              <section id="orgs-projects" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                  <Building2 className="w-5 h-5 text-[#008031]" /> Projects & Environments
                </h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  A <strong>Project</strong> represents an application or business unit (such as <em>Billing Service</em> or <em>Customer App</em>). Each Project contains three isolated rooms:
                </p>
                <div className="grid sm:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 bg-white border border-[#E9EDE7] rounded-lg">
                    <span className="font-semibold text-[#1A1A1A] block mb-1">1. Development</span>
                    <p className="text-[#767676]">The engineering workshop. Safe to test prototypes without touching real customer data.</p>
                  </div>
                  <div className="p-3 bg-white border border-[#E9EDE7] rounded-lg">
                    <span className="font-semibold text-[#1A1A1A] block mb-1">2. Staging</span>
                    <p className="text-[#767676]">The dress-rehearsal room where systems are verified right before going live.</p>
                  </div>
                  <div className="p-3 bg-white border border-[#E9EDE7] rounded-lg">
                    <span className="font-semibold text-[#1A1A1A] block mb-1">3. Production</span>
                    <p className="text-[#767676]">The live, real-world system. Live customer data lives strictly inside this environment.</p>
                  </div>
                </div>
                <p className="text-xs text-[#767676] italic">
                  <DocsPlanNote />
                </p>
              </section>

              <section id="roles" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                  <Users className="w-5 h-5 text-[#008031]" /> Team Roles & Permissions
                </h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  AMARACUS follows the principle of <em>least privilege</em>—employees only get access to what they need for their job:
                </p>
                <div className="space-y-2 text-xs">
                  <div className="p-2.5 bg-white border border-[#E9EDE7] rounded-lg flex justify-between items-center">
                    <div><strong>Owner & Admin:</strong> Complete governance, inviting team members, managing company settings.</div>
                    <Badge variant="outline">Executive</Badge>
                  </div>
                  <div className="p-2.5 bg-white border border-[#E9EDE7] rounded-lg flex justify-between items-center">
                    <div><strong>Security Admin:</strong> Creates security rules, rotates keys, inspects cryptographic posture.</div>
                    <Badge variant="outline">Security</Badge>
                  </div>
                  <div className="p-2.5 bg-white border border-[#E9EDE7] rounded-lg flex justify-between items-center">
                    <div><strong>Developer:</strong> Generates API keys, encrypts and decrypts application data.</div>
                    <Badge variant="outline">Engineering</Badge>
                  </div>
                  <div className="p-2.5 bg-white border border-[#E9EDE7] rounded-lg flex justify-between items-center">
                    <div><strong>Auditor:</strong> Read-only access to audit logs, compliance reports, and security scores.</div>
                    <Badge variant="outline">Compliance</Badge>
                  </div>
                  <div className="p-2.5 bg-white border border-[#E9EDE7] rounded-lg flex justify-between items-center">
                    <div><strong>Billing Admin:</strong> Manages subscription plans, invoices, and spending limits.</div>
                    <Badge variant="outline">Finance</Badge>
                  </div>
                </div>
              </section>

              <section id="api-keys" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                  <Key className="w-5 h-5 text-[#008031]" /> API Keys (Digital Security Badges)
                </h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  Software systems use API keys instead of passwords. To protect against leaks, AMARACUS displays the secret key <strong>only once</strong> when you create it. After that, it is permanently concealed.
                </p>
                <p className="text-xs text-[#767676]">
                  Navigate to <strong>Build → API Credentials</strong> to create and manage digital badges.
                </p>
              </section>

              <section id="workbench" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                  <Zap className="w-5 h-5 text-[#008031]" /> Cryptography Playground
                </h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  Test real digital locks without writing code! Go to <strong>Build → Cryptography Playground</strong>:
                </p>
                <ul className="text-xs text-[#555555] space-y-1.5 list-disc pl-5">
                  <li><strong>Encrypt / Decrypt:</strong> Scramble text into an authenticated ciphertext envelope and unlock it back.</li>
                  <li><strong>Hash:</strong> Generate an unforgeable 64-character digital fingerprint of any message.</li>
                  <li><strong>Digital Signatures:</strong> Put an unforgeable digital wax seal on approvals and contracts.</li>
                </ul>
              </section>

              <section id="rotation" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                  <Lock className="w-5 h-5 text-[#008031]" /> Key Management & Automatic Rotation
                </h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  Security standards require encryption keys to be rotated every 90 days. When you rotate a key in AMARACUS:
                </p>
                <ul className="text-xs text-[#555555] space-y-1.5 list-disc pl-5">
                  <li>New data is automatically encrypted with <strong>Version 2</strong>.</li>
                  <li>Historical data previously encrypted with Version 1 still decrypts safely because the historical version chain is preserved.</li>
                  <li>Zero private key material is ever exposed to the web browser.</li>
                </ul>
              </section>

              <section id="pqc-simple" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                  <Cpu className="w-5 h-5 text-[#008031]" /> Post-Quantum Cryptography (PQC)
                </h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  Future quantum computers will be able to crack traditional mathematical locks (like RSA). AMARACUS includes the new 2024 NIST-approved quantum-resistant algorithms: <strong>ML-KEM</strong> (for encryption) and <strong>ML-DSA</strong> (for signatures). You can inspect them in <strong>Cryptography → Algorithm Registry</strong>.
                </p>
              </section>

              <section id="posture-score" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                  <Activity className="w-5 h-5 text-[#008031]" /> Health Score & CBOM
                </h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  Go to <strong>Cryptography → Crypto Intelligence & CBOM</strong> to view your company&apos;s security credit score (from 0 to 100). The dashboard alerts you if keys are overdue for rotation, if certificates are expiring soon, or if any outdated algorithms are detected.
                </p>
              </section>

              <section id="production-infra" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                  <Activity className="w-5 h-5 text-[#008031]" /> Global Production & 24/7 Reliability
                </h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  How AMARACUS stays online, resilient, and fast at massive scale without losing your data or slowing down:
                </p>
                <div className="space-y-3">
                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-[#008031]" /> 24/7 High Availability (No Single Point of Failure)
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      AMARACUS runs across multiple duplicate servers and data centers. If one machine crashes, the others take over traffic instantly without dropping a single user request.
                    </p>
                  </div>

                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <Zap className="w-4 h-4 text-[#008031]" /> Self-Healing Background Jobs (Zombie Recovery)
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      If an unexpected server reboot happens right in the middle of a large cryptographic operation, our automated recovery watchdog detects the abandoned task within 60 seconds and smoothly restarts or rescues it, ensuring zero lost tasks.
                    </p>
                  </div>

                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <Shield className="w-4 h-4 text-[#008031]" /> Provider Circuit Breakers (Overload Protection)
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      Just like the electrical circuit breaker in your house protects against power surges, AMARACUS monitors cloud providers (like Azure Key Vault or Hardware Security Modules). If an upstream provider throttles requests, the circuit breaker protects the system from traffic pile-ups and safely fails over.
                    </p>
                  </div>

                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <Lock className="w-4 h-4 text-[#008031]" /> Rolling Deployment Architecture
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      Whenever we release security updates or new cryptographic algorithms, the new version launches alongside the existing version and verifies health checks before retiring the old one to minimize maintenance disruptions.
                    </p>
                  </div>
                </div>
              </section>

              <section id="ecosystem-simple" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                  <Zap className="w-5 h-5 text-[#008031]" /> Connecting Your Apps & Webhooks
                </h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  How AMARACUS easily talks to your websites, databases, internal company tools, and partner apps:
                </p>
                <div className="space-y-3">
                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-[#008031]" /> The Walkie-Talkie (What are Webhooks?)
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      Instead of having your website constantly refresh and ask: <em>&ldquo;Is the encryption job finished yet?&rdquo;</em>, webhooks are like a private walkie-talkie. The exact millisecond a key rotates, a contract is signed, or an alert triggers, AMARACUS rings your app instantly with the result.
                    </p>
                  </div>

                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <Shield className="w-4 h-4 text-[#008031]" /> The Unforgeable Wax Seal (HMAC Signatures)
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      How does your system know a notification genuinely came from AMARACUS and not a hacker? AMARACUS stamps each notification with a mathematical wax seal (an HMAC signature). If anyone tries to alter the data or replay an old message, the seal breaks and your system safely ignores it.
                    </p>
                  </div>

                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <FileCode className="w-4 h-4 text-[#008031]" /> Pre-Built Adapters for Express & Next.js
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      Your engineers don&apos;t have to write hundreds of lines of glue code. We provide ready-to-use plug-and-play middleware for popular web frameworks like Express and Next.js that verify notifications and process security events in just 3 lines of code.
                    </p>
                  </div>

                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <Lock className="w-4 h-4 text-[#008031]" /> Safe Storefront Rule (Zero Browser Key Exposure)
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      Think of your website frontend like a store display window. You would never leave the master vault keys inside the shop window where passersby can grab them! AMARACUS enforces that master keys only live inside private, secured servers—never inside client web browsers.
                    </p>
                  </div>
                </div>
              </section>

              <section id="migration-simple" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                  <RefreshCw className="w-5 h-5 text-[#008031]" /> Cryptographic Migration Platform
                </h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  How AMARACUS helps your company smoothly upgrade older security locks, retire compromised keys, and transition to Post-Quantum cryptography without disrupting business:
                </p>
                <div className="space-y-3">
                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-[#008031]" /> The Analogy: Upgrading Locks While the Bank Stays Open
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      Imagine a bank deciding to replace all its mechanical combination locks with biometric scanners. You can&apos;t just shut down the bank, lock customers out of their safety deposit boxes, or throw away the old keys before verifying the new locks work. AMARACUS handles cryptographic upgrades the same way: new data gets locked with the modern locks, but the bank can still open every historical safety deposit box without interruption.
                    </p>
                  </div>

                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <Shield className="w-4 h-4 text-[#008031]" /> The Three Categories of Responsibility
                    </h3>
                    <div className="text-xs text-[#555555] space-y-1.5 leading-relaxed">
                      <p>AMARACUS is completely transparent about what can be automated versus what needs human attention:</p>
                      <ul className="list-disc pl-4 space-y-1">
                        <li><strong>Category A (AMARACUS-Managed Vaults):</strong> Keys and certificates stored directly in AMARACUS. We can rotate keys and create Post-Quantum pairs; older key versions stay available for decryption.</li>
                        <li><strong>Category B (Connected Systems):</strong> External tools connected via our SDK or webhooks. AMARACUS provisions the new keys and notifies your systems, but your engineers approve the final switch.</li>
                        <li><strong>Category C (Your Own Code & Databases):</strong> Legacy code running on your private servers. We scan your inventory, generate step-by-step instructions, and flag weaknesses, but we never touch or alter your proprietary source code without you.</li>
                      </ul>
                    </div>
                  </div>

                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <Lock className="w-4 h-4 text-[#008031]" /> Never Throw Away the Old Key (Safe Reversibility)
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      When a key is migrated, AMARACUS marks it as &ldquo;Retired for New Encryption&rdquo; rather than deleting it. That means you can always decrypt historical customer records or verify past signatures. And if you ever need to rollback a migration, AMARACUS switches back to the previous key instantly with a single click.
                    </p>
                  </div>

                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <Users className="w-4 h-4 text-[#008031]" /> The Four-Eyes Rule (Separation of Duties)
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      To prevent mistakes or unauthorized sabotage, AMARACUS strictly enforces that the person who designs or proposes a migration plan cannot be the one who approves it for production. A second authorized security officer must inspect the plan and give the green light.
                    </p>
                  </div>
                </div>
              </section>

              <section id="os-simple" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                  <Cpu className="w-5 h-5 text-[#008031]" /> Cryptographic Control Plane
                </h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  How AMARACUS acts as the unified central operating cockpit for all your enterprise keys, certificates, cloud vaults, policies, and migrations:
                </p>
                <div className="space-y-3">
                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-[#008031]" /> The Analogy: The Conductor of the Symphony Orchestra
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      In a large enterprise, cryptography is like a symphony orchestra with dozens of instruments: one team manages Azure Key Vault, another provisions web server SSL certificates, a compliance team writes security policies, and application developers encrypt customer databases. If everyone plays independently, you get deafening noise and security gaps. AMARACUS is the conductor at the podium—ensuring every key, certificate, and cloud vault plays in perfect harmony according to your organizational score.
                    </p>
                  </div>

                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <Shield className="w-4 h-4 text-[#008031]" /> Verified vs. Inferred Inventory (No Guesswork)
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      Other security tools make guesses based on vague network traffic. AMARACUS clearly distinguishes between <strong>Verified Resources</strong> (keys and certificates stored in AMARACUS or in your connected vault) and <strong>Inferred Resources</strong> (third-party client apps spotted in logs). You always know exactly what is real and what requires investigation.
                    </p>
                  </div>

                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <Users className="w-4 h-4 text-[#008031]" /> Four-Eyes Workflow Governance
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      High-impact actions—like rotating a database encryption key or retiring a root certificate—can never be performed by a single person in production. AMARACUS enforces that the security engineer who drafts a workflow cannot self-approve it. A second authorized security officer must inspect and sign off before execution begins.
                    </p>
                  </div>

                  <div className="p-3.5 bg-white border border-[#E9EDE7] rounded-xl space-y-1">
                    <h3 className="text-sm font-bold text-[#1A1A1A] flex items-center gap-2">
                      <Zap className="w-4 h-4 text-[#008031]" /> Controlled Automation (Safe & Reversible)
                    </h3>
                    <p className="text-xs text-[#555555] leading-relaxed">
                      Instead of dangerous &ldquo;autonomous bots&rdquo; that might unexpectedly break production, AMARACUS uses controlled, observable automation. It continuously monitors certificate expiration dates and key ages, queueing alerts and pre-staged renewal workflows for human review well before deadlines arrive.
                    </p>
                  </div>
                </div>
              </section>

              <section id="tutorial-simple" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-[#E8F5E9] text-[#008031] border border-[#C8E6C9]">Interactive Guide</span>
                  <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                    <BookOpen className="w-5 h-5 text-[#008031]" /> Step-by-Step Tutorial: Managing Migrations & The Cryptographic OS
                  </h2>
                </div>
                <p className="text-sm text-[#555555] leading-relaxed">
                  A beginner-friendly, non-technical walkthrough for business leaders, security officers, and operations managers. Follow this 8-step tutorial to discover your security locks, upgrade an older key to quantum-resistant standards, and observe automated watchdogs:
                </p>

                <div className="space-y-4 mt-2">
                  {/* Step 1 */}
                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-6 h-6 rounded-full bg-[#008031] text-white flex items-center justify-center text-xs font-bold shrink-0">1</span>
                      <h3 className="text-sm font-bold text-[#1A1A1A]">Discover What Security Locks You Own (Unified Inventory)</h3>
                    </div>
                    <p className="text-xs text-[#555555] leading-relaxed pl-8">
                      Click <strong>Cryptographic Inventory</strong> in the left sidebar. AMARACUS gathers every single key, TLS certificate, cloud vault (like Azure Key Vault or Hardware Security Modules), and algorithm rule into one single list.
                    </p>
                    <div className="ml-8 p-2.5 bg-[#F8F7F4] rounded-lg text-xs text-[#666666] space-y-1">
                      <p><strong>Look for the Badges:</strong></p>
                      <p><span className="text-[#008031] font-semibold">● Verified (Green):</span> We have confirmed this key directly inside your hardware vault or database.</p>
                      <p><span className="text-[#E65100] font-semibold">● Inferred (Yellow):</span> We spotted an older system talking to your servers, so we flagged it for your team to double-check without making assumptions.</p>
                    </div>
                  </div>

                  {/* Step 2 */}
                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-6 h-6 rounded-full bg-[#008031] text-white flex items-center justify-center text-xs font-bold shrink-0">2</span>
                      <h3 className="text-sm font-bold text-[#1A1A1A]">Check Your Security Health Score (Posture Overview)</h3>
                    </div>
                    <p className="text-xs text-[#555555] leading-relaxed pl-8">
                      Navigate to <strong>Cryptographic Posture</strong>. You will see an overall health score (e.g. <strong>92 / 100</strong>) and a Post-Quantum readiness percentage.
                    </p>
                    <p className="text-xs text-[#555555] leading-relaxed pl-8">
                      Below the score, AMARACUS lists <em>Deduplicated Findings</em>. If three different servers report that a customer data key is over 90 days old, AMARACUS merges them into one single actionable alert: <em>&ldquo;Key Exceeds 90-Day Rotation Policy (Deduction: -5 pts)&rdquo;</em>.
                    </p>
                  </div>

                  {/* Step 3 */}
                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-6 h-6 rounded-full bg-[#008031] text-white flex items-center justify-center text-xs font-bold shrink-0">3</span>
                      <h3 className="text-sm font-bold text-[#1A1A1A]">Create a Migration Upgrade Plan (Upgrading to Post-Quantum)</h3>
                    </div>
                    <p className="text-xs text-[#555555] leading-relaxed pl-8">
                      Next to the finding, click <strong>Create Migration Plan</strong>. Give your plan a name (e.g., <em>&ldquo;Upgrade Customer Database to ML-KEM-768&rdquo;</em>).
                    </p>
                    <p className="text-xs text-[#555555] leading-relaxed pl-8">
                      Select your target algorithm: <strong>ML-KEM-768</strong> (the official NIST quantum-resistant standard). AMARACUS automatically classifies your target into <strong>Category A</strong> (Directly Managed by AMARACUS), meaning our engine can automate the rotation safely.
                    </p>
                  </div>

                  {/* Step 4 */}
                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-6 h-6 rounded-full bg-[#008031] text-white flex items-center justify-center text-xs font-bold shrink-0">4</span>
                      <h3 className="text-sm font-bold text-[#1A1A1A]">Run a &ldquo;Test Flight&rdquo; (Dry-Run Simulation)</h3>
                    </div>
                    <p className="text-xs text-[#555555] leading-relaxed pl-8">
                      Before touching any production customer records, click <strong>Run Simulation</strong>. AMARACUS performs a dry-run test:
                    </p>
                    <ul className="text-xs text-[#555555] list-disc pl-12 space-y-1">
                      <li>Validates that your cloud provider supports the new key structure.</li>
                      <li>Ensures your company security policies allow this upgrade.</li>
                      <li>Validates that the plan supports deterministic rollback mechanisms if issues arise.</li>
                    </ul>
                  </div>

                  {/* Step 5 */}
                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-6 h-6 rounded-full bg-[#008031] text-white flex items-center justify-center text-xs font-bold shrink-0">5</span>
                      <h3 className="text-sm font-bold text-[#1A1A1A]">Four-Eyes Review & Approval (Two-Person Rule)</h3>
                    </div>
                    <p className="text-xs text-[#555555] leading-relaxed pl-8">
                      If Alice created this plan, she <em>cannot</em> approve it for production. A second authorized team member (like Bob, the CISO or Security Officer) logs into the dashboard, reviews the green simulation checkmark, and clicks <strong>Approve Plan</strong>. The status changes from <em>Awaiting Approval</em> to <em>Ready</em>.
                    </p>
                  </div>

                  {/* Step 6 */}
                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-6 h-6 rounded-full bg-[#008031] text-white flex items-center justify-center text-xs font-bold shrink-0">6</span>
                      <h3 className="text-sm font-bold text-[#1A1A1A]">Execute Cutover with Zero Downtime</h3>
                    </div>
                    <p className="text-xs text-[#555555] leading-relaxed pl-8">
                      With approval granted, click <strong>Execute Migration</strong>. Here is what happens behind the scenes in milliseconds:
                    </p>
                    <ol className="text-xs text-[#555555] list-decimal pl-12 space-y-1">
                      <li>AMARACUS creates the brand-new quantum-resistant key pair.</li>
                      <li>It runs an automatic round-trip test (locking and unlocking sample data) to verify the new lock works.</li>
                      <li>It switches the active key pointer so that all future data gets locked with the modern key.</li>
                      <li><strong>The old key is retired, NOT deleted:</strong> Your historical records can still be read and decrypted with zero data loss.</li>
                    </ol>
                  </div>

                  {/* Step 7 */}
                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-6 h-6 rounded-full bg-[#E65100] text-white flex items-center justify-center text-xs font-bold shrink-0">7</span>
                      <h3 className="text-sm font-bold text-[#1A1A1A]">The &ldquo;Oh No!&rdquo; Button (One-Click Instant Rollback)</h3>
                    </div>
                    <p className="text-xs text-[#555555] leading-relaxed pl-8">
                      What if an old partner integration suddenly cannot handle the new format? Click <strong>Rollback Migration</strong>. AMARACUS immediately flips the active pointer back to the previous key. Zero panic, zero broken databases, zero downtime.
                    </p>
                  </div>

                  {/* Step 8 */}
                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-6 h-6 rounded-full bg-[#008031] text-white flex items-center justify-center text-xs font-bold shrink-0">8</span>
                      <h3 className="text-sm font-bold text-[#1A1A1A]">Relax: Automated Watchdogs Keep Guard</h3>
                    </div>
                    <p className="text-xs text-[#555555] leading-relaxed pl-8">
                      You don&apos;t have to remember expiration dates on a calendar. AMARACUS continuously runs background watchdogs. 30 days before any certificate expires or when a key approaches 90 days of age, you receive an automated notification and a pre-staged renewal workflow ready for one-click approval.
                    </p>
                  </div>
                </div>
              </section>

              <section id="intelligence-simple" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-[#E8F5E9] text-[#008031] border border-[#C8E6C9]">Enterprise Intelligence</span>
                  <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                    <Zap className="w-5 h-5 text-[#008031]" /> Cryptographic Intelligence & Autonomous Optimization
                  </h2>
                </div>
                <p className="text-sm text-[#555555] leading-relaxed">
                  Until now, security teams had to manually track hundreds of keys, certificates, and compliance policies in spreadsheets. AMARACUS Cryptographic Intelligence acts as your <strong>24/7 automated security co-pilot</strong>. It continuously monitors your cloud vaults, flags hidden vulnerabilities, and produces plain-English recommendations backed by hard evidence.
                </p>

                <div className="grid sm:grid-cols-2 gap-4 text-xs">
                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                      <Shield className="w-4 h-4 text-[#008031]" /> 1. Hard Evidence, No Hallucinations
                    </h3>
                    <p className="text-[#666666] leading-relaxed">
                      Every recommendation includes exact verifiable facts: key age in days, days until TLS certificate expiry, cloud circuit-breaker trips, and <DocsBillingFact />. We strictly never guess or fabricate security scores.
                    </p>
                  </div>

                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                      <Lock className="w-4 h-4 text-[#008031]" /> 2. The Four-Eyes Rule (Two-Person Safety)
                    </h3>
                    <p className="text-[#666666] leading-relaxed">
                      AI and automation can propose a fix, but they can <em>never</em> touch your production master keys alone. High-impact operations (like rotating a master key) enforce the Four-Eyes principle: the person who proposes the fix cannot be the person who executes it.
                    </p>
                  </div>

                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                      <Activity className="w-4 h-4 text-[#008031]" /> 3. Test Flights (Dry-Run Impact Analysis)
                    </h3>
                    <p className="text-[#666666] leading-relaxed">
                      Before touching live customer traffic, AMARACUS calculates the blast radius. It verifies that policies allow the change, checks rollback feasibility, and executes migrations designed to avoid customer service interruption.
                    </p>
                  </div>

                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                      <Cpu className="w-4 h-4 text-[#008031]" /> 4. Non-Destructive Key Versioning Policy
                    </h3>
                    <p className="text-[#666666] leading-relaxed">
                      Rotating a key creates a fresh version for subsequent operations. AMARACUS preserves historical key versions so archived backups and historical records remain decryptable.
                    </p>
                  </div>
                </div>
              </section>

              <section id="compliance-simple" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-[#E8F5E9] text-[#008031] border border-[#C8E6C9]">Audit & Assurance</span>
                  <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                    <CheckCircle2 className="w-5 h-5 text-[#008031]" /> Cryptographic Trust, Compliance & Assurance
                  </h2>
                </div>
                <p className="text-sm text-[#555555] leading-relaxed">
                  Compliance should never be a stressful once-a-year scramble. AMARACUS turns cryptographic assurance into a continuous, verifiable process. We map your actual keys, TLS certificates, and policy rules directly to <strong>SOC 2 Type II</strong>, <strong>ISO 27001</strong>, and <strong>NIST standards</strong>.
                </p>
                <p className="text-xs text-[#767676] leading-relaxed">
                  These reports are a self-assessment aid for your own audit preparation, not an audit or certification. AMARACUS itself has not completed a SOC 2 or ISO 27001 audit.
                </p>

                <div className="grid sm:grid-cols-2 gap-4 text-xs">
                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                      <Shield className="w-4 h-4 text-[#008031]" /> 1. Verifiable Cryptographic Evidence
                    </h3>
                    <p className="text-[#666666] leading-relaxed">
                      Every single piece of evidence is hashed using SHA-256 with timestamped chain of custody. Auditors can independently verify that your security logs and key configurations have not been modified or tampered with.
                    </p>
                  </div>

                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                      <Lock className="w-4 h-4 text-[#008031]" /> 2. Zero Private Key Leakage
                    </h3>
                    <p className="text-[#666666] leading-relaxed">
                      Compliance logs must never create new security vulnerabilities. AMARACUS automatically redacts all private key material, tokens, and customer plaintexts before evidence is recorded.
                    </p>
                  </div>

                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                      <Users className="w-4 h-4 text-[#008031]" /> 3. Four-Eyes Exception Governance
                    </h3>
                    <p className="text-[#666666] leading-relaxed">
                      Need a temporary grace period for a legacy banking connection? Request a formal exception with compensating controls and an expiration date. An independent reviewer must sign off—self-approval is strictly prevented.
                    </p>
                  </div>

                  <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                    <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                      <BookOpen className="w-4 h-4 text-[#008031]" /> 4. One-Click Audit Reports (JSON & CSV)
                    </h3>
                    <p className="text-[#666666] leading-relaxed">
                      Export audit-ready evidence sheets in CSV for your GRC platform (Vanta, Drata) or JSON for automated pipeline verifications, complete with cryptographic validation hashes and legal auditor disclaimers.
                    </p>
                  </div>
                </div>
              </section>

              <section id="ai-prompting-simple" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-[#E8F5E9] text-[#008031] border border-[#C8E6C9]">AI &amp; No-Code Builders</span>
                  <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A] flex items-center gap-2">
                    <Bot className="w-5 h-5 text-[#008031]" /> Prompting AI Assistants with AMARACUS
                  </h2>
                </div>
                <p className="text-sm text-[#555555] leading-relaxed">
                  When you ask AI tools (like ChatGPT, Claude, or Cursor) to build an application that handles confidential data, they frequently try to write custom encryption math themselves. This often results in weak passwords, insecure encryption keys, or vulnerabilities that expose private customer records.
                </p>
                <div className="p-4 bg-[#E8F5E9]/50 border border-[#C8E6C9] rounded-xl text-xs text-[#008031] flex items-start gap-3">
                  <Sparkles className="w-5 h-5 shrink-0 mt-0.5" />
                  <div>
                    <strong className="font-semibold block mb-0.5">The Safe Way to Build with AI:</strong>
                    Tell your AI assistant to use <strong>AMARACUS as your digital security vault</strong> instead of writing its own encryption algorithms. This enforces defense-in-depth standards, policy-bound key rotation, and NIST post-quantum algorithm alignments without requiring deep in-house cryptographic engineering.
                  </div>
                </div>

                <div className="space-y-3 pt-2">
                  <h3 className="font-bold text-sm text-[#1A1A1A]">Ready-to-Use Prompts for ChatGPT &amp; Claude</h3>
                  <div className="grid gap-3 text-xs">
                    <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-[#1A1A1A]">Prompt 1: Storing Sensitive User Data Safely</span>
                        <span className="px-2 py-0.5 bg-[#F8F7F4] text-[#767676] rounded text-[10px] font-mono">Database / Forms</span>
                      </div>
                      <p className="p-3 bg-[#F8F7F4] rounded-lg font-mono text-[11px] text-[#333333] border border-[#E9EDE7] select-all">
                        &quot;I am building a web app where users enter sensitive personal data (SSN, medical info, or credit card details). Do NOT write custom encryption functions. Instead, call the AMARACUS API at {API_BASE_URL}/api/v1/crypto/encrypt using our server-side AMARACUS_API_KEY. Show me how to encrypt the data before saving it to my database and how to decrypt it when viewing the profile.&quot;
                      </p>
                    </div>

                    <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-[#1A1A1A]">Prompt 2: Modern Secure Passwords &amp; Login</span>
                        <span className="px-2 py-0.5 bg-[#F8F7F4] text-[#767676] rounded text-[10px] font-mono">Authentication</span>
                      </div>
                      <p className="p-3 bg-[#F8F7F4] rounded-lg font-mono text-[11px] text-[#333333] border border-[#E9EDE7] select-all">
                        &quot;Help me build a user login and signup workflow. Hash passwords locally with Argon2id (the argon2 npm package) and a unique salt; never use MD5, SHA-1 or a plain SHA-256 for passwords. Encrypt sensitive profile fields (phone, address) with AMARACUS: POST {API_BASE_URL}/v1/encrypt with my managed keyId, store the returned envelope, and decrypt with POST /v1/decrypt. Provide a timing-safe login function in TypeScript.&quot;
                      </p>
                    </div>
                  </div>
                </div>

                <div className="pt-2">
                  <button 
                    onClick={() => setActiveTab("developer")}
                    className="inline-flex items-center gap-2 text-xs font-semibold text-[#008031] hover:underline"
                  >
                    View developer .cursorrules and technical system prompts <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </section>
            </div>

          </div>
          <div className={activeTab === "developer" ? "" : "hidden"}>
            <div className="space-y-10">
              <section id="universal-api-guide" className="space-y-4">
                <div className="flex items-center gap-2 text-xs text-[#767676]">
                  <span>Developer Docs</span>
                  <span>/</span>
                  <span className="text-[#008031] font-medium">Universal Integration</span>
                </div>
                <h2 className="font-editorial text-4xl font-bold text-[#1A1A1A] tracking-tight">
                  Universal Cryptographic API Quickstart
                </h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  Integrate AMARACUS into any application, microservice, or AI pipeline (e.g. Google Gemini, user authentication servers, chat platforms, or financial systems) using our universal cryptographic patterns.
                </p>

                <div className="space-y-6">
                  {/* Pattern 1: Passwords */}
                  <div className="space-y-3">
                    <h3 className="text-base font-bold text-[#1A1A1A] flex items-center gap-2">
                      <Lock className="w-4 h-4 text-[#008031]" /> Pattern 1: Encrypting a Sensitive Field with a Managed Key
                    </h3>
                    <p className="text-xs text-[#636863] leading-relaxed">
                      Create a managed key once (dashboard or <code className="font-mono">POST /v1/keys</code>), then encrypt values with it. The response contains an opaque <code className="font-mono">envelope</code> string that carries the ciphertext, IV, tag and key version; store it and pass it back to decrypt. AMARACUS does not hash passwords: use a password-hashing library such as Argon2id in your own server for that.
                    </p>
                    <CodeBlock
                      title="Encrypt / Decrypt (TypeScript / Node.js)"
                      language="typescript"
                      code={`import { Amaracus } from '@amaracus/sdk';

const client = new Amaracus({
  apiKey: process.env.AMARACUS_API_KEY!, // am_live_...
});

// Encrypt: returns an opaque envelope string to store in your database
const { envelope } = await client.encrypt({
  key: process.env.AMARACUS_KEY_ID!, // e.g. "key_ab12cd34"
  data: '+1 555 0100',
});

// Decrypt: pass the envelope back
const { plaintext } = await client.decrypt({
  key: process.env.AMARACUS_KEY_ID!,
  envelope,
});`}
                    />

                    <CodeBlock
                      title="Encrypt / Decrypt (Python, plain HTTP)"
                      language="python"
                      code={`import requests, os

API_KEY = os.getenv("AMARACUS_API_KEY")  # am_live_...
API_URL = os.getenv("AMARACUS_API_URL", "${API_BASE_URL}/v1")
KEY_ID = os.getenv("AMARACUS_KEY_ID")
headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}

enc = requests.post(f"{API_URL}/encrypt", headers=headers,
                    json={"key": KEY_ID, "data": "+1 555 0100"})
envelope = enc.json()["data"]["envelope"]

dec = requests.post(f"{API_URL}/decrypt", headers=headers,
                    json={"key": KEY_ID, "envelope": envelope})
print(dec.json()["data"]["plaintext"])`}
                    />
                  </div>

                  {/* Pattern 2: Envelope Encryption */}
                  <div className="space-y-3 pt-4 border-t border-[#E9EDE7]">
                    <h3 className="text-base font-bold text-[#1A1A1A] flex items-center gap-2">
                      <Shield className="w-4 h-4 text-[#008031]" /> Pattern 2: Sensitive Chats & PII (Envelope Encryption)
                    </h3>
                    <p className="text-xs text-[#636863] leading-relaxed">
                      For large conversation transcripts, medical records, or customer PII, keep the bulk data local: generate a random Data Encryption Key (DEK) in your server, encrypt with AES-256-GCM, and use AMARACUS only to wrap and unwrap the 32-byte DEK with your managed key. There is no separate data-key endpoint; the DEK goes through the normal encrypt/decrypt calls.
                    </p>
                    <CodeBlock
                      title="Envelope Encryption (TypeScript / Node.js)"
                      language="typescript"
                      code={`import { Amaracus } from '@amaracus/sdk';
import crypto from 'crypto';

const client = new Amaracus({ apiKey: process.env.AMARACUS_API_KEY! });
const KEY_ID = process.env.AMARACUS_KEY_ID!;

// 1. Generate a DEK locally and encrypt the transcript with it
const dek = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
const ciphertext = Buffer.concat([cipher.update(transcript, 'utf8'), cipher.final()]);
const tag = cipher.getAuthTag();

// 2. Wrap the DEK with your AMARACUS managed key
const { envelope: wrappedDek } = await client.encrypt({ key: KEY_ID, data: dek });
dek.fill(0);

// Store { wrappedDek, iv, tag, ciphertext } in your database.

// 3. Later: unwrap the DEK and decrypt locally
const { plaintext, encoding } = await client.decrypt({ key: KEY_ID, envelope: wrappedDek });
const recovered = Buffer.from(plaintext, encoding as BufferEncoding); // binary DEKs come back as base64
const decipher = crypto.createDecipheriv('aes-256-gcm', recovered, iv);
decipher.setAuthTag(tag);
const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');`}
                    />
                  </div>
                </div>
              </section>

              <section id="authentication" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <div className="flex items-center gap-2 text-xs text-[#767676]">
                  <span>Developer Docs</span>
                  <span>/</span>
                  <span className="text-[#008031] font-medium">Authentication</span>
                </div>
                <h2 className="font-editorial text-4xl font-bold text-[#1A1A1A] tracking-tight">
                  Developer API Reference
                </h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  Pass your project API key in the <code className="bg-[#EAE8E1] px-1.5 py-0.5 rounded text-xs font-mono">Authorization</code> header:
                </p>
                <CodeBlock
                  title="HTTP Request Header"
                  language="http"
                  code="Authorization: Bearer am_live_9a8b7c6d5e4f3g2h1"
                />
              </section>

              <section className="pt-2">
                <CryptoPlayground />
              </section>

              <section id="quickstart" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A]">Universal Encryption API</h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  Encrypt a value with one of your managed keys. The response&apos;s <code className="font-mono text-[11px]">data.envelope</code> holds everything needed to decrypt it:
                </p>
                <CodeBlock
                  title="curl - Universal Encryption"
                  language="bash"
                  code={`curl -X POST ${API_BASE_URL}/v1/encrypt \\
  -H "Authorization: Bearer am_live_your_key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "key": "key_your_key_id",
    "data": "This is a secret payload"
  }'

# Decrypt: send the envelope back with the same key
curl -X POST ${API_BASE_URL}/v1/decrypt \\
  -H "Authorization: Bearer am_live_your_key" \\
  -H "Content-Type: application/json" \\
  -d '{ "key": "key_your_key_id", "envelope": "<data.envelope from above>" }'`}
                />
              </section>

              <section id="pqc" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A]">Post-Quantum Key Encapsulation</h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  ML-KEM-768 key encapsulation (NIST FIPS 203). The recipient generates a key pair; the sender encapsulates against the public key and gets a shared secret plus a ciphertext to send:
                </p>
                <CodeBlock
                  title="curl - ML-KEM"
                  language="bash"
                  code={`# 1. Recipient: generate a key pair (keep privateKey on your side)
curl -X POST ${API_BASE_URL}/v1/pqc/keypair \\
  -H "Authorization: Bearer am_live_your_key" \\
  -H "Content-Type: application/json" \\
  -d '{ "algorithm": "ML-KEM-768" }'

# 2. Sender: encapsulate against the public key
curl -X POST ${API_BASE_URL}/v1/pqc/encapsulate \\
  -H "Authorization: Bearer am_live_your_key" \\
  -H "Content-Type: application/json" \\
  -d '{ "algorithm": "ML-KEM-768", "publicKey": "<data.publicKey>" }'
# -> data.sharedSecret and data.ciphertext`}
                />
              </section>

              <section id="health-probes" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <h2 className="font-editorial text-2xl font-bold text-[#1A1A1A]">Cloud Probes & Prometheus Metrics</h2>
                <p className="text-sm text-[#555555] leading-relaxed">
                  AMARACUS exports cloud-native Kubernetes probes and standard Prometheus format metrics for monitoring platforms like Datadog, Prometheus, or Grafana:
                </p>
                <div className="space-y-4">
                  <CodeBlock
                    title="Kubernetes Liveness & Readiness Probes"
                    language="bash"
                    code={`# Liveness: Verifies process is alive
curl ${API_BASE_URL}/health/live

# Readiness: Verifies database connectivity and worker queues
curl ${API_BASE_URL}/health/ready`}
                  />

                  <CodeBlock
                    title="Prometheus Metrics Exposition (/metrics)"
                    language="bash"
                    code={`# Scrape real-time node, HTTP, crypto ops, and queue metrics
curl ${API_BASE_URL}/metrics

# Sample response:
# process_resident_memory_bytes 58490880
# amaracus_crypto_operations_total{status="COMPLETED"} 1420
# amaracus_worker_queue_depth 0
# amaracus_circuit_breaker_state{provider="azure-keyvault"} 0`}
                  />
                </div>
              </section>

              <section id="webhooks-api" className="space-y-4">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-[#E8F5E9] text-[#008031] border border-[#C8E6C9]">Event Streaming</span>
                  <h2 className="text-2xl font-bold text-[#1A1A1A]">Webhooks & SDK Framework Adapters</h2>
                </div>
                <p className="text-[#555555] leading-relaxed">
                  AMARACUS delivers real-time event notifications to external webhook listeners when cryptographic operations finish, policies trigger, or provider health changes. All webhook payloads are cryptographically signed with HMAC-SHA256 headers for authentication and replay mitigation:
                </p>
                <div className="space-y-4">
                  <CodeBlock
                    title="1. Register Webhook Endpoint (cURL)"
                    language="bash"
                    code={`curl -X POST ${API_BASE_URL}/api/v1/webhooks \\
  -H "Authorization: Bearer am_live_..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "https://api.yourcompany.com/crypto-events",
    "description": "Primary Security Event Ingestion",
    "events": [
      "operation.completed",
      "operation.failed",
      "policy.violation",
      "key.disabled",
      "provider.health.changed",
      "usage.threshold.reached"
    ]
  }'

# Response contains your unique signing secret:
# { "id": "wh_...", "secret": "whsec_...", "status": "active" }`}
                  />

                  <CodeBlock
                    title="2. Express.js Adapter (@amaracus/sdk)"
                    language="typescript"
                    code={`import express from 'express';
import { amaracusWebhookMiddleware } from '@amaracus/sdk';

const app = express();

// Express requires raw body for HMAC verification:
app.post(
  '/webhooks/amaracus',
  express.raw({ type: 'application/json' }),
  amaracusWebhookMiddleware({
    secret: process.env.AMARACUS_WEBHOOK_SECRET!,
    toleranceSeconds: 300, // Replay attack tolerance
    onEvent: async (event) => {
      console.log('Received verified event:', event.type, event.data);
      if (event.type === 'policy.violation') {
        await notifySecurityTeam(event.data);
      }
    },
    onError: (err, req, res) => {
      console.error('Webhook verification failed:', err.message);
      res.status(401).json({ error: 'Invalid HMAC signature or expired timestamp' });
    }
  })
);`}
                  />

                  <CodeBlock
                    title="3. Next.js App Router Route Handler (@amaracus/sdk)"
                    language="typescript"
                    code={`import { NextRequest, NextResponse } from 'next/server';
import { verifyNextJsWebhook } from '@amaracus/sdk';

export async function POST(req: NextRequest) {
  try {
    const event = await verifyNextJsWebhook(req, process.env.AMARACUS_WEBHOOK_SECRET!);

    switch (event.type) {
      case 'operation.completed':
        console.log('Operation ID finished:', event.data.operationId);
        break;
      case 'provider.health.changed':
        console.warn('Provider health status alert:', event.data.provider, event.data.status);
        break;
    }

    return NextResponse.json({ received: true });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 401 });
  }
}`}
                  />

                  <CodeBlock
                    title="4. Multi-Version Secret Rotation"
                    language="bash"
                    code={`# Instantly generate a new signing secret for an endpoint:
curl -X POST ${API_BASE_URL}/api/v1/webhooks/wh_12345/rotate-secret \\
  -H "Authorization: Bearer am_live_..."

# Response returns the newly minted secret:
# { "id": "wh_12345", "secret": "whsec_new_token_..." }`}
                  />
                  </div>
              </section>

              <section id="migration-api" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-[#E8F5E9] text-[#008031] border border-[#C8E6C9]">High Availability Migration</span>
                  <h2 className="text-2xl font-bold text-[#1A1A1A]">Cryptographic Migration Platform</h2>
                </div>
                <p className="text-[#555555] leading-relaxed">
                  Discover deprecated algorithms, calculate explainable risk scores, generate dependency graphs, run dry-run simulations, and execute audited key rotations and bulk data re-encryptions with dual-authorization and deterministic rollback:
                </p>
                <div className="space-y-4">
                  <CodeBlock
                    title="1. Assess Cryptographic Migration Risk (cURL)"
                    language="bash"
                    code={`curl -X POST ${API_BASE_URL}/api/v1/migrations/assess \\
  -H "Authorization: Bearer am_live_..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "environment": "production",
    "includeCompliant": false
  }'

# Response returns ranked assessment items with explainable scoring:
# {
#   "summary": { "totalAssessed": 12, "highRisk": 3, "averageScore": 72.4 },
#   "items": [{ "resourceId": "key-rsa-2048", "priorityScore": { "overallScore": 82 } }]
# }`}
                  />

                  <CodeBlock
                    title="2. Create & Simulate Migration Plan (@amaracus/sdk)"
                    language="typescript"
                    code={`import { Amaracus } from '@amaracus/sdk';

const client = new Amaracus({ apiKey: 'am_live_...' });

// 1. Create Migration Plan
const plan = await client.migrations.createPlan({
  name: 'Upgrade Billing Database to ML-KEM-768',
  migrationType: 'PQC_TRANSITION',
  sourceResourceId: 'key_billing_rsa_2048',
  targetAlgorithm: 'ML-KEM-768',
  proposerId: 'usr_sec_engineer_alice',
  environment: 'production'
});

// 2. Run Non-Destructive Simulation
const sim = await client.migrations.simulatePlan(plan.id);
console.log('Simulation Safe:', sim.overallSafe);
console.log('Rollback Feasible:', sim.rollbackFeasibility.isReversible);`}
                  />

                  <CodeBlock
                    title="3. Four-Eyes Approval & Safe Execution"
                    language="bash"
                    code={`# Step 1: Second officer approves (proposer != approver)
curl -X POST ${API_BASE_URL}/api/v1/migrations/plans/plan_12345/approve \\
  -H "Authorization: Bearer am_live_..." \\
  -H "Content-Type: application/json" \\
  -d '{ "approverId": "usr_ciso_bob" }'

# Step 2: Execute Migration (Generates target key, verifies roundtrip, updates pointer)
curl -X POST ${API_BASE_URL}/api/v1/migrations/plans/plan_12345/execute \\
  -H "Authorization: Bearer am_live_..." \\
  -H "Content-Type: application/json" \\
  -d '{ "executedBy": "usr_ciso_bob" }'

# Step 3: If needed, deterministic rollback:
# curl -X POST ${API_BASE_URL}/api/v1/migrations/plans/plan_12345/rollback \\
#   -d '{ "reason": "Downstream legacy system incompatible" }'`}
                  />

                  <CodeBlock
                    title="4. Envelope v1 Batch Re-Encryption (@amaracus/sdk)"
                    language="typescript"
                    code={`// Re-encrypt large historical database datasets in controlled batches:
const result = await client.migrations.reEncrypt({
  sourceKeyId: 'key_old_aes128',
  targetKeyId: 'key_new_aes256_gcm',
  envelopes: [
    { id: 'rec_001', ciphertext: 'base64_blob...', algorithm: 'AES-128-GCM' },
    { id: 'rec_002', ciphertext: 'base64_blob...', algorithm: 'AES-128-GCM' }
  ],
  batchSize: 500
});

console.log('Re-encrypted:', result.successfulCount, 'Failed:', result.failedCount);`}
                  />
                </div>
              </section>

              <section id="os-api" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-[#E8F5E9] text-[#008031] border border-[#C8E6C9]">Control Plane & Orchestration</span>
                  <h2 className="text-2xl font-bold text-[#1A1A1A]">Cryptographic Control Plane & Workflows</h2>
                </div>
                <p className="text-[#555555] leading-relaxed">
                  Query unified resource inventories across cloud vaults and HSMs, calculate consolidated security postures, orchestrate multi-step workflows from templates with four-eyes governance, and evaluate continuous automations:
                </p>
                <div className="space-y-4">
                  <CodeBlock
                    title="1. Query Unified Cryptographic Inventory (@amaracus/sdk)"
                    language="typescript"
                    code={`import { Amaracus } from '@amaracus/sdk';

const client = new Amaracus({ apiKey: 'am_live_...' });

// Retrieve all verified cryptographic keys, certs, and cloud vaults
const inventory = await client.os.getInventory({ verifiedOnly: true });

console.log('Discovered Resources:', inventory.length);
// Sample item: { id: 'key_master_aes', type: 'KEY', verified: true, verificationSource: 'DIRECT_STORAGE' }`}
                  />

                  <CodeBlock
                    title="2. Retrieve Consolidated Security Posture & Deduplicated Findings"
                    language="bash"
                    code={`curl ${API_BASE_URL}/api/v1/os/posture \\
  -H "Authorization: Bearer am_live_..."

# Response returns overall health score (0-100) and deduplicated findings:
# {
#   "score": 92,
#   "totalFindings": 2,
#   "pqcReadinessPercentage": 60,
#   "verifiedInventoryPercentage": 100,
#   "findings": [
#     { "code": "KEY_ROTATION_OVERDUE", "severity": "MEDIUM", "remediation": { "workflowTemplateId": "tpl_key_rotation" } }
#   ]
# }`}
                  />

                  <CodeBlock
                    title="3. Instantiate & Execute Enterprise Workflow (@amaracus/sdk)"
                    language="typescript"
                    code={`// 1. Instantiate Staged Key Rotation Workflow from template
const workflow = await client.os.instantiateTemplate('tpl_key_rotation', {
  name: 'Rotate Database Master Key Q4'
});
console.log('Workflow created in state:', workflow.state); // 'AWAITING_APPROVAL'

// 2. Second Officer approves workflow (server-side proposer !== approver enforcement)
const approved = await client.os.approveWorkflow(workflow.id, 'usr_security_officer_bob');
console.log('Approved state:', approved.state); // 'READY'

// 3. Execute approved workflow steps sequentially
const result = await client.os.executeWorkflow(workflow.id);
console.log('Completed all', result.steps.length, 'steps successfully!');`}
                  />

                  <CodeBlock
                    title="4. Continuous Automation Rules Evaluation (cURL)"
                    language="bash"
                    code={`# Trigger automated background rules check across key ages and cert validity:
curl -X POST ${API_BASE_URL}/api/v1/os/automations/evaluate \\
  -H "Authorization: Bearer am_live_..."

# Response:
# {
#   "totalRules": 3,
#   "evaluations": [
#     { "rule": { "trigger": "CERT_EXPIRING" }, "triggered": false, "reason": "All certificates within validity windows" }
#   ]
# }`}
                  />
                  </div>
              </section>

              <section id="intelligence-api" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-[#E8F5E9] text-[#008031] border border-[#C8E6C9]">Autonomous Optimization</span>
                  <h2 className="text-2xl font-bold text-[#1A1A1A]">Cryptographic Intelligence & Autonomous Optimization API</h2>
                </div>
                <p className="text-[#555555] leading-relaxed">
                  Analyze cryptographic telemetry, retrieve explainable recommendations with deterministic priority scores (0–100), simulate dry-run impacts non-destructively, and execute remediations under the Four-Eyes principle:
                </p>
                <div className="space-y-4">
                  <CodeBlock
                    title="1. Query Prioritized Recommendations (@amaracus/sdk)"
                    language="typescript"
                    code={`import { Amaracus } from '@amaracus/sdk';

const client = new Amaracus({ apiKey: 'am_live_...' });

// Query active recommendations sorted by priority score
const recommendations = await client.intelligence.getRecommendations({
  status: 'DETECTED',
  severity: 'CRITICAL'
});

for (const rec of recommendations) {
  console.log(\`[\${rec.priorityScore} pts] \${rec.title}\`);
  console.log('Observed Facts:', rec.explanation.observedFacts);
  console.log('Remediation:', rec.proposedAction.type);
}`}
                  />

                  <CodeBlock
                    title="2. Non-Destructive Dry-Run Impact Simulation"
                    language="typescript"
                    code={`// Simulate proposed action without mutating production keys:
const dryRun = await client.intelligence.dryRunRecommendation('rec-rot-master');

console.log('Downtime:', dryRun.potentialDowntime); // 'NONE'
console.log('Reversibility:', dryRun.reversibility); // 'FULLY_REVERSIBLE'
console.log('Policy Compliant:', dryRun.policyConsequences.compliant); // true
console.log('Required Approvals:', dryRun.requiredApprovals); 
// ['SECURITY_OFFICER_APPROVAL', 'FOUR_EYES_SECOND_PARTY_APPROVAL']`}
                  />

                  <CodeBlock
                    title="3. Accept & Execute with Four-Eyes Separation of Duties"
                    language="typescript"
                    code={`// Step 1: Officer Alice accepts the recommendation
await client.intelligence.acceptRecommendation('rec-rot-master', {
  reason: 'Scheduled for Q4 key cryptoperiod renewal'
});

// Step 2: Officer Bob executes the remediation (proposer != executor)
// If Alice tries to execute, AMARACUS rejects with 403 Forbidden.
const completed = await client.intelligence.executeRecommendation('rec-rot-master');
console.log('Remediation completed! Status:', completed.status); // 'COMPLETED'`}
                  />

                  <CodeBlock
                    title="4. Trigger Live Multi-Source Analysis Scan (cURL)"
                    language="bash"
                    code={`# Triggers live telemetry scan across Keys, Certs, Circuit Breakers, and Policies:
curl -X POST ${API_BASE_URL}/api/v1/intelligence/analyze \\
  -H "Authorization: Bearer am_live_..." \\
  -H "Content-Type: application/json" \\
  -d '{ "categories": ["SECURITY_RISK", "KEY_LIFECYCLE", "PQC_READINESS"] }'

# Response:
# {
#   "data": {
#     "newlyDetected": 2,
#     "total": 5,
#     "recommendations": [...]
#   }
# }`}
                  />
                </div>
              </section>

              <section id="compliance-api" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-[#E8F5E9] text-[#008031] border border-[#C8E6C9]">Compliance Self-Assessment</span>
                  <h2 className="text-2xl font-bold text-[#1A1A1A]">Trust, Compliance & Assurance API</h2>
                </div>
                <p className="text-[#555555] leading-relaxed">
                  Evaluate technical control compliance against SOC 2 Type II, ISO/IEC 27001, NIST SP 800-53, NIST SP 800-57, FIPS 140-3, and NIST PQC. Collect verifiable SHA-256 evidence, request Four-Eyes exceptions, and export audit-ready reports:
                </p>

                <div className="space-y-4">
                  <CodeBlock
                    title="1. Evaluate Compliance Posture (@amaracus/sdk)"
                    language="typescript"
                    code={`import { Amaracus } from '@amaracus/sdk';

const client = new Amaracus({ apiKey: 'am_live_...' });

// Evaluate SOC 2 Type II compliance in real-time
const report = await client.compliance.evaluate({
  frameworkId: 'SOC_2_TYPE_II',
  forceRefresh: true
});

console.log('Overall SOC 2 Score:', report.overallScore + '%'); // e.g. 100%
console.log('Satisfied Controls:', report.satisfiedControls, '/', report.totalControls);
console.log('Identified Gaps:', report.gapsCount);
console.log('Cryptographic Digest:', report.reportDigest); // SHA-256 hash`}
                  />

                  <CodeBlock
                    title="2. Request & Approve Compliance Exception (Four-Eyes Principle)"
                    language="typescript"
                    code={`// Step 1: Officer Alice requests a temporary exception for a legacy connection
const exception = await client.compliance.requestException({
  controlId: 'SOC2-CC6.1',
  justification: 'Legacy banking mainframe batch connector migration scheduled for Q4',
  compensatingControls: 'Air-gapped VPC subnet, mutual TLS 1.3, hourly log verification',
  expiresAt: new Date(Date.now() + 30 * 86400000).toISOString() // 30-day grace period
});

console.log('Exception created! Status:', exception.status); // 'PENDING'

// Step 2: Independent Officer Bob approves the exception
// (If Alice attempts to approve her own exception, AMARACUS rejects with 403 Forbidden)
const approved = await client.compliance.approveException(exception.id, 'usr_bob_auditor');
console.log('Exception approved by Bob! Status:', approved.status); // 'APPROVED'`}
                  />

                  <CodeBlock
                    title="3. Export Audit-Ready Reports (CSV & JSON)"
                    language="bash"
                    code={`# Export RFC 4180 CSV report for compliance spreadsheets (Vanta, Drata, Excel):
curl -s -H "Authorization: Bearer am_live_..." \\
  "${API_BASE_URL}/api/v1/compliance/reports/csv?frameworkId=SOC_2_TYPE_II" > soc2_audit_report.csv

# Export programmatic JSON report with SHA-256 integrity stamp:
curl -s -H "Authorization: Bearer am_live_..." \\
  "${API_BASE_URL}/api/v1/compliance/reports/json?frameworkId=ISO_27001_2022" > iso27001_report.json`}
                  />
                </div>
              </section>

              <section id="tutorial-developer" className="space-y-4 pt-6 border-t border-[#E9EDE7]">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-[#E8F5E9] text-[#008031] border border-[#C8E6C9]">Developer Tutorial</span>
                  <h2 className="text-2xl font-bold text-[#1A1A1A]">End-to-End Developer Tutorial: Migration & OS Automation</h2>
                </div>
                <p className="text-[#555555] leading-relaxed">
                  A complete, runnable walkthrough using the official <code className="bg-[#EAE8E1] px-1.5 py-0.5 rounded text-xs font-mono">@amaracus/sdk</code>. Follow these 6 steps to discover resources, evaluate health, create a post-quantum migration plan, simulate, approve, execute, and verify:
                </p>

                <div className="space-y-4">
                  <CodeBlock
                    title="Complete TypeScript Automation Script (migration-tutorial.ts)"
                    language="typescript"
                    code={`import { Amaracus } from '@amaracus/sdk';

async function main() {
  // 1. Initialize Amaracus Client
  const client = new Amaracus({
    apiKey: process.env.AMARACUS_API_KEY!,
    baseUrl: process.env.AMARACUS_BASE_URL || '${API_BASE_URL}/api/v1'
  });

  console.log('=== Step 1: Discover Unified Inventory ===');
  const inventory = await client.os.getInventory({ verifiedOnly: true });
  console.log(\`Found \${inventory.length} cryptographic resources.\`);

  console.log('\\n=== Step 2: Query Security Posture & Deduplicated Findings ===');
  const posture = await client.os.getPosture();
  console.log(\`Overall Health Score: \${posture.score} / 100\`);
  console.log(\`PQC Readiness: \${posture.pqcReadinessPercentage}%\`);
  for (const finding of posture.findings) {
    console.log(\`  - [\${finding.severity}] \${finding.title} (\${finding.code})\`);
  }

  console.log('\\n=== Step 3: Create & Simulate Migration Plan ===');
  const plan = await client.migrations.createPlan({
    name: 'Transition Billing Keys to ML-KEM-768',
    migrationType: 'PQC_TRANSITION',
    sourceResourceId: 'key_billing_rsa_2048',
    sourceAlgorithm: 'RSA-2048',
    targetAlgorithm: 'ML-KEM-768',
    proposerId: 'usr_alice_engineer',
    environment: 'production'
  });
  console.log(\`Created plan \${plan.id} in state: \${plan.state}\`);

  // Run non-destructive simulation
  const simulation = await client.migrations.simulatePlan(plan.id);
  console.log(\`Simulation Safe: \${simulation.overallSafe}\`);
  console.log(\`Rollback Feasible: \${simulation.rollbackFeasibility.isReversible}\`);

  console.log('\\n=== Step 4: Multi-Party Approval (Four-Eyes Principle) ===');
  // Proposer Alice cannot approve her own plan; Bob the CISO signs off
  const approvedPlan = await client.migrations.approvePlan(plan.id, 'usr_bob_ciso');
  console.log(\`Plan approved by \${approvedPlan.approverId}. State: \${approvedPlan.state}\`);

  console.log('\\n=== Step 5: Execute Migration with Zero Downtime ===');
  const executed = await client.migrations.executePlan(plan.id, 'usr_bob_ciso');
  console.log(\`Migration completed! New active key pointer: \${executed.targetResourceId}\`);
  console.log(\`Old key \${executed.sourceResourceId} status: RETIRED_FOR_ENCRYPTION (Historical reads preserved).\`);

  console.log('\\n=== Step 6: Evaluate Continuous Automation Rules ===');
  const automations = await client.os.evaluateAutomations();
  console.log(\`Evaluated \${automations.totalRules} rules across estate. Active watchdogs: \${automations.evaluations.length}\`);
}

main().catch(console.error);`}
                  />

                  <CodeBlock
                    title="Instant Rollback Example (If Legacy Service Anomaly Occurs)"
                    language="typescript"
                    code={`// If any downstream client experiences an issue, trigger instant deterministic rollback:
const rollback = await client.migrations.rollbackPlan(
  'plan_mig_12345',
  'Downstream payment partner incompatible with multi-kilobyte lattice keys'
);

console.log('Rollback status:', rollback.state); // 'ROLLED_BACK'
console.log('Active key restored to original source key pointer.');`}
                  />
                </div>
              </section>

              <section id="ai-prompting" className="space-y-6 pt-6 border-t border-[#E9EDE7]">
                <div className="flex items-center gap-2 text-xs text-[#767676]">
                  <span>Developer Docs</span>
                  <span>/</span>
                  <span className="text-[#008031] font-medium">AI &amp; LLM Integration</span>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h2 className="font-editorial text-3xl font-bold text-[#1A1A1A] flex items-center gap-2.5">
                      <Bot className="w-7 h-7 text-[#008031]" /> Implementing with AI Assistants
                    </h2>
                    <p className="text-xs text-[#767676] mt-1">
                      System rules, prompt engineering templates, and anti-hallucination guardrails for Cursor, Claude Code, GitHub Copilot, ChatGPT, and Antigravity.
                    </p>
                  </div>
                  <Badge variant="outline" className="border-[#008031] text-[#008031] bg-[#E8F5E9] px-2.5 py-1 text-xs shrink-0 self-start sm:self-auto">
                    <Sparkles className="w-3.5 h-3.5 mr-1" /> AI-Native Cryptography
                  </Badge>
                </div>

                <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl text-xs space-y-3">
                  <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                    <Shield className="w-4 h-4 text-[#008031]" /> Why AI Needs Cryptographic Guardrails
                  </h3>
                  <p className="text-[#555555] leading-relaxed">
                    AI models are notoriously prone to generating subtly insecure cryptographic code. They frequently suggest unauthenticated AES modes (ECB, CBC without HMAC), non-constant-time string comparisons that are vulnerable to timing attacks, or hardcode API secrets in client-side bundles.
                  </p>
                  <p className="text-[#555555] leading-relaxed">
                    By providing the AMARACUS system prompt and pointing the AI to our canonical endpoint <code className="px-1.5 py-0.5 bg-[#F8F7F4] rounded font-mono text-[#008031]">{API_BASE_URL}/api/v1</code>, you instruct the AI to delegate cryptographic operations to the AMARACUS API instead of writing its own.
                  </p>
                </div>

                {/* Cursorrules / System Prompt */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-[#008031]" /> 1. Project System Prompt (.cursorrules / CLAUDE.md)
                    </h3>
                    <span className="text-[11px] text-[#767676] font-mono">Place in root of repository</span>
                  </div>
                  <p className="text-xs text-[#555555]">
                    Add these instructions to your project&apos;s <code className="px-1.5 py-0.5 bg-white border rounded font-mono text-xs">.cursorrules</code>, <code className="px-1.5 py-0.5 bg-white border rounded font-mono text-xs">CLAUDE.md</code>, or GitHub Copilot custom instructions:
                  </p>
                  <CodeBlock
                    title=".cursorrules / System Prompt"
                    language="markdown"
                    code={`# AMARACUS Cryptographic Integration Guardrails

When generating encryption, decryption, signing, or post-quantum key exchange in this codebase:
1. NEVER generate custom, local cryptographic algorithms, unauthenticated AES modes (ECB/CBC), or insecure random math.
2. Use the AMARACUS REST API (${API_BASE_URL}/v1) or the @amaracus/sdk TypeScript client.
3. Keep the API key in process.env.AMARACUS_API_KEY. NEVER expose it to client-side bundles (e.g., no NEXT_PUBLIC_ prefixes).
4. Core endpoints:
   - Encrypt with a managed key: POST /v1/encrypt { key, data } -> data.envelope
   - Decrypt: POST /v1/decrypt { key, envelope } -> data.plaintext, data.encoding
   - Hashing (SHA-2 / SHA-3 only): POST /v1/hash { algorithm, data }
   - Post-Quantum KEM (ML-KEM-768): POST /v1/crypto/kem/keygen, /v1/crypto/kem/encapsulate, /v1/crypto/kem/decapsulate
   - Security Posture & CBOM: GET /v1/os/posture & GET /v1/os/inventory
5. Passwords: AMARACUS does not hash passwords. Use Argon2id (or scrypt/bcrypt) locally; never SHA-256 alone.
6. Zero-out sensitive plaintext from memory after use and never log plaintext or keys.`}
                  />
                </div>

                {/* Copyable Developer Prompts */}
                <div className="space-y-4 pt-2">
                  <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-[#008031]" /> 2. Master Prompts for AI Coding Assistants
                  </h3>

                  <div className="space-y-4">
                    {/* Prompt A */}
                    <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-xs text-[#1A1A1A]">Pattern A: Database Column &amp; Field-Level Envelope Encryption</span>
                        <span className="px-2 py-0.5 bg-[#E8F5E9] text-[#008031] rounded text-[10px] font-semibold">Prisma / Drizzle / Next.js</span>
                      </div>
                      <CodeBlock
                        title="Copy to Cursor / Claude / Copilot"
                        language="text"
                        code={`Act as a Principal Security Architect. I need to implement field-level envelope encryption for sensitive user records (ssn, taxId, bankAccountNumber) in my Node.js/Next.js application using Prisma ORM.

Requirements:
1. Use the AMARACUS API at ${API_BASE_URL}/v1 with Bearer auth via process.env.AMARACUS_API_KEY and a managed key id in process.env.AMARACUS_KEY_ID.
2. For small fields, call POST /v1/encrypt with { key, data } and store the returned data.envelope string; decrypt with POST /v1/decrypt { key, envelope }.
3. For large payloads, use envelope encryption:
   - Generate a random 32-byte data key locally (crypto.randomBytes) and encrypt the record with AES-256-GCM (Node crypto).
   - Wrap the data key with POST /v1/encrypt { key, data: <base64 data key>, encoding: "base64" } and store the envelope.
   - Erase the plaintext data key from memory.
   - Store the ciphertext, IV, auth tag, and the wrapped data key envelope alongside the record.
4. Write a TypeScript service 'AmaracusCryptoService' with encryptField(plaintext) and decryptField(payload).
5. Provide a sample Prisma schema and a Next.js Server Action demonstrating how to save and retrieve an encrypted user profile.
6. Include robust error handling and ensure no decrypted data is ever logged.`}
                      />
                    </div>

                    {/* Prompt B */}
                    <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-xs text-[#1A1A1A]">Pattern B: Password Hashing &amp; Encrypted Profile Fields</span>
                        <span className="px-2 py-0.5 bg-[#E8F5E9] text-[#008031] rounded text-[10px] font-semibold">Auth</span>
                      </div>
                      <CodeBlock
                        title="Copy to Cursor / Claude / Copilot"
                        language="text"
                        code={`I am building an authentication service in TypeScript for my web app.

Requirements:
1. Passwords: hash locally with Argon2id using the argon2 npm package (memoryCost >= 19456, timeCost >= 2). AMARACUS does not provide password hashing; never send passwords to it and never use plain SHA-256 for passwords.
2. Login: verify with argon2.verify(storedHash, candidate), which is constant-time.
3. Sensitive profile fields (phone, date of birth): encrypt with the AMARACUS API at ${API_BASE_URL}/v1:
   - POST /v1/encrypt with { "key": process.env.AMARACUS_KEY_ID, "data": "<value>" }; store data.envelope.
   - POST /v1/decrypt with { "key": process.env.AMARACUS_KEY_ID, "envelope": "<stored envelope>" }; read data.plaintext.
4. Provide TypeScript code with input validation (zod) and proper error handling.`}
                      />
                    </div>

                    {/* Prompt C */}
                    <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-xs text-[#1A1A1A]">Pattern C: Post-Quantum Lattice Secret Vault (NIST ML-KEM-768)</span>
                        <span className="px-2 py-0.5 bg-[#E8F5E9] text-[#008031] rounded text-[10px] font-semibold">Post-Quantum KEM</span>
                      </div>
                      <CodeBlock
                        title="Copy to Cursor / Claude / Copilot"
                        language="text"
                        code={`Help me implement a Post-Quantum Cryptographic (PQC) message vault in TypeScript using NIST ML-KEM-768 via the AMARACUS API.

Requirements:
1. Use the AMARACUS API endpoints at ${API_BASE_URL}/v1:
   - Generate Keypair: POST /v1/crypto/kem/keygen with { "algorithm": "ML-KEM-768" }
   - Encapsulate: POST /v1/crypto/kem/encapsulate with { "algorithm": "ML-KEM-768", "publicKey": "<recipient_public_key>" }
   - Decapsulate: POST /v1/crypto/kem/decapsulate with { "algorithm": "ML-KEM-768", "ciphertext": "<encapsulation_ciphertext>", "privateKey": "<recipient_private_key>" }
2. Implement a hybrid envelope workflow:
   - Sender encapsulates a shared secret using recipient's ML-KEM-768 public key.
   - Sender encrypts the sensitive file using AES-256-GCM keyed by the shared secret.
   - Recipient decapsulates the shared secret using their private key and decrypts the file.
3. Provide clean TypeScript functions with typed request and response interfaces.`}
                      />
                    </div>

                    {/* Prompt D */}
                    <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-xs text-[#1A1A1A]">Pattern D: Webhook Verification Middleware with Timing-Safe Equality</span>
                        <span className="px-2 py-0.5 bg-[#E8F5E9] text-[#008031] rounded text-[10px] font-semibold">Express / Next.js Route Handler</span>
                      </div>
                      <CodeBlock
                        title="Copy to Cursor / Claude / Copilot"
                        language="text"
                        code={`Write a robust webhook receiver middleware in Node.js (Express or Next.js App Router route handler) to verify incoming AMARACUS webhook signatures.

Requirements:
1. AMARACUS sends a signature in the header: X-Amaracus-Signature: t=<timestamp>,v1=<hmac_sha256_hex>.
2. The middleware must:
   - Extract the raw request body buffer (do not parse JSON before calculating HMAC).
   - Recreate the signed payload: \${timestamp}.\${rawBody}.
   - Compute HMAC-SHA256 using crypto.createHmac('sha256', process.env.AMARACUS_WEBHOOK_SECRET).
   - Compare the computed digest with the received v1 signature using crypto.timingSafeEqual to avoid timing attacks.
   - Reject requests where the timestamp is older than 5 minutes (replay attack protection).
3. Return HTTP 400 or 401 if verification fails, and proceed to handler if verified.`}
                      />
                    </div>
                  </div>
                </div>

                {/* AI Review Checklist */}
                <div className="p-4 bg-white border border-[#E9EDE7] rounded-xl text-xs space-y-3">
                  <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-[#008031]" /> AI Code Review &amp; Safety Checklist
                  </h3>
                  <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="AI code review and safety checklist table">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="border-b border-[#E9EDE7] text-[#767676]">
                          <th className="py-2 pr-4 font-semibold">Checklist Item</th>
                          <th className="py-2 pr-4 font-semibold text-[#008031]">Safe AI Pattern</th>
                          <th className="py-2 font-semibold text-rose-600">Reject / Flag Prompt</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#E9EDE7] text-[#555555]">
                        <tr>
                          <td className="py-2.5 pr-4 font-medium text-[#1A1A1A]">API Keys</td>
                          <td className="py-2.5 pr-4">Server-side env <code className="font-mono text-[11px]">process.env.AMARACUS_API_KEY</code></td>
                          <td className="py-2.5 font-mono text-[11px] text-rose-600">NEXT_PUBLIC_AMARACUS_API_KEY</td>
                        </tr>
                        <tr>
                          <td className="py-2.5 pr-4 font-medium text-[#1A1A1A]">Cipher Mode</td>
                          <td className="py-2.5 pr-4">Authenticated AEAD (AES-256-GCM / ChaCha20-Poly1305)</td>
                          <td className="py-2.5 font-mono text-[11px] text-rose-600">AES-ECB or CBC without HMAC</td>
                        </tr>
                        <tr>
                          <td className="py-2.5 pr-4 font-medium text-[#1A1A1A]">Signatures</td>
                          <td className="py-2.5 pr-4"><code className="font-mono text-[11px]">crypto.timingSafeEqual()</code></td>
                          <td className="py-2.5 font-mono text-[11px] text-rose-600">String comparison &apos;===&apos;</td>
                        </tr>
                        <tr>
                          <td className="py-2.5 pr-4 font-medium text-[#1A1A1A]">Key Erasure</td>
                          <td className="py-2.5 pr-4">Plaintext data keys zeroed from memory immediately</td>
                          <td className="py-2.5 font-mono text-[11px] text-rose-600">Retaining plaintext in global memory</td>
                        </tr>
                        <tr>
                          <td className="py-2.5 pr-4 font-medium text-[#1A1A1A]">Endpoint</td>
                          <td className="py-2.5 pr-4"><code className="font-mono text-[11px]">{API_BASE_URL}/api/v1</code></td>
                          <td className="py-2.5 font-mono text-[11px] text-rose-600">Hallucinated local crypto endpoints</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Instant Verification with cURL */}
                <div className="space-y-3">
                  <h3 className="font-bold text-sm text-[#1A1A1A] flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-[#008031]" /> 3. Live Verification Commands
                  </h3>
                  <p className="text-xs text-[#555555]">
                    Test the endpoints in your terminal to verify responses against what your AI generated:
                  </p>
                  <CodeBlock
                    title="Bash / cURL"
                    language="bash"
                    code={`# 1. Check your API key works (lists the keys it can see)
curl ${API_BASE_URL}/v1/keys \\
  -H "Authorization: Bearer $AMARACUS_API_KEY"

# 2. Encrypt with one of your managed keys
curl -X POST ${API_BASE_URL}/v1/encrypt \\
  -H "Authorization: Bearer $AMARACUS_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"key":"'"$AMARACUS_KEY_ID"'","data":"Sensitive payload test"}'`}
                  />
                </div>
              </section>
            </div>
          </div>
        </main>
      </div>

      <PublicFooter />
    </div>
  );
}
