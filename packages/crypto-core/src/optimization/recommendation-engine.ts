/**
 * @file packages/crypto-core/src/optimization/recommendation-engine.ts
 * Recommendation Engine for AMARACUS Cryptographic Intelligence (Phase 21)
 */

import {
  EvidenceSnapshot,
  OptimizationRecommendation,
  EvidenceReference,
  RecommendationCategory,
  SeverityLevel,
  EvidenceConfidenceLevel,
  ProposedAction,

  AffectedResourceRef,
  RawKeyTelemetry,
  RawCertTelemetry,
  RawCircuitBreakerTelemetry,
  RawPolicyEvaluationTelemetry,
  RawUsageTelemetry,
} from './types';
import { EvidenceAnalyzer } from './evidence-analyzer';

export class RecommendationEngine {
  /**
   * Generates prioritized, evidence-backed recommendations from an evidence snapshot.
   */
  public static generateRecommendations(snapshot: EvidenceSnapshot): OptimizationRecommendation[] {
    const rawEvidence = EvidenceAnalyzer.extractEvidence(snapshot);
    const recommendations: OptimizationRecommendation[] = [];
    const seenDeduplicationKeys = new Set<string>();

    const now = new Date().toISOString();

    // 1. Analyze Key Lifecycle & Security Risks (Keys past rotation threshold or deprecated algorithms)
    if (snapshot.keys && snapshot.keys.length > 0) {
      for (const key of snapshot.keys) {
        // (a) Deprecated algorithm check
        const isDeprecated = this.isDeprecatedAlgorithm(key.algorithm);
        if (isDeprecated) {
          const dedupeKey = `SECURITY_RISK:${key.id}:DEPRECATED_ALGORITHM`;
          if (!seenDeduplicationKeys.has(dedupeKey)) {
            seenDeduplicationKeys.add(dedupeKey);

            const evidence = rawEvidence.filter(e => e.resourceId === key.id);
            const severity: SeverityLevel = 'CRITICAL';
            const confidence: EvidenceConfidenceLevel = 'VERIFIED_FACT';
            const score = this.calculatePriorityScore(severity, 1, confidence, true);

            recommendations.push({
              id: `rec-alg-${key.id}`,
              orgId: snapshot.orgId,
              category: 'SECURITY_RISK',
              severity,
              priorityScore: score,
              title: `Deprecated Algorithm (${key.algorithm}) Detected on Key ${key.name}`,
              explanation: {
                summary: `Key "${key.name}" uses ${key.algorithm}, which is deprecated and disallowed by modern cryptographic standards.`,
                observedFacts: [
                  `Key ID: ${key.id}`,
                  `Configured Algorithm: ${key.algorithm}`,
                  `Hardware Provider: ${key.provider}`,
                ],
                technicalRisk: `Algorithm ${key.algorithm} provides insufficient bit-security against modern cryptanalysis and violates FIPS 140-3 compliance mandates.`,
                businessImpact: `Non-compliance with enterprise cryptographic policies, audit failure risks, and data integrity exposure.`,
                remediationSteps: [
                  `Review active workloads referencing key "${key.name}".`,
                  `Generate a replacement key utilizing an approved algorithm (e.g. AES-256-GCM or Ed25519).`,
                  `Execute envelope re-encryption using the AMARACUS Migration Platform.`,
                ],
                isAiGeneratedSummary: false,
              },
              evidence,
              affectedResources: [{ id: key.id, type: 'KEY', name: key.name, provider: key.provider, algorithm: key.algorithm }],
              expectedBenefit: `Brings cryptographic infrastructure into compliance with FIPS 140-3 and NIST SP 800-131A Rev 2.`,
              risks: [`Requires coordinating dependent application key identifiers.`],
              preconditions: [`Target algorithm must be supported by configured provider ${key.provider}.`],
              proposedAction: {
                type: 'PLAN_MIGRATION',
                targetResourceId: key.id,
                targetResourceType: 'KEY',
                parameters: { targetAlgorithm: 'AES-256-GCM' },
                isAutomated: false,
                requiresApproval: true,
                requiresFourEyes: true,
              },
              requiredPermissions: ['keys:rotate', 'migrations:plan'],
              verificationProcedure: `Validate new key envelope test encryption and verify deprecation alert clears.`,
              status: 'DETECTED',
              deduplicationKey: dedupeKey,
              createdAt: now,
              updatedAt: now,
            });
          }
        }

        // (b) Key Rotation Threshold check
        const createdAtTime = new Date(key.createdAt).getTime();
        const lastRotatedTime = key.lastRotatedAt ? new Date(key.lastRotatedAt).getTime() : createdAtTime;
        const ageDays = Math.floor((Date.now() - lastRotatedTime) / (1000 * 60 * 60 * 24));
        const rotationThreshold = key.rotationIntervalDays || 90;

        if (ageDays >= rotationThreshold) {
          const dedupeKey = `KEY_LIFECYCLE:${key.id}:ROTATION_DUE`;
          if (!seenDeduplicationKeys.has(dedupeKey)) {
            seenDeduplicationKeys.add(dedupeKey);

            const evidence = rawEvidence.filter(e => e.resourceId === key.id && e.metricOrFact === 'KEY_AGE_DAYS');
            const severity: SeverityLevel = ageDays > rotationThreshold * 1.5 ? 'HIGH' : 'MEDIUM';
            const confidence: EvidenceConfidenceLevel = 'VERIFIED_FACT';
            const isUrgent = ageDays > rotationThreshold * 1.5;
            const score = this.calculatePriorityScore(severity, 1, confidence, isUrgent);

            recommendations.push({
              id: `rec-rot-${key.id}`,
              orgId: snapshot.orgId,
              category: 'KEY_LIFECYCLE',
              severity,
              priorityScore: score,
              title: `Cryptographic Key Rotation Due for "${key.name}" (${ageDays} Days Active)`,
              explanation: {
                summary: `Key "${key.name}" has been active for ${ageDays} days without rotation, exceeding the configured threshold of ${rotationThreshold} days.`,
                observedFacts: [
                  `Key Age: ${ageDays} days`,
                  `Configured Threshold: ${rotationThreshold} days`,
                  `Provider: ${key.provider}`,
                ],
                technicalRisk: `Prolonged key usage increases cryptanalytic exposure limits and expands potential blast radius if a compromised version goes undetected.`,
                businessImpact: `Potential failure of SOC 2 Type II, PCI-DSS 4.0, and ISO 27001 annual rotation audit controls.`,
                remediationSteps: [
                  `Generate a new key version within the target provider (${key.provider}).`,
                  `Update active pointer for new encryption operations.`,
                  `Retain previous version in read-only status for legacy ciphertext decryption.`,
                ],
                isAiGeneratedSummary: false,
              },
              evidence,
              affectedResources: [{ id: key.id, type: 'KEY', name: key.name, provider: key.provider, algorithm: key.algorithm }],
              expectedBenefit: `Limits cryptoperiod exposure and satisfies regulatory key rotation compliance.`,
              risks: [`None; previous versions are preserved for historical decryption.`],
              preconditions: [`Provider ${key.provider} must be reachable and healthy.`],
              proposedAction: {
                type: 'ROTATE_KEY',
                targetResourceId: key.id,
                targetResourceType: 'KEY',
                isAutomated: false,
                requiresApproval: true,
                requiresFourEyes: true,
              },
              requiredPermissions: ['keys:rotate'],
              verificationProcedure: `Verify new key version is active and test encrypt/decrypt cycle succeeds.`,
              status: 'DETECTED',
              deduplicationKey: dedupeKey,
              createdAt: now,
              updatedAt: now,
            });
          }
        }
      }
    }

    // 2. Analyze Certificate Expiry Intelligence
    if (snapshot.certificates && snapshot.certificates.length > 0) {
      for (const cert of snapshot.certificates) {
        const expiryTime = new Date(cert.notAfter).getTime();
        const daysUntilExpiry = Math.floor((expiryTime - Date.now()) / (1000 * 60 * 60 * 24));

        if (daysUntilExpiry <= 30) {
          const dedupeKey = `SECURITY_RISK:${cert.id}:CERT_EXPIRING`;
          if (!seenDeduplicationKeys.has(dedupeKey)) {
            seenDeduplicationKeys.add(dedupeKey);

            const evidence = rawEvidence.filter(e => e.resourceId === cert.id);
            let severity: SeverityLevel = 'MEDIUM';
            let isUrgent = false;

            if (daysUntilExpiry <= 0) {
              severity = 'CRITICAL';
              isUrgent = true;
            } else if (daysUntilExpiry <= 7) {
              severity = 'HIGH';
              isUrgent = true;
            }

            const score = this.calculatePriorityScore(severity, 1, 'VERIFIED_FACT', isUrgent);

            recommendations.push({
              id: `rec-cert-${cert.id}`,
              orgId: snapshot.orgId,
              category: 'SECURITY_RISK',
              severity,
              priorityScore: score,
              title: daysUntilExpiry <= 0
                ? `Certificate "${cert.commonName}" Has Expired`
                : `Certificate "${cert.commonName}" Expires in ${daysUntilExpiry} Days`,
              explanation: {
                summary: daysUntilExpiry <= 0
                  ? `Certificate for "${cert.commonName}" has expired, causing TLS connection outages.`
                  : `Certificate for "${cert.commonName}" expires in ${daysUntilExpiry} days. Renewal is required to avoid service downtime.`,
                observedFacts: [
                  `Common Name: ${cert.commonName}`,
                  `Expiration Date: ${cert.notAfter}`,
                  `Days Remaining: ${daysUntilExpiry}`,
                ],
                technicalRisk: `Expired certificates cause TLS handshake negotiation failures, broken mutual authentication, and API rejections.`,
                businessImpact: `Critical operational outage for client applications connecting to endpoints secured by this certificate.`,
                remediationSteps: [
                  `Issue renewal certificate from parent Certificate Authority.`,
                  `Deploy updated certificate chain to endpoints.`,
                ],
                isAiGeneratedSummary: false,
              },
              evidence,
              affectedResources: [{ id: cert.id, type: 'CERTIFICATE', name: cert.commonName, algorithm: cert.algorithm }],
              expectedBenefit: `Prevents service outage and maintains encrypted communications.`,
              risks: [`Requires endpoint certificate reload.`],
              preconditions: [`Issuing CA must be active and valid.`],
              proposedAction: {
                type: 'EXPEDITE_CERTIFICATE_RENEWAL',
                targetResourceId: cert.id,
                targetResourceType: 'CERTIFICATE',
                isAutomated: false,
                requiresApproval: true,
                requiresFourEyes: false,
              },
              requiredPermissions: ['certificates:issue'],
              verificationProcedure: `Validate new certificate validity period and establish TLS handshake test.`,
              status: 'DETECTED',
              deduplicationKey: dedupeKey,
              createdAt: now,
              updatedAt: now,
            });
          }
        }
      }
    }

    // 3. Analyze Provider Intelligence (Circuit Breakers & High Latency)
    if (snapshot.circuitBreakers && snapshot.circuitBreakers.length > 0) {
      for (const cb of snapshot.circuitBreakers) {
        if (cb.state === 'OPEN' || cb.state === 'HALF_OPEN') {
          const dedupeKey = `PROVIDER_OPTIMIZATION:${cb.providerId}:CIRCUIT_BREAKER_${cb.state}`;
          if (!seenDeduplicationKeys.has(dedupeKey)) {
            seenDeduplicationKeys.add(dedupeKey);

            const evidence = rawEvidence.filter(e => e.resourceId === cb.providerId);
            const severity: SeverityLevel = cb.state === 'OPEN' ? 'CRITICAL' : 'HIGH';
            const score = this.calculatePriorityScore(severity, 1, 'VERIFIED_FACT', true);

            recommendations.push({
              id: `rec-cb-${cb.providerId}`,
              orgId: snapshot.orgId,
              category: 'PROVIDER_OPTIMIZATION',
              severity,
              priorityScore: score,
              title: `Circuit Breaker Tripped (${cb.state}) for Provider "${cb.providerId}"`,
              explanation: {
                summary: `Provider "${cb.providerId}" circuit breaker is ${cb.state} after ${cb.failuresCount} consecutive upstream failures.`,
                observedFacts: [
                  `Provider ID: ${cb.providerId}`,
                  `Circuit State: ${cb.state}`,
                  `Recorded Failures: ${cb.failuresCount}`,
                ],
                technicalRisk: `Upstream KMS or HSM provider is unreachable or returning persistent errors, blocking cryptographic operations.`,
                businessImpact: `Data-plane encryption/decryption operations for workloads routed to this provider are failing fast.`,
                remediationSteps: [
                  `Inspect cloud provider status (Azure Key Vault / Managed HSM telemetry).`,
                  `Verify Azure Service Principal credentials and RBAC permissions.`,
                  `Trigger circuit breaker health recheck once connectivity is restored.`,
                ],
                isAiGeneratedSummary: false,
              },
              evidence,
              affectedResources: [{ id: cb.providerId, type: 'PROVIDER', name: cb.providerId, provider: cb.providerType }],
              expectedBenefit: `Prevents cascading timeout failures across consumer applications.`,
              risks: [`Requests will fail fast until provider health probe succeeds.`],
              preconditions: [`Provider configuration must be verified.`],
              proposedAction: {
                type: 'ENABLE_CIRCUIT_BREAKER',
                targetResourceId: cb.providerId,
                targetResourceType: 'PROVIDER',
                isAutomated: true,
                requiresApproval: false,
                requiresFourEyes: false,
              },
              requiredPermissions: ['os:write'],
              verificationProcedure: `Run provider diagnostic probe and confirm circuit transitions to CLOSED.`,
              status: 'DETECTED',
              deduplicationKey: dedupeKey,
              createdAt: now,
              updatedAt: now,
            });
          }
        }
      }
    }

    // 4. Analyze Policy Intelligence (Repeated Policy Denials)
    if (snapshot.policyLogs && snapshot.policyLogs.length > 0) {
      const denialMap = new Map<string, { count: number; name: string; lastAlgorithm: string }>();

      for (const log of snapshot.policyLogs) {
        if (log.verdict === 'DENY') {
          const current = denialMap.get(log.policyId) || { count: 0, name: log.policyName, lastAlgorithm: log.algorithmRequested };
          current.count += 1;
          current.lastAlgorithm = log.algorithmRequested;
          denialMap.set(log.policyId, current);
        }
      }

      for (const [policyId, stat] of denialMap.entries()) {
        if (stat.count >= 5) {
          const dedupeKey = `POLICY_OPTIMIZATION:${policyId}:FREQUENT_DENIALS`;
          if (!seenDeduplicationKeys.has(dedupeKey)) {
            seenDeduplicationKeys.add(dedupeKey);

            const evidence = rawEvidence.filter(e => e.resourceId === policyId);
            const severity: SeverityLevel = 'MEDIUM';
            const score = this.calculatePriorityScore(severity, 1, 'VERIFIED_FACT', false);

            recommendations.push({
              id: `rec-pol-${policyId}`,
              orgId: snapshot.orgId,
              category: 'POLICY_OPTIMIZATION',
              severity,
              priorityScore: score,
              title: `Repeated Policy Denials (${stat.count} Denials) on Policy "${stat.name}"`,
              explanation: {
                summary: `Policy "${stat.name}" rejected ${stat.count} client requests, primarily attempting to use algorithm ${stat.lastAlgorithm}.`,
                observedFacts: [
                  `Policy ID: ${policyId}`,
                  `Total Denials: ${stat.count}`,
                  `Rejected Algorithm: ${stat.lastAlgorithm}`,
                ],
                technicalRisk: `Client applications are misconfigured to request non-compliant algorithms or attempting unauthorized cryptographic operations.`,
                businessImpact: `Application errors and rejected cryptographic calls in consumer workloads. Note: This recommendation does NOT propose weakening mandatory policies.`,
                remediationSteps: [
                  `Review application client SDK configurations to update requested algorithm to an authorized algorithm.`,
                  `Review policy scope assignments to confirm whether target environment requires specific policy exemptions.`,
                ],
                isAiGeneratedSummary: false,
              },
              evidence,
              affectedResources: [{ id: policyId, type: 'POLICY', name: stat.name }],
              expectedBenefit: `Reduces avoidable application request failures while maintaining strict cryptographic boundaries.`,
              risks: [`Mandatory policy controls must never be silently relaxed.`],
              preconditions: [`Review requires security officer credentials.`],
              proposedAction: {
                type: 'UPDATE_POLICY_ASSIGNMENT',
                targetResourceId: policyId,
                targetResourceType: 'POLICY',
                isAutomated: false,
                requiresApproval: true,
                requiresFourEyes: true,
              },
              requiredPermissions: ['policies:write'],
              verificationProcedure: `Verify client telemetry after application config update shows zero policy rejections.`,
              status: 'DETECTED',
              deduplicationKey: dedupeKey,
              createdAt: now,
              updatedAt: now,
            });
          }
        }
      }
    }

    // 5. Analyze Post-Quantum Readiness Intelligence
    if (snapshot.cbomAssets && snapshot.cbomAssets.length > 0) {
      const classicalAssets = snapshot.cbomAssets.filter(
        a => a.quantumStatus === 'CLASSICAL' || a.quantumStatus === 'QUANTUM_VULNERABLE'
      );

      if (classicalAssets.length > 0) {
        const dedupeKey = `PQC_READINESS:${snapshot.orgId}:CLASSICAL_INVENTORY`;
        if (!seenDeduplicationKeys.has(dedupeKey)) {
          seenDeduplicationKeys.add(dedupeKey);

          const evidence = rawEvidence.filter(e => e.metricOrFact === 'CBOM_QUANTUM_STATUS');
          const severity: SeverityLevel = 'LOW';
          const score = this.calculatePriorityScore(severity, classicalAssets.length, 'VERIFIED_FACT', false);

          recommendations.push({
            id: `rec-pqc-${snapshot.orgId}`,
            orgId: snapshot.orgId,
            category: 'PQC_READINESS',
            severity,
            priorityScore: score,
            title: `Post-Quantum Migration Readiness: ${classicalAssets.length} Classical Cryptographic Assets Identified`,
            explanation: {
              summary: `${classicalAssets.length} cryptographic assets in inventory rely on classical algorithms (RSA/ECC) susceptible to future quantum cryptanalysis (CRQC).`,
              observedFacts: [
                `Total Classical Assets: ${classicalAssets.length}`,
                `Algorithms Observed: ${Array.from(new Set(classicalAssets.map(a => a.algorithm))).join(', ')}`,
              ],
              technicalRisk: `Store-Now-Decrypt-Later (SNDL) threats target sensitive data encrypted under classical asymmetric keys with long retention lifetimes.`,
              businessImpact: `Long-term data security exposure for highly confidential assets; future compliance gap with CNSA 2.0 timeline.`,
              remediationSteps: [
                `Assess long-term confidentiality requirements for identified assets.`,
                `Deploy hybrid or quantum-safe algorithms (e.g. ML-KEM-768 for KEM, ML-DSA-65 for signatures) using the AMARACUS Migration Platform.`,
              ],
              isAiGeneratedSummary: false,
            },
            evidence,
            affectedResources: classicalAssets.map(a => ({ id: a.id, type: 'CBOM_ASSET', name: a.name, algorithm: a.algorithm })),
            expectedBenefit: `Future-proofs sensitive data assets against post-quantum cryptanalysis threats.`,
            risks: [`Requires client endpoints to support larger ciphertext and key sizes.`],
            preconditions: [`AMARACUS PQC engine is enabled.`],
            proposedAction: {
              type: 'PLAN_MIGRATION',
              targetResourceId: classicalAssets[0].id,
              targetResourceType: 'CBOM_ASSET',
              isAutomated: false,
              requiresApproval: true,
              requiresFourEyes: false,
            },
            requiredPermissions: ['migrations:plan'],
            verificationProcedure: `Simulate PQC migration plan using the Migration Platform simulator.`,
            status: 'DETECTED',
            deduplicationKey: dedupeKey,
            createdAt: now,
            updatedAt: now,
          });
        }
      }
    }

    // 6. Analyze Cost & Reliability Efficiency
    if (snapshot.usage && snapshot.usage.length > 0) {
      for (const u of snapshot.usage) {
        if (u.failedOperations > 0 && u.totalOperations > 0) {
          const failureRatePct = (u.failedOperations / u.totalOperations) * 100;
          if (failureRatePct >= 5.0) {
            const dedupeKey = `RELIABILITY:${snapshot.orgId}:HIGH_FAILURE_RATE`;
            if (!seenDeduplicationKeys.has(dedupeKey)) {
              seenDeduplicationKeys.add(dedupeKey);

              const evidence = rawEvidence.filter(e => e.metricOrFact === 'OPERATION_FAILURE_RATE_PCT');
              const severity: SeverityLevel = 'HIGH';
              const score = this.calculatePriorityScore(severity, 1, 'HIGH_CONFIDENCE', true);

              recommendations.push({
                id: `rec-rel-${snapshot.orgId}`,
                orgId: snapshot.orgId,
                category: 'RELIABILITY',
                severity,
                priorityScore: score,
                title: `Elevated Cryptographic Operation Failure Rate (${failureRatePct.toFixed(1)}%)`,
                explanation: {
                  summary: `Observed a ${failureRatePct.toFixed(1)}% failure rate across ${u.totalOperations} total cryptographic operations.`,
                  observedFacts: [
                    `Total Operations: ${u.totalOperations}`,
                    `Failed Operations: ${u.failedOperations}`,
                    `Failure Rate: ${failureRatePct.toFixed(1)}%`,
                  ],
                  technicalRisk: `Frequent retries cause unnecessary load on cloud HSM providers and degrade client application latency.`,
                  businessImpact: `Degraded end-user experience and potential billable retry consumption.`,
                  remediationSteps: [
                    `Investigate top error codes in operational metrics (e.g. invalid parameters or provider timeouts).`,
                    `Ensure client exponential backoff and jitter configurations are enabled.`,
                  ],
                  isAiGeneratedSummary: false,
                },
                evidence,
                affectedResources: [{ id: snapshot.orgId, type: 'ORGANIZATION', name: `Org ${snapshot.orgId}` }],
                expectedBenefit: `Restores normal operation reliability and reduces redundant network traffic.`,
                risks: [`None.`],
                preconditions: [`Operational logs must be accessible.`],
                proposedAction: {
                  type: 'INVESTIGATE_ANOMALY',
                  targetResourceId: snapshot.orgId,
                  targetResourceType: 'ORGANIZATION',
                  isAutomated: true,
                  requiresApproval: false,
                  requiresFourEyes: false,
                },
                requiredPermissions: ['usage:read'],
                verificationProcedure: `Monitor subsequent period failure rate drops below 1.0%.`,
                status: 'DETECTED',
                deduplicationKey: dedupeKey,
                createdAt: now,
                updatedAt: now,
              });
            }
          }
        }
      }
    }

    // Sort descending by deterministic priority score
    return recommendations.sort((a, b) => b.priorityScore - a.priorityScore);
  }

  /**
   * Deterministic Priority Score Formula:
   * - Severity: CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10, INFORMATIONAL=5
   * - Blast Radius: 1=5, 2-5=15, >5=25
   * - Evidence Confidence: VERIFIED_FACT=20, HIGH_CONFIDENCE=15, MEDIUM_CONFIDENCE=10, ESTIMATE=5
   * - Urgency: +15 if urgent
   * Clamped between 0 and 100.
   */
  public static calculatePriorityScore(
    severity: SeverityLevel,
    affectedCount: number,
    confidence: EvidenceConfidenceLevel,
    isUrgent: boolean = false

  ): number {
    let score = 0;

    // Severity component
    switch (severity) {
      case 'CRITICAL': score += 40; break;
      case 'HIGH': score += 30; break;
      case 'MEDIUM': score += 20; break;
      case 'LOW': score += 10; break;
      case 'INFORMATIONAL': score += 5; break;
    }

    // Blast radius component
    if (affectedCount > 5) {
      score += 25;
    } else if (affectedCount >= 2) {
      score += 15;
    } else {
      score += 5;
    }

    // Confidence component
    switch (confidence) {
      case 'VERIFIED_FACT': score += 20; break;
      case 'HIGH_CONFIDENCE': score += 15; break;
      case 'MEDIUM_CONFIDENCE': score += 10; break;
      case 'ESTIMATE':
      case 'INFERRED': score += 5; break;
    }

    // Urgency component
    if (isUrgent) {
      score += 15;
    }

    return Math.min(100, Math.max(0, score));
  }

  /**
   * Checks if an algorithm is considered deprecated by NIST/FIPS standards.
   */
  public static isDeprecatedAlgorithm(algorithm: string): boolean {
    const alg = (algorithm || '').toUpperCase().trim();
    return (
      alg.includes('3DES') ||
      alg.includes('DES') ||
      alg.includes('RC4') ||
      alg.includes('MD5') ||
      alg.includes('SHA1') ||
      alg.includes('SHA-1') ||
      alg === 'AES-128-ECB' ||
      alg === 'AES-256-ECB'
    );
  }
}
