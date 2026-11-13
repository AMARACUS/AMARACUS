/**
 * @file packages/crypto-core/src/os/posture-engine.ts
 * Unified Cryptographic Security Posture & Deduplication Engine (Phase 20)
 */

import { PostureFinding, UnifiedPostureSummary, UnifiedResource, PostureCategory } from './types';

export class UnifiedPostureEngine {
  /**
   * Evaluates organization resources and aggregates a unified security posture.
   */
  public static evaluatePosture(
    resources: UnifiedResource[],
    options: {
      activePolicyProfile?: string;
      circuitBreakerStates?: Record<string, 'CLOSED' | 'HALF_OPEN' | 'OPEN'>;
      now?: Date;
    } = {}
  ): UnifiedPostureSummary {
    const now = options.now || new Date();
    const findingsMap = new Map<string, PostureFinding>();

    let totalAsymmetricKeys = 0;
    let pqcKeys = 0;
    let verifiedCount = 0;

    for (const res of resources) {
      if (res.verified) {
        verifiedCount++;
      } else {
        // Incomplete/unverified inventory finding
        const dedupeKey = `INCOMPLETE_INVENTORY:${res.id}:UNVERIFIED`;
        findingsMap.set(dedupeKey, {
          id: `find_${Math.random().toString(36).substring(2, 10)}`,
          code: 'UNVERIFIED_RESOURCE_TELEMETRY',
          severity: 'LOW',
          title: `Unverified Cryptographic Resource: ${res.name}`,
          description: `Resource was inferred from unverified external logs without authoritative key storage confirmation.`,
          category: 'INCOMPLETE_INVENTORY',
          affectedResourceId: res.id,
          affectedResourceType: res.type,
          remediation: {
            action: 'Verify resource ownership or configure active telemetry probe.',
            automatedFixAvailable: false,
          },
          source: 'UnifiedResourceModel',
          deduplicationKey: dedupeKey,
          detectedAt: now.toISOString(),
        });
      }

      // 1. Evaluate Keys
      if (res.type === 'KEY') {
        const alg = (res.algorithm || res.metadata?.algorithm || '').toUpperCase();

        // Check PQC readiness
        const isAsymmetric = alg.includes('RSA') || alg.includes('ECDSA') || alg.includes('ED25519') || alg.includes('ML-');
        if (isAsymmetric) {
          totalAsymmetricKeys++;
          if (alg.includes('ML-KEM') || alg.includes('ML-DSA') || alg.includes('X25519+ML-KEM')) {
            pqcKeys++;
          } else {
            // Post-Quantum readiness gap finding
            const dedupeKey = `PQC_GAP:${res.id}:CLASSICAL_ALGORITHM`;
            findingsMap.set(dedupeKey, {
              id: `find_${Math.random().toString(36).substring(2, 10)}`,
              code: 'PQC_TRANSITION_RECOMMENDED',
              severity: 'LOW',
              title: `Classical Asymmetric Key Lacks Post-Quantum Protection: ${res.name}`,
              description: `Key relies on classical discrete logarithm or factorization (${alg}) vulnerable to Store-Now-Decrypt-Later attacks.`,
              category: 'PQC_GAP',
              affectedResourceId: res.id,
              affectedResourceType: 'KEY',
              remediation: {
                action: 'Plan transition to hybrid X-Wing or NIST FIPS 203 ML-KEM-768.',
                recommendedPlanType: 'PQC_TRANSITION',
                workflowTemplateId: 'tpl_pqc_transition',
                automatedFixAvailable: true,
              },
              source: 'UnifiedPostureEngine',
              deduplicationKey: dedupeKey,
              detectedAt: now.toISOString(),
            });
          }
        }

        // Check Deprecated or Broken Algorithms
        if (alg.includes('3DES') || alg.includes('DES') || alg.includes('RC4') || alg.includes('MD5') || (alg.includes('RSA') && alg.includes('1024'))) {
          const dedupeKey = `DEPRECATED_ALGORITHM:${res.id}:${alg}`;
          findingsMap.set(dedupeKey, {
            id: `find_${Math.random().toString(36).substring(2, 10)}`,
            code: 'DEPRECATED_ALGORITHM_DETECTED',
            severity: 'CRITICAL',
            title: `Cryptographically Deprecated Algorithm: ${alg}`,
            description: `Key uses deprecated primitive ${alg} vulnerable to modern cryptanalysis.`,
            category: 'DEPRECATED_ALGORITHM',
            affectedResourceId: res.id,
            affectedResourceType: 'KEY',
            remediation: {
              action: 'Execute immediate key rotation to AES-256-GCM or FIPS-compliant cipher.',
              recommendedPlanType: 'KEY_ROTATION',
              workflowTemplateId: 'tpl_key_rotation',
              automatedFixAvailable: true,
            },
            source: 'AlgorithmRegistry',
            deduplicationKey: dedupeKey,
            detectedAt: now.toISOString(),
          });
        }

        // Check Key Rotation Deadlines
        const createdAt = new Date(res.createdAt || 0).getTime();
        const ageDays = (now.getTime() - createdAt) / (1000 * 60 * 60 * 24);
        if (ageDays > 90 && res.status === 'ACTIVE') {
          const dedupeKey = `KEY_ROTATION:${res.id}:AGE_EXCEEDED`;
          findingsMap.set(dedupeKey, {
            id: `find_${Math.random().toString(36).substring(2, 10)}`,
            code: 'KEY_ROTATION_OVERDUE',
            severity: 'MEDIUM',
            title: `Key Exceeds 90-Day Rotation Policy: ${res.name}`,
            description: `Key has been active for ${Math.round(ageDays)} days without version rotation.`,
            category: 'KEY_ROTATION',
            affectedResourceId: res.id,
            affectedResourceType: 'KEY',
            remediation: {
              action: 'Trigger staged key rotation workflow.',
              recommendedPlanType: 'KEY_ROTATION',
              workflowTemplateId: 'tpl_key_rotation',
              automatedFixAvailable: true,
            },
            source: 'KeyLifecycleManager',
            deduplicationKey: dedupeKey,
            detectedAt: now.toISOString(),
          });
        }
      }

      // 2. Evaluate Certificates
      if (res.type === 'CERTIFICATE') {
        const expiresAt = new Date(res.metadata?.validTo || res.metadata?.expiresAt || 0).getTime();
        if (expiresAt > 0) {
          const daysRemaining = (expiresAt - now.getTime()) / (1000 * 60 * 60 * 24);
          if (daysRemaining <= 0) {
            const dedupeKey = `CERT_EXPIRATION:${res.id}:EXPIRED`;
            findingsMap.set(dedupeKey, {
              id: `find_${Math.random().toString(36).substring(2, 10)}`,
              code: 'CERTIFICATE_EXPIRED',
              severity: 'CRITICAL',
              title: `Expired X.509 Certificate: ${res.name}`,
              description: `Certificate expired on ${new Date(expiresAt).toISOString()}.`,
              category: 'CERT_EXPIRATION',
              affectedResourceId: res.id,
              affectedResourceType: 'CERTIFICATE',
              remediation: {
                action: 'Renew certificate immediately via PKI Certificate Authority.',
                workflowTemplateId: 'tpl_cert_renewal',
                automatedFixAvailable: true,
              },
              source: 'PkiEngine',
              deduplicationKey: dedupeKey,
              detectedAt: now.toISOString(),
            });
          } else if (daysRemaining <= 14) {
            const dedupeKey = `CERT_EXPIRATION:${res.id}:EXPIRING_SOON`;
            findingsMap.set(dedupeKey, {
              id: `find_${Math.random().toString(36).substring(2, 10)}`,
              code: 'CERTIFICATE_EXPIRING_IMMINENT',
              severity: 'HIGH',
              title: `Certificate Expiring in ${Math.round(daysRemaining)} Days: ${res.name}`,
              description: `Certificate expires soon on ${new Date(expiresAt).toISOString()}.`,
              category: 'CERT_EXPIRATION',
              affectedResourceId: res.id,
              affectedResourceType: 'CERTIFICATE',
              remediation: {
                action: 'Schedule certificate renewal before expiration deadline.',
                workflowTemplateId: 'tpl_cert_renewal',
                automatedFixAvailable: true,
              },
              source: 'PkiEngine',
              deduplicationKey: dedupeKey,
              detectedAt: now.toISOString(),
            });
          } else if (daysRemaining <= 30) {
            const dedupeKey = `CERT_EXPIRATION:${res.id}:EXPIRING_30D`;
            findingsMap.set(dedupeKey, {
              id: `find_${Math.random().toString(36).substring(2, 10)}`,
              code: 'CERTIFICATE_EXPIRING_30_DAYS',
              severity: 'MEDIUM',
              title: `Certificate Expiring in ${Math.round(daysRemaining)} Days: ${res.name}`,
              description: `Certificate reaches end of validity on ${new Date(expiresAt).toISOString()}.`,
              category: 'CERT_EXPIRATION',
              affectedResourceId: res.id,
              affectedResourceType: 'CERTIFICATE',
              remediation: {
                action: 'Plan certificate renewal.',
                workflowTemplateId: 'tpl_cert_renewal',
                automatedFixAvailable: true,
              },
              source: 'PkiEngine',
              deduplicationKey: dedupeKey,
              detectedAt: now.toISOString(),
            });
          }
        }
      }

      // 3. Evaluate Providers
      if (res.type === 'PROVIDER') {
        const providerName = res.name.toLowerCase();
        const cbState = options.circuitBreakerStates?.[providerName];
        if (cbState === 'OPEN') {
          const dedupeKey = `PROVIDER_HEALTH:${res.id}:CIRCUIT_BREAKER_OPEN`;
          findingsMap.set(dedupeKey, {
            id: `find_${Math.random().toString(36).substring(2, 10)}`,
            code: 'PROVIDER_CIRCUIT_BREAKER_OPEN',
            severity: 'CRITICAL',
            title: `Cryptographic Provider Circuit Breaker Open: ${res.name}`,
            description: `Upstream provider is failing or experiencing high latency; requests are currently failing over.`,
            category: 'PROVIDER_HEALTH',
            affectedResourceId: res.id,
            affectedResourceType: 'PROVIDER',
            remediation: {
              action: 'Inspect cloud KMS IAM permissions, network firewall, or Azure outage status.',
              automatedFixAvailable: false,
            },
            source: 'CircuitBreakerMonitoring',
            deduplicationKey: dedupeKey,
            detectedAt: now.toISOString(),
          });
        }
      }
    }

    const findings = Array.from(findingsMap.values());

    // Calculate score deductions
    let deductions = 0;
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const byCategory: Record<string, number> = {};

    for (const f of findings) {
      if (f.severity === 'CRITICAL') {
        bySeverity.critical++;
        deductions += 20;
      } else if (f.severity === 'HIGH') {
        bySeverity.high++;
        deductions += 10;
      } else if (f.severity === 'MEDIUM') {
        bySeverity.medium++;
        deductions += 5;
      } else if (f.severity === 'LOW') {
        bySeverity.low++;
        deductions += 2;
      } else {
        bySeverity.info++;
      }

      byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    }

    const score = Math.max(0, 100 - deductions);
    const pqcReadinessPercentage =
      totalAsymmetricKeys > 0 ? Math.round((pqcKeys / totalAsymmetricKeys) * 100) : 100;
    const verifiedInventoryPercentage =
      resources.length > 0 ? Math.round((verifiedCount / resources.length) * 100) : 100;

    return {
      score,
      totalFindings: findings.length,
      bySeverity,
      byCategory,
      pqcReadinessPercentage,
      verifiedInventoryPercentage,
      findings,
      evaluatedAt: now.toISOString(),
    };
  }
}
