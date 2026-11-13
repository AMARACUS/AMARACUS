import crypto from 'crypto';
import { CryptoAssetItem, CryptoFindingItem, FindingSeverity, FindingCategory } from './types';
import { CRYPTO_POLICIES, CryptoPolicy } from '../policy';

export class PolicyEvaluator {
  /**
   * Audit discovered cryptographic assets against active policy and security standards.
   */
  static evaluateAssets(
    assets: CryptoAssetItem[],
    policyName: string = 'DEFAULT_SECURE',
    customPolicy?: CryptoPolicy
  ): CryptoFindingItem[] {
    const findings: CryptoFindingItem[] = [];
    const policy = customPolicy || CRYPTO_POLICIES[policyName] || CRYPTO_POLICIES['DEFAULT_SECURE'];
    const now = new Date();

    for (const asset of assets) {
      const orgId = asset.organizationId;
      const algoUpper = (asset.algorithm || '').toUpperCase();

      // 1. Certificate Expiration & Validity Checks
      if (asset.assetType === 'CERTIFICATE' || asset.assetType === 'CERTIFICATE_AUTHORITY') {
        const notAfterRaw = asset.metadata?.notAfter;
        if (notAfterRaw) {
          const notAfter = new Date(notAfterRaw);
          const msUntilExp = notAfter.getTime() - now.getTime();
          const daysUntilExp = msUntilExp / (1000 * 60 * 60 * 24);

          if (daysUntilExp < 0) {
            findings.push(this.createFinding({
              organizationId: orgId,
              projectId: asset.projectId,
              environmentId: asset.environmentId,
              affectedAssetId: asset.id,
              severity: 'CRITICAL',
              category: 'EXPIRED_CERTIFICATE',
              title: `Expired Certificate: ${asset.name}`,
              description: `Certificate expired on ${notAfter.toISOString().split('T')[0]} (${Math.abs(Math.round(daysUntilExp))} days ago). Using expired certificates will cause TLS connection failures and security breaches.`,
              evidence: { notAfter: notAfter.toISOString(), expiredDaysAgo: Math.abs(Math.round(daysUntilExp)), serialNumber: asset.metadata?.serialNumber },
              policySource: 'RFC 5280 Section 4.1.2.5',
              remediationGuidance: 'Renew or re-issue certificate immediately using an active Certificate Authority.',
            }));
          } else if (daysUntilExp <= 30) {
            findings.push(this.createFinding({
              organizationId: orgId,
              projectId: asset.projectId,
              environmentId: asset.environmentId,
              affectedAssetId: asset.id,
              severity: 'HIGH',
              category: 'EXPIRING_SOON',
              title: `Certificate Expiring Soon: ${asset.name}`,
              description: `Certificate expires in ${Math.round(daysUntilExp)} days (on ${notAfter.toISOString().split('T')[0]}). Certificates should be rotated at least 30 days prior to expiration.`,
              evidence: { notAfter: notAfter.toISOString(), daysRemaining: Math.round(daysUntilExp), serialNumber: asset.metadata?.serialNumber },
              policySource: 'Enterprise Certificate Hygiene & RFC 5280',
              remediationGuidance: 'Schedule certificate renewal and redeployment to target endpoints.',
            }));
          }
        }

        // Revocation status check
        if (asset.status === 'REVOKED') {
          findings.push(this.createFinding({
            organizationId: orgId,
            projectId: asset.projectId,
            environmentId: asset.environmentId,
            affectedAssetId: asset.id,
            severity: 'CRITICAL',
            category: 'REVOKED_CERTIFICATE_REFERENCED',
            title: `Revoked Certificate Referenced in Inventory: ${asset.name}`,
            description: `The certificate is marked REVOKED in inventory. Ensure all consuming services have cleared their caches and deployed new valid certificates.`,
            evidence: { serialNumber: asset.metadata?.serialNumber, status: asset.status },
            policySource: 'RFC 5280 CRL/OCSP Standards',
            remediationGuidance: 'Remove references to this revoked certificate and replace with a newly issued certificate.',
          }));
        }
      }

      // 2. Algorithm Strength & Deprecation
      if (algoUpper) {
        if (algoUpper.includes('MD5') || algoUpper.includes('SHA-1') || algoUpper.includes('DES') || algoUpper.includes('RC4')) {
          findings.push(this.createFinding({
            organizationId: orgId,
            projectId: asset.projectId,
            environmentId: asset.environmentId,
            affectedAssetId: asset.id,
            severity: 'CRITICAL',
            category: 'DEPRECATED_ALGORITHM',
            title: `Deprecated and Insecure Algorithm: ${asset.algorithm}`,
            description: `Asset "${asset.name}" utilizes "${asset.algorithm}", which is cryptographically broken and vulnerable to practical collision or plaintext recovery attacks.`,
            evidence: { algorithm: asset.algorithm, assetType: asset.assetType, source: asset.source },
            policySource: 'NIST SP 800-131A Rev 2',
            remediationGuidance: 'Immediately replace with SHA-256 (for hashing) or AES-256-GCM (for symmetric encryption).',
          }));
        }

        // RSA Key Size evaluation
        if (algoUpper.includes('RSA')) {
          if (algoUpper.includes('1024') || algoUpper.includes('512')) {
            findings.push(this.createFinding({
              organizationId: orgId,
              projectId: asset.projectId,
              environmentId: asset.environmentId,
              affectedAssetId: asset.id,
              severity: 'CRITICAL',
              category: 'WEAK_KEY_SIZE',
              title: `Weak RSA Key Length (<2048 bits): ${asset.algorithm}`,
              description: `RSA keys below 2048 bits offer less than 80 bits of classical security and are factorable by modern compute clusters.`,
              evidence: { algorithm: asset.algorithm, keyBits: 1024 },
              policySource: 'NIST SP 800-57 Part 1 Rev 5',
              remediationGuidance: 'Rotate to minimum RSA-2048, or migrate directly to post-quantum ML-DSA-65.',
            }));
          } else if (algoUpper.includes('2048')) {
            findings.push(this.createFinding({
              organizationId: orgId,
              projectId: asset.projectId,
              environmentId: asset.environmentId,
              affectedAssetId: asset.id,
              severity: 'LOW',
              category: 'ALGORITHM_MIGRATION_REQUIRED',
              title: `Legacy RSA-2048 Key: Migration Recommended`,
              description: `RSA-2048 provides approximately 112 bits of classical security. NIST recommends migration to 128-bit classical security or post-quantum alternatives.`,
              evidence: { algorithm: asset.algorithm, classicalSecurityBits: 112 },
              policySource: 'NIST Transition Guidelines',
              remediationGuidance: 'Plan migration to ML-DSA-65 or hybrid dual-signature architectures.',
            }));
          }
        }
      }

      // 3. Organization Policy Compliance & Post-Quantum Mandates
      if (policy.requiredSecurityClass === 'PQC_ONLY') {
        if (asset.quantumStatus === 'QUANTUM_VULNERABLE') {
          findings.push(this.createFinding({
            organizationId: orgId,
            projectId: asset.projectId,
            environmentId: asset.environmentId,
            affectedAssetId: asset.id,
            severity: 'HIGH',
            category: 'NON_COMPLIANT_POLICY',
            title: `Policy Violation: Quantum-Vulnerable Primitive in PQC-Only Policy`,
            description: `Active organization policy mandates PQC_ONLY. Asset "${asset.name}" uses classical "${asset.algorithm}", which is vulnerable to Shor's algorithm on a quantum computer.`,
            evidence: { algorithm: asset.algorithm, policyMandate: 'PQC_ONLY', quantumStatus: asset.quantumStatus },
            policySource: `Organization Policy: ${policy.name}`,
            remediationGuidance: 'Replace with NIST standardized PQC primitive (ML-KEM for key exchange, ML-DSA for signatures).',
          }));
        }
      } else if (policy.requiredSecurityClass === 'HYBRID_REQUIRED') {
        if (asset.quantumStatus === 'QUANTUM_VULNERABLE') {
          findings.push(this.createFinding({
            organizationId: orgId,
            projectId: asset.projectId,
            environmentId: asset.environmentId,
            affectedAssetId: asset.id,
            severity: 'MEDIUM',
            category: 'QUANTUM_VULNERABLE_PUBLIC_KEY',
            title: `Hybrid Migration Required: ${asset.name}`,
            description: `Under the HYBRID_REQUIRED policy, classical public-key algorithm "${asset.algorithm}" must be upgraded to a hybrid classical+PQC combiner (e.g. X25519+ML-KEM-768).`,
            evidence: { algorithm: asset.algorithm, policyMandate: 'HYBRID_REQUIRED' },
            policySource: `Organization Policy: ${policy.name}`,
            remediationGuidance: 'Deploy dual-combiner hybrid key exchange to mitigate Store-Now-Decrypt-Later threats.',
          }));
        }
      }
    }

    return findings;
  }

  private static createFinding(params: {
    organizationId: string;
    projectId?: string | null;
    environmentId?: string | null;
    affectedAssetId?: string | null;
    severity: FindingSeverity;
    category: FindingCategory;
    title: string;
    description: string;
    evidence?: Record<string, any>;
    policySource?: string;
    remediationGuidance?: string;
  }): CryptoFindingItem {
    const idSeed = `${params.organizationId}:${params.affectedAssetId}:${params.category}:${params.title}`;
    const id = `fnd_${crypto.createHash('sha256').update(idSeed).digest('hex').slice(0, 16)}`;
    const now = new Date();

    return {
      id,
      organizationId: params.organizationId,
      projectId: params.projectId || null,
      environmentId: params.environmentId || null,
      affectedAssetId: params.affectedAssetId || null,
      severity: params.severity,
      category: params.category,
      title: params.title,
      description: params.description,
      evidence: params.evidence || null,
      policySource: params.policySource || null,
      firstDetectedAt: now,
      lastDetectedAt: now,
      status: 'OPEN',
      remediationGuidance: params.remediationGuidance || null,
      resolvedBy: null,
      resolvedAt: null,
      resolutionComment: null,
      createdAt: now,
      updatedAt: now,
    };
  }
}
