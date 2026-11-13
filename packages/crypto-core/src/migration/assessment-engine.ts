/**
 * AMARACUS Cryptographic Migration Platform — Migration Assessment Engine
 *
 * Scans real inventory assets, CBOM components, certificates, and findings to identify
 * viable migration candidates. Categorizes assets into Categories A, B, and C.
 */

import {
  MigrationAssessmentItem,
  MigrationCategory,
  MigrationType,
} from './types';
import { MigrationPriorityScorer } from './priority-scorer';
import { CryptoMigrationEngine } from '../intelligence/agility';

export interface AssessmentAssetInput {
  id: string;
  name: string;
  assetType: 'KEY' | 'CERTIFICATE' | 'ALGORITHM' | 'LIBRARY' | 'APPLICATION';
  source?: string;
  algorithm: string;
  provider?: string;
  expiresAt?: string | null;
  status?: string;
  isManagedByAmaracus?: boolean;
  metadata?: Record<string, any>;
}

export class MigrationAssessmentEngine {
  /**
   * Run end-to-end assessment across a collection of discovered cryptographic assets.
   */
  public static assessAssets(
    assets: AssessmentAssetInput[],
    organizationId: string
  ): MigrationAssessmentItem[] {
    const assessments: MigrationAssessmentItem[] = [];

    for (const asset of assets) {
      const normAlg = (asset.algorithm || '').toUpperCase().trim();
      const isManaged = asset.isManagedByAmaracus ?? (asset.source !== 'SOURCE_CODE_SCAN' && asset.source !== 'STATIC_ANALYSIS');

      // 1. Determine Migration Category
      let category: MigrationCategory = 'CATEGORY_A_AMARACUS_MANAGED';
      if (asset.source === 'SOURCE_CODE_SCAN' || asset.assetType === 'APPLICATION' || asset.assetType === 'LIBRARY') {
        category = 'CATEGORY_C_APPLICATION_MANAGED';
      } else if (
        asset.provider?.toLowerCase().includes('azure') ||
        asset.provider?.toLowerCase().includes('aws') ||
        asset.provider?.toLowerCase().includes('external')
      ) {
        category = 'CATEGORY_B_INTEGRATED_EXTERNAL';
      } else if (isManaged) {
        category = 'CATEGORY_A_AMARACUS_MANAGED';
      } else {
        category = 'CATEGORY_C_APPLICATION_MANAGED';
      }

      // 2. Assess Deprecated / Broken Algorithms (DES, MD5, SHA-1, etc.)
      if (
        normAlg.includes('DES') ||
        normAlg.includes('MD5') ||
        normAlg.includes('SHA-1') ||
        normAlg.includes('RC4')
      ) {
        const rec = CryptoMigrationEngine.getMigrationRecommendation(asset.algorithm);
        const priority = MigrationPriorityScorer.calculate({
          algorithm: asset.algorithm,
          isPolicyViolation: true,
          policySeverity: 'DISALLOWED',
          businessCriticality: 'PRODUCTION',
          estimatedComplexity: category === 'CATEGORY_A_AMARACUS_MANAGED' ? 'LOW' : 'MEDIUM',
        });

        assessments.push({
          id: `assess_${asset.id}_depr`,
          assetId: asset.id,
          assetName: asset.name,
          category,
          migrationType: 'DEPRECATED_ALGORITHM_REPLACEMENT',
          currentAlgorithm: asset.algorithm,
          recommendedAlgorithm: rec.recommendedAlgorithm,
          currentProvider: asset.provider,
          recommendedProvider: asset.provider,
          reason: `Deprecated algorithm '${asset.algorithm}' violates cryptographic baseline. Upgrade to '${rec.recommendedAlgorithm}'.`,
          prerequisites: ['Verify consuming applications support AES-256-GCM / SHA-256 envelope format.'],
          compatibilityRisks: [
            category === 'CATEGORY_C_APPLICATION_MANAGED'
              ? 'Application code rewrite required for cipher initializations.'
              : 'Legacy ciphertext encrypted with previous cipher requires staged re-encryption.',
          ],
          potentialDowntime: 'Zero (phased parallel dual-read deployment).',
          dataConversionRequired: normAlg.includes('DES') || normAlg.includes('AES-128'),
          estimatedComplexity: category === 'CATEGORY_A_AMARACUS_MANAGED' ? 'LOW' : 'MEDIUM',
          requiredApprovals: ['SECURITY_ADMIN', 'ADMIN'],
          verificationCriteria: [
            'Test vector encryption/decryption succeeds with target algorithm.',
            'Target algorithm allowed by active policy.',
          ],
          priority,
          codeMigrationSnippet: {
            language: 'typescript',
            before: `// Deprecated legacy cipher\nconst cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);`,
            after: `// AMARACUS AEAD Envelope\nconst encrypted = await amaracus.crypto.encrypt({\n  algorithm: 'AES-256-GCM',\n  plaintext: data,\n  keyId: '${asset.id}'\n});`,
            diffNotes: 'Replaced vulnerable DES cipher with authenticated AES-256-GCM envelope.',
          },
        });
        continue;
      }

      // 3. Assess Expiring or Deprecated Certificates
      if (asset.assetType === 'CERTIFICATE') {
        let daysUntilExpiry: number | null = null;
        if (asset.expiresAt) {
          const expTime = new Date(asset.expiresAt).getTime();
          daysUntilExpiry = Math.ceil((expTime - Date.now()) / (1000 * 60 * 60 * 24));
        }

        const isExpiringSoon = daysUntilExpiry !== null && daysUntilExpiry <= 90;
        const isClassicalRsa = normAlg.includes('RSA');

        if (isExpiringSoon || isClassicalRsa) {
          const recAlg = isClassicalRsa ? 'ML-DSA-65' : asset.algorithm;
          const priority = MigrationPriorityScorer.calculate({
            algorithm: asset.algorithm,
            daysUntilExpiry,
            businessCriticality: 'PRODUCTION',
            estimatedComplexity: 'LOW',
          });

          assessments.push({
            id: `assess_${asset.id}_cert`,
            assetId: asset.id,
            assetName: asset.name,
            category,
            migrationType: 'CERTIFICATE_REPLACEMENT',
            currentAlgorithm: asset.algorithm,
            recommendedAlgorithm: recAlg,
            currentProvider: asset.provider,
            reason: isExpiringSoon
              ? `Certificate '${asset.name}' expires in ${daysUntilExpiry} days.`
              : `Certificate uses classical RSA; transition to quantum-safe ML-DSA-65 or Ed25519 recommended.`,
            prerequisites: ['Valid Issuer Authority or AMARACUS PKI CA operational.'],
            compatibilityRisks: ['Clients without updated root trust chains must install new CA certificate.'],
            potentialDowntime: 'Zero (graceful dual-certificate deployment).',
            dataConversionRequired: false,
            estimatedComplexity: 'LOW',
            requiredApprovals: ['SECURITY_ADMIN'],
            verificationCriteria: [
              'Replacement certificate issued with valid X.509 format.',
              'Chain validates to root CA.',
              'Old certificate retained until replacement confirmed operational.',
            ],
            priority,
          });
        }
        continue;
      }

      // 4. Assess Post-Quantum Migration Candidates (Classical Asymmetric: RSA, ECDSA, ECDH)
      if (
        normAlg.includes('RSA') ||
        normAlg.includes('ECDSA') ||
        normAlg.includes('ED25519') ||
        normAlg.includes('ECDH') ||
        normAlg.includes('X25519')
      ) {
        const isSignature = normAlg.includes('RSA') || normAlg.includes('ECDSA') || normAlg.includes('ED25519');
        const recommendedAlgorithm = isSignature ? 'ML-DSA-65' : 'X25519+ML-KEM-768';

        const priority = MigrationPriorityScorer.calculate({
          algorithm: asset.algorithm,
          policySeverity: 'COMPLIANT',
          businessCriticality: 'PRODUCTION',
          estimatedComplexity: 'MEDIUM',
        });

        assessments.push({
          id: `assess_${asset.id}_pqc`,
          assetId: asset.id,
          assetName: asset.name,
          category,
          migrationType: 'POST_QUANTUM_MIGRATION',
          currentAlgorithm: asset.algorithm,
          recommendedAlgorithm,
          currentProvider: asset.provider,
          recommendedProvider: asset.provider?.includes('azure') ? 'software' : asset.provider,
          reason: `Asset '${asset.name}' relies on classical asymmetric cryptography vulnerable to quantum cryptanalysis (Shor algorithm).`,
          prerequisites: ['Verify client library supports NIST FIPS 203/204 key sizes.'],
          compatibilityRisks: ['Larger public key and ciphertext/signature payload sizes.'],
          potentialDowntime: 'Zero with hybrid dual-run transition.',
          dataConversionRequired: false,
          estimatedComplexity: 'MEDIUM',
          requiredApprovals: ['SECURITY_ADMIN', 'ADMIN'],
          verificationCriteria: [
            'Target PQC key generated with verified parameters.',
            'Encapsulation/Decapsulation or Sign/Verify test roundtrip succeeds.',
          ],
          priority,
          codeMigrationSnippet: {
            language: 'typescript',
            before: `// Classical key exchange\nconst sharedSecret = await crypto.diffieHellman(...);`,
            after: `// Quantum-Safe Hybrid KEM (X-Wing)\nconst kemResult = await amaracus.pqc.encapsulate({\n  algorithm: 'ML-KEM-768',\n  publicKey: targetPublicKey\n});`,
            diffNotes: 'Migrated to post-quantum key encapsulation mechanism.',
          },
        });
      }

      // 5. Assess Key Provider Migration (Software -> Hardware HSM)
      if (
        isManaged &&
        (!asset.provider || asset.provider === 'software' || asset.provider === 'internal') &&
        (normAlg.includes('AES') || normAlg.includes('RSA'))
      ) {
        const priority = MigrationPriorityScorer.calculate({
          algorithm: asset.algorithm,
          businessCriticality: 'MISSION_CRITICAL',
          estimatedComplexity: 'MEDIUM',
        });

        assessments.push({
          id: `assess_${asset.id}_prov`,
          assetId: asset.id,
          assetName: asset.name,
          category: 'CATEGORY_A_AMARACUS_MANAGED',
          migrationType: 'KEY_PROVIDER_MIGRATION',
          currentAlgorithm: asset.algorithm,
          recommendedAlgorithm: asset.algorithm,
          currentProvider: 'software',
          recommendedProvider: 'azure-managed-hsm',
          reason: `High-value production key '${asset.name}' in software storage is eligible for hardware-isolated FIPS 140-2 Level 3 HSM protection.`,
          prerequisites: ['Active Azure Key Vault / Managed HSM connection configured in organization settings.'],
          compatibilityRisks: ['Keys created in Managed HSM cannot be exported in plaintext.'],
          potentialDowntime: 'Zero (dual-key reference window).',
          dataConversionRequired: false,
          estimatedComplexity: 'MEDIUM',
          requiredApprovals: ['OWNER', 'SECURITY_ADMIN'],
          verificationCriteria: [
            'Target key provisioned inside HSM partition.',
            'Hardware attestation confirmed.',
            'Test cryptographic operation succeeds via HSM provider routing.',
          ],
          priority,
        });
      }
    }

    // Sort by priority score descending (highest priority first)
    return assessments.sort((a, b) => b.priority.score - a.priority.score);
  }
}
