/**
 * AMARACUS Cryptographic Infrastructure — Recommendation Engine
 *
 * Generates deterministic, explainable security and crypto-agility recommendations.
 *
 * CRITICAL ARCHITECTURAL GUARANTEE:
 * Recommendations provide forward-looking security advice (e.g. PQC migration,
 * hygiene rotation) and MUST NOT block an ALLOW decision.
 */

import { PolicyEvaluationContext } from './types';
import { AlgorithmStatus } from '../types';

export interface CryptographicRecommendation {
  id: string;
  category: 'PQC_MIGRATION' | 'KEY_HYGIENE' | 'ALGORITHM_AGILITY' | 'HARDWARE_BACKING';
  message: string;
  target?: string;
  urgency: 'LOW' | 'MEDIUM' | 'HIGH';
}

export class CryptographicRecommendationEngine {
  /**
   * Generates actionable recommendations based on context, algorithm, and key characteristics.
   */
  public static generateRecommendations(
    context: PolicyEvaluationContext,
    algorithmStatus?: AlgorithmStatus
  ): string[] {
    const recommendations: string[] = [];
    const alg = (context.algorithm || '').toUpperCase().replace(/_/g, '-');

    // 1. Classical Asymmetric to PQC / Hybrid Migration Recommendations
    if (alg.startsWith('RSA-') || alg.startsWith('ECDSA-') || alg === 'ED25519') {
      recommendations.push(
        `[PQC Migration] Operation uses classical asymmetric algorithm '${alg}'. Consider adopting ML-DSA-65 or hybrid post-quantum signatures to mitigate Store-Now-Decrypt-Later threats.`
      );
    }

    if (alg === 'X25519' || alg === 'ECDH') {
      recommendations.push(
        `[PQC Migration] Consider migrating key agreement from '${alg}' to 'X25519+ML-KEM-768' hybrid key encapsulation.`
      );
    }

    // 2. Symmetric Cryptography Hygiene
    if (alg === 'AES-128-GCM') {
      recommendations.push(
        `[Crypto Agility] AES-128-GCM is secure but provides 64-bit security against Grover quantum search. Upgrade to AES-256-GCM for 128-bit quantum security margin.`
      );
    }

    // 3. Key Age Hygiene Recommendations
    if (context.keyAgeDays !== undefined && context.keyAgeDays > 90) {
      recommendations.push(
        `[Key Hygiene] Active key has been in use for ${context.keyAgeDays} days. Enterprise best practices recommend regular cryptographic key rotation every 90-180 days.`
      );
    }

    // 4. Algorithm Deprecation Warnings
    if (algorithmStatus === 'DEPRECATED') {
      recommendations.push(
        `[Deprecation Alert] Algorithm '${alg}' is deprecated and scheduled for future phase-out. Plan transition to standard FIPS-compliant algorithms.`
      );
    }

    // 5. Hardware Backing for Production
    if (
      context.environmentType === 'production' &&
      context.keyReference &&
      !context.keyReference.isHsmBacked
    ) {
      recommendations.push(
        `[Compliance] Key '${context.keyReference.id}' is software-backed in a production environment. Consider provisioning Cloud HSM backed keys for enhanced FIPS 140-3 Level 3 isolation.`
      );
    }

    return recommendations;
  }
}
