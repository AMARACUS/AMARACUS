/**
 * AMARACUS Cryptographic Migration Platform — Explainable Prioritization Model
 *
 * Implements a transparent, documented mathematical prioritization algorithm:
 * PriorityScore = Severity (0-40) + PolicyViolation (0-25) + Urgency (0-20) + Criticality (0-15) - ComplexityDiscount (0-10)
 *
 * Guaranteed explainability: Every score includes a detailed rationale breakdown.
 */

import { MigrationPriorityScore, MigrationPriorityLevel } from './types';

export interface PriorityScoreInput {
  algorithm: string;
  isPolicyViolation?: boolean;
  policySeverity?: 'DISALLOWED' | 'DEPRECATED' | 'COMPLIANT';
  daysUntilExpiry?: number | null;
  businessCriticality?: 'MISSION_CRITICAL' | 'PRODUCTION' | 'INTERNAL' | 'DEVELOPMENT';
  estimatedComplexity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'EXTREME';
  isCompromised?: boolean;
  dependentApplicationCount?: number;
}

export class MigrationPriorityScorer {
  /**
   * Calculates an explainable priority score with component breakdown and rationale.
   */
  public static calculate(input: PriorityScoreInput): MigrationPriorityScore {
    const normAlg = (input.algorithm || '').toUpperCase().trim();

    // 1. Severity Score (0 - 40)
    let severity = 10;
    let severityReason = 'Standard cryptographic asset';

    if (input.isCompromised) {
      severity = 40;
      severityReason = 'CRITICAL: Asset compromise flagged or indicated';
    } else if (normAlg.includes('DES') || normAlg.includes('MD5')) {
      severity = 40;
      severityReason = 'Broken cipher/hash primitive (known collision/practical decryption attacks)';
    } else if (normAlg.includes('SHA-1') || normAlg.includes('RC4') || (normAlg.includes('RSA') && normAlg.includes('1024'))) {
      severity = 30;
      severityReason = 'Deprecated legacy algorithm with reduced security margin';
    } else if (normAlg.includes('RSA') || normAlg.includes('ECDSA') || normAlg.includes('ECDH')) {
      severity = 20;
      severityReason = 'Classical asymmetric primitive vulnerable to Shor algorithm post-quantum attacks';
    } else if (normAlg.includes('AES-128')) {
      severity = 15;
      severityReason = '128-bit symmetric key under Grover bound reduction (64-bit effective)';
    } else {
      severity = 10;
      severityReason = 'Modern primitive undergoing routine lifecycle management';
    }

    // 2. Policy Violation Score (0 - 25)
    let policyViolation = 0;
    let policyReason = 'Complies with active cryptographic baseline';

    if (input.isPolicyViolation || input.policySeverity === 'DISALLOWED') {
      policyViolation = 25;
      policyReason = 'Violates mandatory organizational cryptographic policy (DISALLOWED)';
    } else if (input.policySeverity === 'DEPRECATED') {
      policyViolation = 15;
      policyReason = 'Allowed under deprecation schedule with phase-out requirement';
    }

    // 3. Expiration Urgency Score (0 - 20)
    let urgency = 0;
    let urgencyReason = 'No immediate expiration urgency';

    if (input.daysUntilExpiry !== undefined && input.daysUntilExpiry !== null) {
      if (input.daysUntilExpiry <= 0) {
        urgency = 20;
        urgencyReason = 'Certificate / Key has expired';
      } else if (input.daysUntilExpiry <= 14) {
        urgency = 18;
        urgencyReason = `Certificate / Key expires within ${input.daysUntilExpiry} days (URGENT)`;
      } else if (input.daysUntilExpiry <= 30) {
        urgency = 14;
        urgencyReason = `Certificate / Key expires in ${input.daysUntilExpiry} days`;
      } else if (input.daysUntilExpiry <= 90) {
        urgency = 8;
        urgencyReason = `Certificate / Key renewal window open (${input.daysUntilExpiry} days remaining)`;
      }
    }

    // 4. Business Criticality Score (0 - 15)
    let criticality = 5;
    const crit = input.businessCriticality || 'PRODUCTION';
    if (crit === 'MISSION_CRITICAL') {
      criticality = 15;
    } else if (crit === 'PRODUCTION') {
      criticality = 10;
    } else if (crit === 'INTERNAL') {
      criticality = 5;
    } else {
      criticality = 2;
    }

    // Extra weight if high application dependency count
    if (input.dependentApplicationCount && input.dependentApplicationCount > 5) {
      criticality = Math.min(15, criticality + 3);
    }

    // 5. Complexity Discount (0 - 10)
    // Higher complexity slightly reduces score to prioritize rapid, high-impact wins
    let complexityDiscount = 0;
    const comp = input.estimatedComplexity || 'MEDIUM';
    if (comp === 'LOW') {
      complexityDiscount = 0;
    } else if (comp === 'MEDIUM') {
      complexityDiscount = 3;
    } else if (comp === 'HIGH') {
      complexityDiscount = 6;
    } else {
      complexityDiscount = 10;
    }

    // Calculate Final Clamped Score (0 - 100)
    const rawScore = severity + policyViolation + urgency + criticality - complexityDiscount;
    const finalScore = Math.max(0, Math.min(100, rawScore));

    let level: MigrationPriorityLevel = 'LOW';
    if (finalScore >= 80) {
      level = 'CRITICAL';
    } else if (finalScore >= 60) {
      level = 'HIGH';
    } else if (finalScore >= 40) {
      level = 'MEDIUM';
    } else {
      level = 'LOW';
    }

    let rationale = `Score: ${finalScore}/100 (${level}). [Severity: +${severity} (${severityReason})], ` +
      `[Policy: +${policyViolation} (${policyReason})], [Urgency: +${urgency} (${urgencyReason})], ` +
      `[Criticality: +${criticality} (${crit})], [Complexity Discount: -${complexityDiscount} (${comp})].`;

    if (input.isCompromised) {
      rationale = `CRITICAL INCIDENT: Asset compromise indicated. Must follow emergency incident-response protocol rather than scheduled migration. ${rationale}`;
    }

    return {
      score: finalScore,
      level,
      components: {
        severity,
        policyViolation,
        urgency,
        criticality,
        complexityDiscount,
      },
      rationale,
    };
  }
}
