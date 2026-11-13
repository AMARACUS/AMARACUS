/**
 * AMARACUS Cryptographic Infrastructure — Policy Conflict Detector
 *
 * Analyzes multiple policy documents across the hierarchy to detect
 * contradictory rules, precedence violations, or attempts by lower-level
 * policies to weaken higher-level mandatory security baselines.
 */

import { PolicyDocument, PolicyRule } from './types';

export interface PolicyConflict {
  ruleA: { policyId: string; policyName: string; ruleId: string; description?: string };
  ruleB: { policyId: string; policyName: string; ruleId: string; description?: string };
  conflictType: 'SECURITY_WEAKENING_ATTEMPT' | 'CONTRADICTORY_ALGORITHM_RULES' | 'INCOMPATIBLE_REQUIREMENTS';
  description: string;
  resolution: string;
}

export class PolicyConflictDetector {
  /**
   * Audits an ordered list of policies (from highest authority to lowest authority)
   * or a pair of policies and reports any conflicts or invalid overriding attempts.
   */
  public static detectConflicts(
    policiesOrFirst: PolicyDocument[] | PolicyDocument,
    second?: PolicyDocument
  ): PolicyConflict[] {
    let policies: PolicyDocument[];
    if (Array.isArray(policiesOrFirst)) {
      policies = policiesOrFirst;
    } else if (second) {
      const scopeRank: Record<string, number> = {
        GLOBAL: 1,
        ORGANIZATION: 2,
        PROJECT: 3,
        ENVIRONMENT: 4,
        OPERATION: 5,
      };
      const rankA = scopeRank[policiesOrFirst.scope] || 99;
      const rankB = scopeRank[second.scope] || 99;
      policies = rankA <= rankB ? [policiesOrFirst, second] : [second, policiesOrFirst];
    } else {
      policies = [policiesOrFirst];
    }

    const conflicts: PolicyConflict[] = [];

    for (let i = 0; i < policies.length; i++) {
      const higherPolicy = policies[i];

      for (let j = i + 1; j < policies.length; j++) {
        const lowerPolicy = policies[j];

        for (const higherRule of higherPolicy.rules) {
          for (const lowerRule of lowerPolicy.rules) {
            // Check algorithm conflicts
            const isHigherAlgo = higherRule.category === 'ALGORITHM_POLICY' || (higherRule.category as string) === 'ALGORITHM_RESTRICTION';
            const isLowerAlgo = lowerRule.category === 'ALGORITHM_POLICY' || (lowerRule.category as string) === 'ALGORITHM_RESTRICTION';

            const higherCond: any = { ...(higherRule.condition || {}), ...higherRule };
            const lowerCond: any = { ...(lowerRule.condition || {}), ...lowerRule };

            if (isHigherAlgo && isLowerAlgo) {
              const higherProhibited: string[] = higherCond.prohibitedAlgorithms || [];
              const lowerAllowed: string[] = lowerCond.algorithms || lowerCond.allowedAlgorithms || [];

              // Check if lower policy tries to allow what higher policy explicitly prohibits
              for (const prohibited of higherProhibited) {
                if (lowerAllowed.includes(prohibited)) {
                  conflicts.push({
                    ruleA: { policyId: higherPolicy.id, policyName: higherPolicy.name, ruleId: higherRule.id },
                    ruleB: { policyId: lowerPolicy.id, policyName: lowerPolicy.name, ruleId: lowerRule.id },
                    conflictType: 'SECURITY_WEAKENING_ATTEMPT',
                    description: `Higher authority policy '${higherPolicy.name}' explicitly prohibits algorithm '${prohibited}', but lower policy '${lowerPolicy.name}' attempts to allow it.`,
                    resolution: `Higher authority '${higherPolicy.name}' takes precedence. Operation with '${prohibited}' will be DENIED.`,
                  });
                }
              }
            }

            // Check PQC requirement conflicts
            if (
              (higherCond.pqcMode === 'PQC_REQUIRED' || higherCond.requirePqc === true) &&
              (lowerCond.pqcMode === 'PQC_NOT_ALLOWED' || lowerCond.requirePqc === false)
            ) {
              conflicts.push({
                ruleA: { policyId: higherPolicy.id, policyName: higherPolicy.name, ruleId: higherRule.id },
                ruleB: { policyId: lowerPolicy.id, policyName: lowerPolicy.name, ruleId: lowerRule.id },
                conflictType: 'INCOMPATIBLE_REQUIREMENTS',
                description: `Higher policy mandates PQC_REQUIRED, while lower policy specifies PQC_NOT_ALLOWED.`,
                resolution: `Higher authority '${higherPolicy.name}' overrides lower policy. PQC remains strictly required.`,
              });
            }
          }
        }
      }
    }

    return conflicts;
  }
}
