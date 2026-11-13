/**
 * AMARACUS Cryptographic Infrastructure — Policy Engine Types
 *
 * Defines the standardized cryptographic policy decision model, context,
 * evaluation rules, category models, and audit trace structures.
 */

import { KeyReference } from '../runtime/key-reference';
import { AlgorithmStatus } from '../types';

export type PolicyDecisionType =
  | 'ALLOW'
  | 'DENY'
  | 'REQUIRE_CONFIGURATION'
  | 'REQUIRE_STRONGER_ALGORITHM'
  | 'REQUIRE_KEY_ROTATION'
  | 'REQUIRE_APPROVED_PROVIDER';

export type PolicyScope =
  | 'GLOBAL'
  | 'ORGANIZATION'
  | 'PROJECT'
  | 'ENVIRONMENT'
  | 'OPERATION';

export type PolicyCategory =
  | 'ALGORITHM_POLICY'
  | 'KEY_POLICY'
  | 'PROVIDER_POLICY'
  | 'OPERATION_POLICY'
  | 'ROTATION_POLICY'
  | 'PQC_POLICY'
  | 'CERTIFICATE_POLICY'
  | 'ENVIRONMENT_POLICY'
  | 'COMPLIANCE_POLICY'
  | 'CRYPTO_AGILITY_POLICY';

export type PqcEnforcementMode =
  | 'PQC_REQUIRED'
  | 'PQC_PREFERRED'
  | 'PQC_ALLOWED'
  | 'PQC_NOT_ALLOWED';

export interface PolicyRuleCondition {
  operationTypes?: string[];
  algorithms?: string[];
  prohibitedAlgorithms?: string[];
  minRsaBits?: number;
  minEccBits?: number;
  minSymmetricBits?: number;
  maxKeyAgeDays?: number;
  requireHardwareBacked?: boolean;
  requireFips?: boolean;
  requireCustomerVault?: boolean;
  pqcMode?: PqcEnforcementMode;
  environmentTypes?: string[];
  blockDeprecated?: boolean;
  maxCertificateLifetimeDays?: number;
}

export interface PolicyRule {
  id: string;
  category: PolicyCategory;
  name: string;
  description?: string;
  effect: 'ALLOW' | 'DENY' | 'REQUIRE';
  requirementType?: PolicyDecisionType;
  priority?: number;
  condition: PolicyRuleCondition;
  remediation?: string;
}

export interface PolicyDocument {
  id: string;
  name: string;
  version: string;
  description?: string;
  scope: PolicyScope;
  scopeId?: string | null;
  rules: PolicyRule[];
  isActive?: boolean;
  enforcementMode?: 'ENFORCE' | 'AUDIT' | 'DISABLED';
  metadata?: Record<string, any>;
  createdAt?: Date;
  updatedAt?: Date;
}

export interface PolicyEvaluationContext {
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  environmentType?: 'production' | 'staging' | 'development' | string;
  operationType: string;
  algorithm?: string | null;
  keyId?: string | null;
  keyReference?: KeyReference | null;
  keyAgeDays?: number;
  keyCreatedAt?: Date | null;
  providerId?: string | null;
  complianceProfile?: 'FIPS_COMPLIANT' | 'PQC_PREFERRED' | 'DEFAULT_SECURE' | string;
  dataClassification?: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED' | string;
  isHistoricalDecryption?: boolean;
}

export interface PolicyTraceStep {
  level: PolicyScope;
  policyId: string;
  policyName: string;
  ruleId?: string;
  decision: PolicyDecisionType;
  reason: string;
  timestamp: string;
}

export interface PolicyDecision {
  decision: PolicyDecisionType;
  allowed: boolean;
  policyVersion: string;
  reasons: string[];
  requirements: string[];
  warnings: string[];
  recommendations: string[];
  evaluatedPolicies: string[];
  trace: PolicyTraceStep[];
  timestamp: string;
}

export interface PolicySimulationImpact {
  affectedKeys: Array<{ id: string; name: string; algorithm: string; reason: string }>;
  affectedCertificates: Array<{ id: string; subject: string; algorithm: string; reason: string }>;
  affectedOperations: string[];
  affectedProjects: string[];
  summary: {
    totalEvaluated: number;
    wouldAllow: number;
    wouldDeny: number;
    wouldRequireChange: number;
    compliantCount?: number;
    nonCompliantCount?: number;
    breakageCount?: number;
  };
  impacts?: Array<{
    assetId: string;
    assetType: 'KEY' | 'OPERATION' | 'FINDING';
    algorithm?: string;
    compliant: boolean;
    previousDecision: PolicyDecisionType;
    simulatedDecision: PolicyDecisionType;
    violations: string[];
    recommendations: string[];
  }>;
  conflicts?: string[];
  timestamp?: string;
}
