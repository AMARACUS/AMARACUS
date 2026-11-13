/**
 * AMARACUS Cryptographic Infrastructure — Phase 19 Cryptographic Migration Platform
 * Core Types and Domain Interfaces
 */

import { AlgorithmId } from '../types';

export type MigrationCategory =
  | 'CATEGORY_A_AMARACUS_MANAGED'
  | 'CATEGORY_B_INTEGRATED_EXTERNAL'
  | 'CATEGORY_C_APPLICATION_MANAGED';

export type MigrationType =
  | 'KEY_ROTATION'
  | 'DEPRECATED_ALGORITHM_REPLACEMENT'
  | 'KEY_PROVIDER_MIGRATION'
  | 'CERTIFICATE_REPLACEMENT'
  | 'POST_QUANTUM_MIGRATION'
  | 'CRYPTO_AGILITY_REMEDIATION'
  | 'DATA_RE_ENCRYPTION';

export type MigrationPlanState =
  | 'DRAFT'
  | 'SIMULATED'
  | 'REVIEWED'
  | 'APPROVED'
  | 'QUEUED'
  | 'EXECUTING'
  | 'VERIFYING'
  | 'COMPLETED'
  | 'FAILED'
  | 'ROLLED_BACK'
  | 'CANCELLED';

export type MigrationPriorityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface MigrationPriorityScore {
  score: number; // 0-100
  level: MigrationPriorityLevel;
  components: {
    severity: number; // 0-40
    policyViolation: number; // 0-25
    urgency: number; // 0-20
    criticality: number; // 0-15
    complexityDiscount: number; // 0-10
  };
  rationale: string;
}

export interface CodeMigrationSnippet {
  language: string;
  before: string;
  after: string;
  diffNotes: string;
}

export interface MigrationAssessmentItem {
  id: string;
  assetId: string;
  assetName: string;
  category: MigrationCategory;
  migrationType: MigrationType;
  currentAlgorithm: string;
  recommendedAlgorithm: string;
  currentProvider?: string;
  recommendedProvider?: string;
  reason: string;
  prerequisites: string[];
  compatibilityRisks: string[];
  potentialDowntime: string;
  dataConversionRequired: boolean;
  estimatedComplexity: 'LOW' | 'MEDIUM' | 'HIGH' | 'EXTREME';
  requiredApprovals: string[];
  verificationCriteria: string[];
  priority: MigrationPriorityScore;
  codeMigrationSnippet?: CodeMigrationSnippet;
}

export interface MigrationDependencyNode {
  id: string;
  type: 'APPLICATION' | 'SDK' | 'LIBRARY' | 'ALGORITHM' | 'KEY' | 'PROVIDER';
  name: string;
  isIncomplete?: boolean;
}

export interface MigrationDependencyEdge {
  from: string;
  to: string;
  relationship: string;
}

export interface MigrationDependencyGraph {
  nodes: MigrationDependencyNode[];
  edges: MigrationDependencyEdge[];
  isIncomplete: boolean;
  incompletenessReasons: string[];
}

export interface PreMigrationCompatibilityResult {
  compatible: boolean;
  policyDecision: string;
  policyReasons: string[];
  algorithmSupported: boolean;
  providerSupported: boolean;
  keyFormatCompatible: boolean;
  blockingIssues: string[];
  warnings: string[];
}

export interface MigrationSimulationReport {
  simulationId: string;
  planId: string;
  simulatedAt: string;
  overallSafe: boolean;
  compatibility: PreMigrationCompatibilityResult;
  impactedAssets: string[];
  dependencyImpact: string[];
  estimatedExecutionDurationMs: number;
  rollbackAvailable: boolean;
  rollbackType: 'AUTOMATIC_REVERSIBLE' | 'MANUAL_RESTORE' | 'IRREVERSIBLE';
  commercialImpact: {
    estimatedBillableOps: number;
    estimatedDataBytes: number;
  };
  recommendations: string[];
}

export interface VerificationCheck {
  checkName: string;
  passed: boolean;
  message: string;
  details?: Record<string, any>;
}

export interface MigrationVerificationResult {
  verified: boolean;
  timestamp: string;
  checks: VerificationCheck[];
}

export interface MigrationRollbackPlan {
  isReversible: boolean;
  strategy: 'AUTOMATIC_REFERENCE_SWAP' | 'CHECKPOINT_RESTORE' | 'MANUAL_RUNBOOK';
  steps: string[];
  requiredBackups: string[];
}

export interface MigrationPlan {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  name: string;
  description?: string | null;
  category: MigrationCategory;
  migrationType: MigrationType;
  status: MigrationPlanState;
  sourceResourceId: string;
  targetResourceId?: string | null;
  sourceAlgorithm: string;
  targetAlgorithm: string;
  sourceProvider?: string | null;
  targetProvider?: string | null;
  proposerId: string;
  approverId?: string | null;
  approvedAt?: string | null;
  executionSequence: string[];
  verificationSteps: string[];
  rollbackPlan: MigrationRollbackPlan;
  simulationReport?: MigrationSimulationReport | null;
  verificationResult?: MigrationVerificationResult | null;
  errorMessage?: string | null;
  createdAt: string;
  updatedAt: string;
}
