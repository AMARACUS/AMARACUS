/**
 * @file packages/crypto-core/src/optimization/types.ts
 * Type definitions for AMARACUS Cryptographic Intelligence & Autonomous Optimization (Phase 21)
 */

export type RecommendationStatus =
  | 'DETECTED'
  | 'UNDER_REVIEW'
  | 'ACCEPTED'
  | 'REJECTED'
  | 'SCHEDULED'
  | 'EXECUTING'
  | 'COMPLETED'
  | 'FAILED'
  | 'DISMISSED';

export type RecommendationCategory =
  | 'SECURITY_RISK'
  | 'KEY_LIFECYCLE'
  | 'PQC_READINESS'
  | 'PROVIDER_OPTIMIZATION'
  | 'POLICY_OPTIMIZATION'
  | 'COST_EFFICIENCY'
  | 'RELIABILITY'
  | 'MIGRATION_RECOMMENDATION';

export type SeverityLevel =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFORMATIONAL';

export type EvidenceConfidenceLevel =
  | 'VERIFIED_FACT'
  | 'HIGH_CONFIDENCE'
  | 'MEDIUM_CONFIDENCE'
  | 'ESTIMATE'
  | 'INFERRED';


export type EvidenceSourceType =
  | 'CBOM_INVENTORY'
  | 'KEY_METADATA'
  | 'CERTIFICATE_METADATA'
  | 'CIRCUIT_BREAKER_TELEMETRY'
  | 'POLICY_EVALUATION_LOG'
  | 'BILLING_USAGE'
  | 'PROVIDER_HEALTH'
  | 'OPERATIONAL_METRICS';

export interface EvidenceReference {
  source: EvidenceSourceType;
  resourceId: string;
  metricOrFact: string;
  observedValue: any;
  thresholdOrStandard?: any;
  timestamp: string;
  isEstimate?: boolean;
  confidence: EvidenceConfidenceLevel;
}


export interface RecommendationExplanation {
  summary: string;
  observedFacts: string[];
  technicalRisk: string;
  businessImpact: string;
  remediationSteps: string[];
  isAiGeneratedSummary?: boolean;
}

export type ActionType =
  | 'ROTATE_KEY'
  | 'PLAN_MIGRATION'
  | 'ENABLE_CIRCUIT_BREAKER'
  | 'REFRESH_POSTURE'
  | 'UPDATE_POLICY_ASSIGNMENT'
  | 'EXPEDITE_CERTIFICATE_RENEWAL'
  | 'OPTIMIZE_PROVIDER_SELECTION'
  | 'INVESTIGATE_ANOMALY';

export interface ProposedAction {
  type: ActionType;
  targetResourceId: string;
  targetResourceType: string;
  parameters?: Record<string, any>;
  isAutomated: boolean;
  requiresApproval: boolean;
  requiresFourEyes: boolean;
}

export interface AffectedResourceRef {
  id: string;
  type: string;
  name: string;
  provider?: string;
  algorithm?: string;
}

export interface UserFeedback {
  decision: 'ACCEPT' | 'REJECT' | 'DISMISS';
  reason?: string;
  decidedBy: string;
  decidedAt: string;
}

export interface ImpactAnalysisResult {
  recommendationId: string;
  affectedResourcesCount: number;
  affectedResources: AffectedResourceRef[];
  policyConsequences: {
    compliant: boolean;
    evaluatedPolicies: number;
    violationsFound: string[];
  };
  compatibilityRisks: string[];
  potentialDowntime: 'NONE' | 'MINIMAL_SUBSECOND' | 'SCHEDULED_MAINTENANCE';
  requiredApprovals: string[];
  estimatedResourceConsumption: {
    operationsCount: number;
    estimatedCostUsd: number;
    isEstimated: boolean;
  };
  knownRecoveryLimitations: string[];
  reversibility: 'FULLY_REVERSIBLE' | 'PARTIALLY_REVERSIBLE' | 'IRREVERSIBLE';
  simulatedAt: string;
}

export interface OptimizationRecommendation {
  id: string;
  orgId: string;
  category: RecommendationCategory;
  severity: SeverityLevel;
  priorityScore: number; // 0 - 100 deterministic scoring
  title: string;
  explanation: RecommendationExplanation;
  evidence: EvidenceReference[];
  affectedResources: AffectedResourceRef[];
  expectedBenefit: string;
  risks: string[];
  preconditions: string[];
  proposedAction: ProposedAction;
  requiredPermissions: string[];
  verificationProcedure: string;
  status: RecommendationStatus;
  userFeedback?: UserFeedback;
  dryRunResult?: ImpactAnalysisResult;
  deduplicationKey: string;
  createdAt: string;
  updatedAt: string;
}

export interface RawKeyTelemetry {
  id: string;
  name: string;
  orgId: string;
  algorithm: string;
  provider: string;
  status: string;
  createdAt: string;
  lastRotatedAt?: string;
  versionCount?: number;
  rotationIntervalDays?: number;
}

export interface RawCertTelemetry {
  id: string;
  commonName: string;
  orgId: string;
  issuerId?: string;
  status: string;
  notBefore: string;
  notAfter: string;
  algorithm: string;
}

export interface RawCircuitBreakerTelemetry {
  providerId: string;
  providerType: string;
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  failuresCount: number;
  lastFailureAt?: string;
  averageLatencyMs?: number;
}

export interface RawPolicyEvaluationTelemetry {
  id: string;
  policyId: string;
  policyName: string;
  orgId: string;
  operationType: string;
  algorithmRequested: string;
  verdict: 'ALLOW' | 'DENY';
  reason?: string;
  timestamp: string;
}

export interface RawUsageTelemetry {
  orgId: string;
  periodStart: string;
  periodEnd: string;
  totalOperations: number;
  failedOperations: number;
  activeKeys: number;
  billedCostUsd?: number;
  estimatedCostUsd?: number;
}

export interface EvidenceSnapshot {
  orgId: string;
  keys?: RawKeyTelemetry[];
  certificates?: RawCertTelemetry[];
  circuitBreakers?: RawCircuitBreakerTelemetry[];
  policyLogs?: RawPolicyEvaluationTelemetry[];
  usage?: RawUsageTelemetry[];
  cbomAssets?: Array<{
    id: string;
    name: string;
    algorithm: string;
    assetType: string;
    quantumStatus?: string;
    provider?: string;
    status: string;
  }>;
}
