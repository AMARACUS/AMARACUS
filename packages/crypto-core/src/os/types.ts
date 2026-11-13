/**
 * @file packages/crypto-core/src/os/types.ts
 * Type definitions for the AMARACUS Enterprise Cryptographic Operating System (Phase 20)
 */

export type CryptoResourceType =
  | 'ORGANIZATION'
  | 'PROJECT'
  | 'ENVIRONMENT'
  | 'APPLICATION'
  | 'SERVICE_IDENTITY'
  | 'API_CREDENTIAL'
  | 'KEY'
  | 'KEY_VERSION'
  | 'ALGORITHM'
  | 'PROVIDER'
  | 'CERTIFICATE'
  | 'POLICY'
  | 'OPERATION'
  | 'MIGRATION'
  | 'CBOM_ASSET';

export type VerificationSource =
  | 'DIRECT_STORAGE'
  | 'CBOM_SCAN'
  | 'PROVIDER_TELEMETRY'
  | 'INFERRED_DEPENDENCY';

export interface UnifiedResource {
  id: string;
  type: CryptoResourceType;
  name: string;
  orgId: string;
  projectId?: string;
  envId?: string;
  status: string;
  verified: boolean;
  verificationSource: VerificationSource;
  algorithm?: string;
  provider?: string;
  metadata: Record<string, any>;
  createdAt: string;
  updatedAt: string;
}

export type ResourceLifecycleStage =
  | 'DISCOVERY'
  | 'ASSESSMENT'
  | 'CONFIGURATION'
  | 'APPROVAL'
  | 'ACTIVATION'
  | 'MONITORING'
  | 'ROTATION'
  | 'MIGRATION'
  | 'DEACTIVATION'
  | 'RETIREMENT';

export type PostureFindingSeverity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFO';

export type PostureCategory =
  | 'POLICY_VIOLATION'
  | 'DEPRECATED_ALGORITHM'
  | 'KEY_ROTATION'
  | 'CERT_EXPIRATION'
  | 'PROVIDER_HEALTH'
  | 'PQC_GAP'
  | 'MIGRATION_RISK'
  | 'INCOMPLETE_INVENTORY';

export interface PostureFinding {
  id: string;
  code: string;
  severity: PostureFindingSeverity;
  title: string;
  description: string;
  category: PostureCategory;
  affectedResourceId: string;
  affectedResourceType: CryptoResourceType;
  remediation: {
    action: string;
    recommendedPlanType?: string;
    workflowTemplateId?: string;
    automatedFixAvailable: boolean;
  };
  source: string;
  deduplicationKey: string;
  detectedAt: string;
}

export interface UnifiedPostureSummary {
  score: number; // 0-100 overall score (100 = perfectly secure)
  totalFindings: number;
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  byCategory: Record<string, number>;
  pqcReadinessPercentage: number;
  verifiedInventoryPercentage: number;
  findings: PostureFinding[];
  evaluatedAt: string;
}

export type WorkflowState =
  | 'DRAFT'
  | 'VALIDATING'
  | 'AWAITING_APPROVAL'
  | 'READY'
  | 'RUNNING'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

export type WorkflowStepState =
  | 'PENDING'
  | 'RUNNING'
  | 'COMPLETED'
  | 'FAILED'
  | 'SKIPPED'
  | 'ROLLED_BACK';

export interface WorkflowStep {
  id: string;
  name: string;
  type:
    | 'ASSESSMENT'
    | 'VALIDATION'
    | 'KEY_ROTATION'
    | 'CERT_RENEWAL'
    | 'RE_ENCRYPT'
    | 'PROVIDER_PROBE'
    | 'NOTIFICATION';
  status: WorkflowStepState;
  parameters: Record<string, any>;
  result?: Record<string, any>;
  error?: string;
  executedAt?: string;
}

export interface WorkflowInstance {
  id: string;
  orgId: string;
  projectId?: string;
  envId?: string;
  templateId?: string;
  name: string;
  description?: string;
  state: WorkflowState;
  requiresDualApproval: boolean;
  proposerId: string;
  approverId?: string;
  approvedAt?: string;
  currentStepIndex: number;
  steps: WorkflowStep[];
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
  cancelledAt?: string;
  cancelReason?: string;
  metadata: Record<string, any>;
}

export interface WorkflowTemplate {
  id: string;
  name: string;
  description: string;
  category: 'KEY_MANAGEMENT' | 'CERTIFICATES' | 'POSTURE' | 'PQC' | 'PROVIDER';
  defaultSteps: Array<Omit<WorkflowStep, 'id' | 'status'>>;
  requiresDualApproval: boolean;
  supportedResourceTypes: CryptoResourceType[];
}

export type AutomationTrigger =
  | 'KEY_ROTATION_DUE'
  | 'CERT_EXPIRING'
  | 'POLICY_VIOLATION_DETECTED'
  | 'PROVIDER_DEGRADED'
  | 'SCHEDULED_AUDIT';

export interface AutomationRule {
  id: string;
  orgId: string;
  name: string;
  description: string;
  trigger: AutomationTrigger;
  conditions: Record<string, any>;
  action:
    | 'GENERATE_POSTURE_REPORT'
    | 'NOTIFY_SIEM'
    | 'CREATE_MIGRATION_PLAN'
    | 'INSTANTIATE_WORKFLOW';
  workflowTemplateId?: string;
  enabled: boolean;
  requiresApproval: boolean;
  lastTriggeredAt?: string;
}
