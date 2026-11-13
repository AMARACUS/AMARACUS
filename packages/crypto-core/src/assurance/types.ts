/**
 * @file packages/crypto-core/src/assurance/types.ts
 * Enterprise Cryptographic Trust, Compliance & Assurance Types (Phase 22)
 */

export type ComplianceFrameworkId =
  | 'SOC_2_TYPE_II'
  | 'ISO_27001_2022'
  | 'NIST_SP_800_53_R5'
  | 'NIST_SP_800_57'
  | 'FIPS_140_3'
  | 'NIST_PQC';

export type ControlCategory =
  | 'DATA_AT_REST'
  | 'DATA_IN_TRANSIT'
  | 'KEY_LIFECYCLE'
  | 'CRYPTO_AGILITY'
  | 'QUANTUM_READINESS'
  | 'ACCESS_CONTROL'
  | 'AUDIT_INTEGRITY';

export type SharedResponsibilityParty =
  | 'AMARACUS_MANAGED'
  | 'CUSTOMER_CONFIGURED'
  | 'SHARED_RESPONSIBILITY'
  | 'CLOUD_PROVIDER_HSM';

export type ControlStatus =
  | 'SATISFIED'
  | 'PARTIALLY_SATISFIED'
  | 'UNSATISFIED'
  | 'NOT_APPLICABLE'
  | 'EXCEPTION_GRANTED';

export type EvidenceType =
  | 'KEY_METADATA'
  | 'POLICY_DEFINITION'
  | 'AUDIT_LOG_ENTRY'
  | 'PKI_CERTIFICATE'
  | 'CBOM_INVENTORY'
  | 'CIRCUIT_BREAKER_STATE'
  | 'CONFIGURATION_SETTING';

export type EvidenceFreshness = 'VALID' | 'STALE' | 'EXPIRED';

export type ExceptionStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';

export interface ChainOfCustody {
  collector: string;
  sourceHost?: string;
  timestamp: string;
  digestAlgorithm: 'SHA-256';
}

export interface EvidenceArtifact {
  id: string;
  orgId: string;
  type: EvidenceType;
  source: string;
  title: string;
  collectedAt: string;
  expiresAt: string;
  digest: string; // SHA-256 digest of normalized properties
  freshness: EvidenceFreshness;
  properties: Record<string, any>;
  chainOfCustody: ChainOfCustody;
}

export interface ControlGap {
  id: string;
  controlId: string;
  frameworkId: ComplianceFrameworkId;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  rootCause: string;
  remediationGuidance: string;
  recommendationId?: string;
}

export interface ComplianceException {
  id: string;
  orgId: string;
  controlId: string;
  frameworkId: ComplianceFrameworkId;
  justification: string;
  compensatingControls: string;
  requestedBy: string;
  approvedBy?: string;
  status: ExceptionStatus;
  createdAt: string;
  expiresAt: string;
}

export interface ControlRequirement {
  id: string;
  frameworkId: ComplianceFrameworkId;
  code: string;
  title: string;
  description: string;
  category: ControlCategory;
  responsibility: SharedResponsibilityParty;
  customerGuidance: string;
  amaracusImplementation: string;
  requiredEvidenceTypes: EvidenceType[];
  evaluate: (evidence: EvidenceArtifact[]) => {
    status: ControlStatus;
    score: number;
    details: string;
    gaps: Omit<ControlGap, 'id'>[];
  };
}

export interface ControlAssessment {
  controlId: string;
  frameworkId: ComplianceFrameworkId;
  code: string;
  title: string;
  category: ControlCategory;
  responsibility: SharedResponsibilityParty;
  status: ControlStatus;
  score: number;
  details: string;
  evidenceIds: string[];
  gaps: ControlGap[];
  exceptionId?: string;
  lastAssessedAt: string;
}

export interface ComplianceFrameworkDefinition {
  id: ComplianceFrameworkId;
  name: string;
  version: string;
  authority: string;
  description: string;
  controlCount: number;
  categories: ControlCategory[];
}

export interface FrameworkAssessmentReport {
  id: string;
  orgId: string;
  frameworkId: ComplianceFrameworkId;
  frameworkName: string;
  overallScore: number; // 0 - 100
  totalControls: number;
  satisfiedControls: number;
  partiallySatisfiedControls: number;
  unsatisfiedControls: number;
  exceptionsCount: number;
  gapsCount: number;
  controls: ControlAssessment[];
  evidenceCount: number;
  reportDigest: string; // SHA-256
  generatedAt: string;
  disclaimer: string;
}
