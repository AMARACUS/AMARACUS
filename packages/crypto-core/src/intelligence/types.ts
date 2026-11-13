import { AlgorithmId } from '../types';

export type AssetType =
  | 'KEY'
  | 'CERTIFICATE'
  | 'CERTIFICATE_AUTHORITY'
  | 'ALGORITHM'
  | 'CRYPTO_LIBRARY'
  | 'CRYPTO_PROVIDER'
  | 'CRYPTO_PROTOCOL'
  | 'CRYPTO_ENDPOINT'
  | 'CRYPTO_CONFIGURATION'
  | 'CRYPTO_OPERATION';

export type RelationshipType =
  | 'USES'
  | 'DEPENDS_ON'
  | 'SIGNED_BY'
  | 'ENCRYPTED_BY'
  | 'ASSOCIATED_WITH'
  | 'STORED_IN'
  | 'ISSUED_BY'
  | 'VERIFIED_BY'
  | 'IMPLEMENTS'
  | 'CONFIGURED_WITH'
  | 'PROVIDED_BY'
  | 'EXPIRES_ON'
  | 'REPLACED_BY'
  | 'AFFECTED_BY_POLICY';

export type DiscoverySource =
  | 'KEY_MANAGEMENT'
  | 'CERTIFICATE_INVENTORY'
  | 'CRYPTO_API'
  | 'SOURCE_CODE'
  | 'CONFIGURATION'
  | 'PROVIDER';

export type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export type QuantumStatus =
  | 'QUANTUM_VULNERABLE'
  | 'PQC'
  | 'HYBRID'
  | 'CLASSICAL'
  | 'UNKNOWN';

export type FindingSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type FindingStatus =
  | 'OPEN'
  | 'ACKNOWLEDGED'
  | 'IN_PROGRESS'
  | 'RESOLVED'
  | 'SUPPRESSED'
  | 'FALSE_POSITIVE';

export type FindingCategory =
  | 'DEPRECATED_ALGORITHM'
  | 'WEAK_KEY_SIZE'
  | 'EXPIRED_CERTIFICATE'
  | 'EXPIRING_SOON'
  | 'REVOKED_CERTIFICATE_REFERENCED'
  | 'UNSUPPORTED_ALGORITHM'
  | 'NON_COMPLIANT_POLICY'
  | 'QUANTUM_VULNERABLE_PUBLIC_KEY'
  | 'MISSING_ROTATION'
  | 'PROVIDER_MISMATCH'
  | 'ORPHANED_KEY'
  | 'ORPHANED_CERTIFICATE'
  | 'ALGORITHM_MIGRATION_REQUIRED';

export type MigrationStatus =
  | 'NOT_STARTED'
  | 'IDENTIFIED'
  | 'PLANNED'
  | 'IN_PROGRESS'
  | 'VALIDATION_REQUIRED'
  | 'COMPLETED'
  | 'BLOCKED';

export interface CryptoAssetItem {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  assetType: AssetType;
  name: string;
  source: DiscoverySource;
  confidence: ConfidenceLevel;
  algorithm?: string | null;
  provider?: string | null;
  status: string;
  quantumStatus: QuantumStatus;
  fingerprint?: string | null;
  firstSeenAt: Date;
  lastSeenAt: Date;
  metadata?: Record<string, any> | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CryptoRelationshipItem {
  id: string;
  organizationId: string;
  sourceAssetId: string;
  targetAssetId: string;
  relationshipType: RelationshipType;
  confidence: ConfidenceLevel;
  metadata?: Record<string, any> | null;
  createdAt: Date;
}

export interface CryptoFindingItem {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  affectedAssetId?: string | null;
  severity: FindingSeverity;
  category: FindingCategory;
  title: string;
  description: string;
  evidence?: Record<string, any> | null;
  policySource?: string | null;
  firstDetectedAt: Date;
  lastDetectedAt: Date;
  status: FindingStatus;
  remediationGuidance?: string | null;
  resolvedBy?: string | null;
  resolvedAt?: Date | null;
  resolutionComment?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CryptoInventorySnapshotItem {
  id: string;
  organizationId: string;
  snapshotDate: Date;
  totalAssets: number;
  assetsByType: Record<string, number>;
  findingsBySeverity: Record<string, number>;
  quantumStatusSummary: Record<string, number>;
  assetFingerprints: Record<string, string>;
  drift?: {
    newAssets: string[];
    changedAssets: string[];
    removedAssets: string[];
    unchangedAssets: string[];
  } | null;
  metadata?: Record<string, any> | null;
  createdAt: Date;
}

export interface CryptoMigrationPlanItem {
  id: string;
  organizationId: string;
  name: string;
  description?: string | null;
  affectedAssetIds: string[];
  currentAlgorithm: string;
  targetAlgorithm: string;
  migrationStrategy: 'DIRECT_REPLACEMENT' | 'HYBRID_DUAL_RUN' | 'PHASED_ROTATION';
  dependencies?: string[];
  blockers?: string[];
  owner?: string | null;
  environmentId?: string | null;
  status: MigrationStatus;
  validationRequirements?: string[];
  metadata?: Record<string, any> | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface DownstreamImpactResult {
  assetId: string;
  assetName: string;
  assetType: AssetType;
  algorithm?: string | null;
  affectedKeys: CryptoAssetItem[];
  affectedCertificates: CryptoAssetItem[];
  affectedApplications: CryptoAssetItem[];
  affectedProviders: CryptoAssetItem[];
  affectedEnvironments: string[];
  totalAffected: number;
  dependencyPath: string[];
}

export interface CBOMComponent {
  id: string;
  type: AssetType;
  name: string;
  algorithm?: string | null;
  provider?: string | null;
  quantumStatus: QuantumStatus;
  status: string;
  source: DiscoverySource;
  confidence: ConfidenceLevel;
  fingerprint?: string | null;
  properties?: Record<string, any>;
}

export interface CBOMRelationship {
  sourceId: string;
  targetId: string;
  relationship: RelationshipType;
  confidence: ConfidenceLevel;
}

export interface CBOMDocument {
  cbomVersion: string;
  specVersion: string;
  serialNumber: string;
  timestamp: string;
  organizationId: string;
  metadata: {
    generatedBy: string;
    version: string;
    environment?: string;
    totalAssets: number;
    quantumReadinessScore: {
      quantumVulnerable: number;
      pqcReady: number;
      hybrid: number;
      classical: number;
    };
  };
  components: CBOMComponent[];
  dependencies: CBOMRelationship[];
  findings?: Array<{
    id: string;
    severity: FindingSeverity;
    category: FindingCategory;
    title: string;
    affectedAssetId?: string | null;
    status: FindingStatus;
  }>;
  integrity: {
    algorithm: 'SHA-256';
    hash: string;
  };
}
