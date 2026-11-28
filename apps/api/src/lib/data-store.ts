import { prisma } from '@amaracus/database';
import { Role, fromDbRole, toDbRole } from './permissions';
import crypto from 'crypto';
import { isTestEnv } from './runtime-config';

export interface UserRecord {
  id: string;
  email: string;
  name?: string | null;
  passwordHash: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface SessionRecord {
  id: string;
  sessionToken: string;
  userId: string;
  activeOrgId?: string | null;
  expiresAt: Date;
  createdAt: Date;
}

export interface OrganizationRecord {
  id: string;
  name: string;
  slug: string;
  metadata?: string | null;
  createdAt: Date;
  updatedAt?: Date;
}

export interface MemberRecord {
  id: string;
  organizationId: string;
  userId: string;
  role: Role;
  createdAt: Date;
  updatedAt?: Date;
  user?: UserRecord | { email: string; name: string | null };
}

export interface ProjectRecord {
  id: string;
  organizationId: string;
  name: string;
  slug: string;
  description?: string | null;
  createdAt: Date;
  updatedAt: Date;
  environments?: EnvironmentRecord[];
}

export interface EnvironmentRecord {
  id: string;
  projectId: string;
  name: string;
  slug: string;
  type: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ApiCredentialRecord {
  id: string;
  organizationId?: string | null;
  projectId?: string | null;
  environmentId: string;
  name: string;
  prefix: string;
  keyHash: string;
  scopes?: string[] | null;
  /** IPs or CIDR ranges the key may be used from; empty or null means any address. */
  allowedIps?: string[] | null;
  status?: string; // ACTIVE, DISABLED, REVOKED, EXPIRED
  createdBy?: string | null;
  lastUsedAt?: Date | null;
  expiresAt?: Date | null;
  revokedAt?: Date | null;
  createdAt: Date;
  updatedAt?: Date;
}

export interface TeamRecord {
  id: string;
  organizationId: string;
  name: string;
  description?: string | null;
  createdAt: Date;
  updatedAt: Date;
  members?: TeamMemberRecord[];
}

export interface TeamMemberRecord {
  id: string;
  teamId: string;
  userId: string;
  role: string;
  createdAt: Date;
  user?: { id: string; name?: string | null; email: string };
}

export interface ServiceIdentityRecord {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  name: string;
  description?: string | null;
  status: string;
  scopes: string[];
  prefix: string;
  keyHash: string;
  createdBy?: string | null;
  lastUsedAt?: Date | null;
  expiresAt?: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ConfigurationDriftRecord {
  id: string;
  organizationId: string;
  resourceType: string;
  resourceId: string;
  expectedState: any;
  actualState: any;
  driftSummary: string;
  status: string;
  detectedAt: Date;
  resolvedAt?: Date | null;
}

export interface OrganizationSecuritySettingRecord {
  id: string;
  organizationId: string;
  enforceMfa: boolean;
  allowedIpRanges: string[];
  defaultKeyRotationDays: number;
  requireHsmInProduction: boolean;
  requirePqcInProduction: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface WebhookEndpointRecord {
  id: string;
  organizationId: string;
  url: string;
  description?: string | null;
  secretHash: string;
  secretPrefix: string;
  events: string[];
  status: string; // ACTIVE, DISABLED
  failureCount: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface WebhookDeliveryRecord {
  id: string;
  endpointId: string;
  eventType: string;
  eventId: string;
  payload: any;
  responseStatus?: number | null;
  responseBody?: string | null;
  durationMs?: number | null;
  status: string; // PENDING, DELIVERED, RETRYING, FAILED
  attempts: number;
  nextRetryAt?: Date | null;
  error?: string | null;
  createdAt: Date;
}

export interface AsyncJobRecord {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  type: string;
  status: string; // QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
  progress: number;
  input?: any;
  result?: any;
  error?: string | null;
  durationMs?: number | null;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface ApiUsageRecord {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  credentialId?: string | null;
  endpoint: string;
  method: string;
  statusCode: number;
  durationMs: number;
  ipAddress?: string | null;
  userAgent?: string | null;
  timestamp: Date;
}

export interface BillingCustomerRecord {
  id: string;
  organizationId: string;
  polarCustomerId?: string | null;
  email?: string | null;
  name?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface BillingSubscriptionRecord {
  id: string;
  organizationId: string;
  polarSubscriptionId?: string | null;
  plan: 'FREE' | 'STARTER' | 'PRO' | 'BUSINESS' | 'PAYG' | string;
  status: 'ACTIVE' | 'TRIALING' | 'PAST_DUE' | 'CANCELED' | 'ENDED' | 'INCOMPLETE' | string;
  currentPeriodStart: Date;
  currentPeriodEnd?: Date | null;
  cancelAtPeriodEnd: boolean;
  canceledAt?: Date | null;
  metadata?: any;
  createdAt: Date;
  updatedAt: Date;
}

export interface BillingUsageRecord {
  id: string;
  organizationId: string;
  periodStart: Date;
  periodEnd: Date;
  operationCount: number;
  includedAllowance: number;
  overageCount: number;
  estimatedCostCents: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface BillingUsageEventRecord {
  id: string;
  organizationId: string;
  operationId: string;
  operationType: string;
  quantity: number;
  keyId?: string | null;
  projectId?: string | null;
  timestamp: Date;
  reportedToPolar: boolean;
  polarEventId?: string | null;
}

/**
 * Allowances are monthly. A yearly subscription's period is cut into months counted from its
 * start, and the month containing `now` is returned (the last one ends at the period end).
 * Periods of 40 days or less are returned as they are.
 */
export function monthlySliceOfPeriod(start: Date, end: Date, now: Date): { periodStart: Date; periodEnd: Date } {
  const days = (end.getTime() - start.getTime()) / 86_400_000;
  if (days <= 40) return { periodStart: start, periodEnd: end };
  const addMonths = (d: Date, n: number) => {
    const r = new Date(d.getTime());
    const day = r.getUTCDate();
    r.setUTCDate(1);
    r.setUTCMonth(r.getUTCMonth() + n);
    const lastDay = new Date(Date.UTC(r.getUTCFullYear(), r.getUTCMonth() + 1, 0)).getUTCDate();
    r.setUTCDate(Math.min(day, lastDay));
    return r;
  };
  let n = 0;
  while (n < 24 && addMonths(start, n + 1).getTime() <= now.getTime()) n++;
  const sliceStart = addMonths(start, n);
  const nextStart = addMonths(start, n + 1);
  return { periodStart: sliceStart, periodEnd: nextStart.getTime() > end.getTime() ? end : nextStart };
}

export type OveragePolicy = 'HARD_STOP' | 'AUTHORIZED_OVERAGE' | 'ENTERPRISE_CUSTOM';

export interface BillingSafetyStateRecord {
  id: string;
  organizationId: string;
  circuitBreakerStatus: 'NORMAL' | 'WARNING' | 'THROTTLED' | 'SUSPENDED' | string;
  opsPerMinute: number;
  opsPerHour: number;
  opsPerDay: number;
  lastWindowReset: Date;
  paygSpendingLimitCents: number;
  alertThresholdPercent: number;
  autoHaltEnabled: boolean;
  overagePolicy: OveragePolicy;
  authorizedOverageSpendingLimitCents: number;
  lastAlertSentAt?: Date | null;
  suspensionReason?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface BillingWebhookEventRecord {
  id: string;
  eventId: string;
  eventType: string;
  payload: any;
  processed: boolean;
  processedAt?: Date | null;
  error?: string | null;
  createdAt: Date;
}

export interface CryptographicOperationRecord {
  id: string;
  requestId?: string | null;
  idempotencyKey?: string | null;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  operationType: string;
  algorithm?: string | null;
  keyId?: string | null;
  providerId?: string | null;
  priority?: 'HIGH' | 'NORMAL' | 'LOW' | string | null;
  request?: any;
  status: string;
  durationMs?: number | null;
  retryCount?: number;
  result?: any;
  metadata?: any;
  error?: any;
  expiresAt?: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface AuditEventRecord {
  id: string;
  organizationId?: string | null;
  userId?: string | null;
  action: string;
  resourceType: string;
  resourceId?: string | null;
  metadata?: any;
  ipAddress?: string | null;
  userAgent?: string | null;
  createdAt: Date;
}

export interface CryptographicKeyRecord {
  id: string;
  name: string;
  description?: string | null;
  organizationId: string;
  projectId: string;
  environmentId: string;
  algorithm: string;
  purpose: string;
  provider: string;
  status: string;
  currentVersion: number;
  expiresAt?: Date | null;
  activatedAt?: Date | null;
  rotatedAt?: Date | null;
  disabledAt?: Date | null;
  revokedAt?: Date | null;
  scheduledDeletionAt?: Date | null;
  destroyedAt?: Date | null;
  metadata?: any;
  createdAt: Date;
  updatedAt: Date;
  versions?: CryptographicKeyVersionRecord[];
  project?: ProjectRecord;
  environment?: EnvironmentRecord;
}

export interface CryptographicKeyVersionRecord {
  id: string;
  keyId: string;
  version: number;
  providerKeyId: string;
  status: string;
  publicKey?: string | null;
  encryptedKeyMaterial?: string | null;
  keyFingerprint?: string | null;
  activatedAt?: Date | null;
  revokedAt?: Date | null;
  destroyedAt?: Date | null;
  metadata?: any;
  createdAt: Date;
}

export interface CustomerKeyProviderRecord {
  id: string;
  organizationId: string;
  projectId: string;
  environmentId: string;
  name: string;
  displayName?: string | null;
  providerType: 'AZURE_KEY_VAULT' | 'AZURE_MANAGED_HSM';
  resourceType?: string;
  ownershipType: string;
  vaultUrl: string;
  hsmUrl?: string | null;
  resourceId?: string | null;
  authType: string;
  authenticationMethod?: string;
  encryptedAuthConfig?: string | null;
  status: string;
  connectionStatus?: string;
  onboardingState?: string;
  capabilityDiscoveryStatus?: string;
  isHsmBacked: boolean;
  capabilities?: any;
  lastHealthCheckAt?: Date | null;
  healthStatus?: string | null;
  healthMessage?: string | null;
  lastHealthCheckError?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CustomerRegisteredKeyRecord {
  id: string;
  providerId: string;
  organizationId: string;
  projectId: string;
  environmentId: string;
  keyIdentifier: string;
  displayName?: string | null;
  keyVaultUrl: string;
  keyType: string;
  algorithm: string;
  purpose: string;
  ownershipType: string;
  isHsmBacked: boolean;
  hsmBackedStatus?: string;
  status: string;
  keyState?: string;
  currentVersion: string;
  publicKey?: string | null;
  keyFingerprint?: string | null;
  operations?: any;
  capabilities?: any;
  lastSyncedAt: Date;
  lastDiscoveredAt?: Date;
  metadata?: any;
  createdAt: Date;
  updatedAt: Date;
  versions?: CustomerKeyVersionRecord[];
}

export interface CustomerKeyVersionRecord {
  id: string;
  registeredKeyId: string;
  version: string;
  status: string;
  publicKey?: string | null;
  keyFingerprint?: string | null;
  isCurrent: boolean;
  createdAt: Date;
  expiresAt?: Date | null;
}

export interface CertificateAuthorityRecord {
  id: string;
  name: string;
  description?: string | null;
  organizationId: string;
  projectId: string;
  environmentId: string;
  type: string; // 'ROOT_CA' | 'INTERMEDIATE_CA'
  status: string; // 'ACTIVE' | 'DISABLED' | 'REVOKED'
  subject: string;
  issuer: string;
  parentAuthorityId?: string | null;
  keyReference: string;
  keyAlgorithm: string;
  signatureAlgorithm: string;
  certificatePem: string;
  serialNumber: string;
  fingerprint: string;
  notBefore: Date;
  notAfter: Date;
  pathLenConstraint?: number | null;
  crlDistributionPoint?: string | null;
  ocspUrl?: string | null;
  metadata?: any;
  createdAt: Date;
  updatedAt: Date;
}

export interface CertificateRecord {
  id: string;
  name?: string | null;
  organizationId: string;
  projectId: string;
  environmentId: string;
  authorityId?: string | null;
  keyReference: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  certificateType: string; // 'ROOT_CA' | 'INTERMEDIATE_CA' | 'SERVER' | 'CLIENT' | 'CODE_SIGNING' | 'EMAIL' | 'DEVICE' | 'CUSTOM'
  keyAlgorithm: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  status: string; // 'REQUESTED' | 'ISSUED' | 'ACTIVE' | 'EXPIRING' | 'EXPIRED' | 'REVOKED' | 'SUSPENDED' | 'REPLACED' | 'FAILED'
  notBefore: Date;
  notAfter: Date;
  fingerprint: string;
  fingerprintSha1?: string | null;
  certificatePem: string;
  chainPem?: string | null;
  chainReference?: string | null;
  san?: any;
  keyUsage?: any;
  extendedKeyUsage?: any;
  renewalOfId?: string | null;
  replacedById?: string | null;
  metadata?: any;
  revocation?: CertificateRevocationRecord | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CertificateRequestRecord {
  id: string;
  organizationId: string;
  projectId: string;
  environmentId: string;
  keyReference?: string | null;
  subject: string;
  csrPem: string;
  publicKey?: string | null;
  keyAlgorithm: string;
  signatureAlgorithm: string;
  status: string; // 'PENDING' | 'APPROVED' | 'REJECTED' | 'ISSUED'
  san?: any;
  keyUsage?: any;
  extendedKeyUsage?: any;
  certificateId?: string | null;
  metadata?: any;
  createdAt: Date;
  updatedAt: Date;
}

export interface CertificateRevocationRecord {
  id: string;
  certificateId: string;
  organizationId: string;
  reason: string; // 'UNSPECIFIED' | 'KEY_COMPROMISE' | 'CA_COMPROMISE' | 'AFFILIATION_CHANGED' | 'SUPERSEDED' | 'CESSATION_OF_OPERATION' | 'CERTIFICATE_HOLD' | 'PRIVILEGE_WITHDRAWN'
  revokedAt: Date;
  revokedBy?: string | null;
  invalidityDate?: Date | null;
  comment?: string | null;
  createdAt: Date;
}

export interface CryptoAssetRecord {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  assetType: string;
  name: string;
  source: string;
  confidence: string;
  algorithm?: string | null;
  provider?: string | null;
  status: string;
  quantumStatus: string;
  fingerprint?: string | null;
  firstSeenAt: Date;
  lastSeenAt: Date;
  metadata?: any;
  createdAt: Date;
  updatedAt: Date;
}

export interface CryptoRelationshipRecord {
  id: string;
  organizationId: string;
  sourceAssetId: string;
  targetAssetId: string;
  relationshipType: string;
  confidence: string;
  metadata?: any;
  createdAt: Date;
}

export interface CryptoFindingRecord {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  affectedAssetId?: string | null;
  severity: string;
  category: string;
  title: string;
  description: string;
  evidence?: any;
  policySource?: string | null;
  firstDetectedAt: Date;
  lastDetectedAt: Date;
  status: string;
  remediationGuidance?: string | null;
  resolvedBy?: string | null;
  resolvedAt?: Date | null;
  resolutionComment?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CryptoSnapshotRecord {
  id: string;
  organizationId: string;
  snapshotDate: Date;
  totalAssets: number;
  assetsByType?: any;
  findingsBySeverity?: any;
  quantumStatusSummary?: any;
  assetFingerprints?: any;
  drift?: any;
  metadata?: any;
  createdAt: Date;
}

export interface CryptoMigrationPlanRecord {
  id: string;
  organizationId: string;
  name: string;
  description?: string | null;
  affectedAssetIds: any;
  currentAlgorithm: string;
  targetAlgorithm: string;
  migrationStrategy: string;
  dependencies?: any;
  blockers?: any;
  owner?: string | null;
  environmentId?: string | null;
  status: string;
  validationRequirements?: any;
  metadata?: any;
  createdAt: Date;
  updatedAt: Date;
}

export interface ZkCircuitRecord {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  name: string;
  version: string;
  description?: string | null;
  provingSystem: string;
  publicInputsSchema: any;
  privateInputsSchema: any;
  constraintsDescription: string;
  verificationKey: any;
  provingKeyMetadata?: any;
  status: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ZkProofRecordDb {
  id: string;
  organizationId: string;
  circuitId: string;
  circuitVersion: string;
  publicInputs: any;
  proofData: any;
  verified: boolean;
  durationMs: number;
  metadata?: any;
  createdAt: Date;
}

export interface FheKeyRecord {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  scheme: string;
  polyModulusDegree: number;
  publicKeyBase64: string;
  relinKeysBase64?: string | null;
  encryptedSecretKey?: string | null;
  metadata?: any;
  createdAt: Date;
  updatedAt: Date;
}

export interface MpcSessionRecord {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  title: string;
  protocol: string;
  operation: string;
  requiredParties: number;
  threshold: number;
  status: string;
  currentRound: number;
  totalRounds: number;
  result?: any;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface MpcPartyRecord {
  id: string;
  sessionId: string;
  partyId: string;
  name: string;
  role: string;
  hasSubmittedInput: boolean;
  blindedShareHash?: string | null;
  joinedAt: Date;
}

export interface ThresholdKeyRecord {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  name: string;
  algorithm: string;
  threshold: number;
  totalParticipants: number;
  groupPublicKey: string;
  participants: any;
  metadata?: any;
  createdAt: Date;
  updatedAt: Date;
}

export interface ThresholdSessionRecord {
  id: string;
  organizationId: string;
  keyId: string;
  operation: string;
  messageToSign?: string | null;
  payloadToAuthorize?: string | null;
  threshold: number;
  totalParticipants: number;
  approvals: any;
  status: string;
  combinedResult?: any;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface CryptographicPolicyRecord {
  id: string;
  organizationId: string;
  name: string;
  description?: string | null;
  currentVersion: number;
  isActive: boolean;
  enforcementMode: string; // ENFORCE, AUDIT, DISABLED
  rules: any;
  metadata?: any;
  createdAt: Date;
  updatedAt: Date;
  versions?: CryptographicPolicyVersionRecord[];
  assignments?: CryptographicPolicyAssignmentRecord[];
}

export interface CryptographicPolicyVersionRecord {
  id: string;
  policyId: string;
  version: number;
  rules: any;
  changeSummary?: string | null;
  actorId?: string | null;
  createdAt: Date;
}

export interface CryptographicPolicyAssignmentRecord {
  id: string;
  policyId: string;
  organizationId: string;
  scopeType: string; // ORGANIZATION, PROJECT, ENVIRONMENT
  scopeId: string;
  priority: number;
  createdAt: Date;
  policy?: CryptographicPolicyRecord;
}

export interface UploadRecord {
  id: string;
  organizationId: string;
  userId?: string | null;
  storageName: string;
  originalName: string;
  sanitizedName: string;
  mimeType: string;
  size: number;
  sha256: string;
  storagePath: string;
  metadata?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

export interface VerificationRecord {
  identifier: string;
  value: string;
  expiresAt: Date;
}

export interface HackathonSubmissionRecord {
  id: string;
  organizationId: string;
  userId: string;
  userEmail: string;
  plan: string; // 'PRO' | 'BUSINESS' | 'ENTERPRISE'
  projectName: string;
  category: string; // 'software' | 'database' | 'enterprise_saas' | 'security_tool' | 'mobile_app' | 'pqc_infrastructure' | 'other'
  description: string;
  sourceCodeUrl: string; // GitHub repo or Google Drive URL
  sourceCodeType: 'github' | 'gdrive' | 'other';
  apiUsageEndpoints: string[]; // List of Amaracus API endpoints integrated
  demoUrl?: string | null; // Direct testable hosted endpoint or downloadable app binary
  videoUrl?: string | null;
  confirmedTerms: boolean;
  score?: number | null;
  status: 'SUBMITTED' | 'UNDER_REVIEW' | 'VERIFIED' | 'DISQUALIFIED' | 'WINNER';
  createdAt: Date;
  updatedAt: Date;
}

export class DatabaseUnavailableError extends Error {
  readonly statusCode = 503;
  readonly code = 'DATABASE_UNAVAILABLE';
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = 'DatabaseUnavailableError';
  }
}

// Prisma connection-level failures: P1001 can't reach server, P1002 timed out,
// P1017 server closed the connection, P2024 pool timeout.
function isConnectionError(err: unknown): boolean {
  const e = err as { code?: string; name?: string } | null;
  return (
    !!e &&
    (e.name === 'PrismaClientInitializationError' || ['P1001', 'P1002', 'P1017', 'P2024'].includes(e.code ?? ''))
  );
}

class WriteGuardMap<K, V> extends Map<K, V> {
  constructor(private readonly storeName: string) {
    super();
  }

  set(_key: K, _value: V): this {
    throw new Error(`[DataStore] in-memory write to '${this.storeName}' outside test mode; this path must use Prisma`);
  }
}

class InMemoryStore {
  users: Map<string, UserRecord> = new Map();
  sessions: Map<string, SessionRecord> = new Map();
  organizations: Map<string, OrganizationRecord> = new Map();
  members: Map<string, MemberRecord> = new Map();
  projects: Map<string, ProjectRecord> = new Map();
  environments: Map<string, EnvironmentRecord> = new Map();
  credentials: Map<string, ApiCredentialRecord> = new Map();
  policies: Map<string, CryptographicPolicyRecord> = new Map();
  policyVersions: Map<string, CryptographicPolicyVersionRecord> = new Map();
  policyAssignments: Map<string, CryptographicPolicyAssignmentRecord> = new Map();
  teams: Map<string, TeamRecord> = new Map();
  teamMembers: Map<string, TeamMemberRecord> = new Map();
  serviceIdentities: Map<string, ServiceIdentityRecord> = new Map();
  configurationDrifts: Map<string, ConfigurationDriftRecord> = new Map();
  securitySettings: Map<string, OrganizationSecuritySettingRecord> = new Map();
  keys: Map<string, CryptographicKeyRecord> = new Map();
  keyVersions: Map<string, CryptographicKeyVersionRecord> = new Map();
  customerProviders: Map<string, CustomerKeyProviderRecord> = new Map();
  customerRegisteredKeys: Map<string, CustomerRegisteredKeyRecord> = new Map();
  customerKeyVersions: Map<string, CustomerKeyVersionRecord> = new Map();
  certificateAuthorities: Map<string, CertificateAuthorityRecord> = new Map();
  certificates: Map<string, CertificateRecord> = new Map();
  certificateRequests: Map<string, CertificateRequestRecord> = new Map();
  certificateRevocations: Map<string, CertificateRevocationRecord> = new Map();
  cryptoAssets: Map<string, CryptoAssetRecord> = new Map();
  cryptoRelationships: Map<string, CryptoRelationshipRecord> = new Map();
  cryptoFindings: Map<string, CryptoFindingRecord> = new Map();
  cryptoSnapshots: Map<string, CryptoSnapshotRecord> = new Map();
  cryptoMigrationPlans: Map<string, CryptoMigrationPlanRecord> = new Map();
  zkCircuits: Map<string, ZkCircuitRecord> = new Map();
  zkProofRecords: Map<string, ZkProofRecordDb> = new Map();
  fheKeys: Map<string, FheKeyRecord> = new Map();
  mpcSessions: Map<string, MpcSessionRecord> = new Map();
  mpcParties: Map<string, MpcPartyRecord> = new Map();
  thresholdKeys: Map<string, ThresholdKeyRecord> = new Map();
  thresholdSessions: Map<string, ThresholdSessionRecord> = new Map();
  webhookEndpoints: Map<string, WebhookEndpointRecord> = new Map();
  webhookDeliveries: Map<string, WebhookDeliveryRecord> = new Map();
  asyncJobs: Map<string, AsyncJobRecord> = new Map();
  billingCustomers: Map<string, BillingCustomerRecord> = new Map();
  billingSubscriptions: Map<string, BillingSubscriptionRecord> = new Map();
  billingUsages: Map<string, BillingUsageRecord> = new Map();
  billingUsageEvents: Map<string, BillingUsageEventRecord> = new Map();
  billingSafetyStates: Map<string, BillingSafetyStateRecord> = new Map();
  billingWebhookEvents: Map<string, BillingWebhookEventRecord> = new Map();
  cryptographicOperations: Map<string, CryptographicOperationRecord> = new Map();
  uploads: Map<string, UploadRecord> = new Map();
  hackathonSubmissions: Map<string, HackathonSubmissionRecord> = new Map();
  verifications: Map<string, VerificationRecord> = new Map();
  apiUsageRecords: ApiUsageRecord[] = [];
  auditEvents: AuditEventRecord[] = [];

  /**
   * Outside tests the DataStore is backed by Postgres only. The in-memory maps
   * stay empty and any write to them throws, so a missed code path fails
   * loudly instead of keeping data that vanishes on restart.
   */
  lockForDatabaseMode() {
    for (const [name, value] of Object.entries(this)) {
      if (value instanceof Map) {
        (this as any)[name] = new WriteGuardMap(name);
      } else if (Array.isArray(value)) {
        (this as any)[name] = Object.freeze([]);
      }
    }
    Object.freeze(this);
  }
}

/**
 * Sessions are stored by the SHA-256 of their token, so a read of the session table does not
 * yield tokens that sign anyone in. Tokens are 256-bit random values, so an unsalted hash is enough.
 */
export function hashSessionToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/** The hashed form, plus the raw form for rows created before hashing that are not yet upgraded. */
function sessionTokenForms(token: string): string[] {
  return [hashSessionToken(token), token];
}

export class DataStore {
  // Memory mode exists only for the test suite. Everywhere else Postgres is the single store.
  private readonly memoryMode = isTestEnv();
  private memStore = new InMemoryStore();
  private prismaConnected = false;

  constructor() {
    if (!this.memoryMode) this.memStore.lockForDatabaseMode();
  }

  isMemoryMode(): boolean {
    return this.memoryMode;
  }

  /**
   * Returns false only in memory (test) mode. Otherwise it returns true once the
   * database answers, and throws DatabaseUnavailableError when it does not.
   */
  async checkPrisma(): Promise<boolean> {
    if (this.memoryMode) return false;
    if (this.prismaConnected) return true;
    if (!process.env.DATABASE_URL) {
      throw new DatabaseUnavailableError('DATABASE_URL is not configured');
    }
    try {
      await prisma.$queryRaw`SELECT 1`;
    } catch (err) {
      throw new DatabaseUnavailableError('Database is unreachable', err);
    }
    this.prismaConnected = true;
    console.log('[DataStore] Connected to PostgreSQL via Prisma');
    return true;
  }

  /** Live connectivity probe for readiness checks; never cached. */
  async pingDatabase(): Promise<boolean> {
    if (this.memoryMode) return true;
    if (!process.env.DATABASE_URL) return false;
    try {
      await prisma.$queryRaw`SELECT 1`;
      return true;
    } catch {
      this.prismaConnected = false;
      return false;
    }
  }

  /**
   * Prisma errors propagate. The one exception is P2025 (record not found on
   * update/delete): the caller then falls through to the empty in-memory path,
   * which returns its not-found result.
   */
  private rethrowUnlessNotFound(err: unknown): void {
    if ((err as { code?: string } | null)?.code === 'P2025') return;
    if (isConnectionError(err)) {
      this.prismaConnected = false;
      throw new DatabaseUnavailableError('Database is unreachable', err);
    }
    throw err;
  }

  // --- USER OPERATIONS ---

  async findUserByEmail(email: string): Promise<UserRecord | null> {
    const normalized = email.toLowerCase().trim();
    if (await this.checkPrisma()) {
      try {
        const user = await prisma.user.findUnique({ where: { email: normalized } });
        if (user) return user as UserRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    for (const u of this.memStore.users.values()) {
      if (u.email.toLowerCase().trim() === normalized) return u;
    }
    return null;
  }

  async findUserById(id: string): Promise<UserRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const user = await prisma.user.findUnique({ where: { id } });
        if (user) return user as UserRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.users.get(id) || null;
  }

  async createUser(data: { id?: string; email: string; name?: string; passwordHash: string }): Promise<UserRecord> {
    const normalized = data.email.toLowerCase().trim();
    if (await this.checkPrisma()) {
      try {
        const user = await prisma.user.create({
          data: {
            id: data.id || undefined,
            email: normalized,
            name: data.name || null,
            passwordHash: data.passwordHash,
          },
        });
        return user as UserRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const user: UserRecord = {
      id: data.id || `usr_${crypto.randomBytes(12).toString('hex')}`,
      email: normalized,
      name: data.name || null,
      passwordHash: data.passwordHash,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.memStore.users.set(user.id, user);
    return user;
  }

  async updateUserPassword(userId: string, passwordHash: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.user.update({
          where: { id: userId },
          data: { passwordHash, updatedAt: new Date() },
        });
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const user = this.memStore.users.get(userId);
    if (user) {
      user.passwordHash = passwordHash;
      user.updatedAt = new Date();
      return true;
    }
    return false;
  }

  async deleteSessionsByUserId(userId: string): Promise<void> {
    if (await this.checkPrisma()) {
      try {
        await prisma.session.deleteMany({ where: { userId } });
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    for (const [token, session] of this.memStore.sessions.entries()) {
      if (session.userId === userId) {
        this.memStore.sessions.delete(token);
      }
    }
  }

  async deleteUser(userId: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.session.deleteMany({ where: { userId } });
        await prisma.member.deleteMany({ where: { userId } });
        await prisma.user.delete({ where: { id: userId } });
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    for (const [token, session] of this.memStore.sessions.entries()) {
      if (session.userId === userId) {
        this.memStore.sessions.delete(token);
      }
    }
    for (const [memberId, member] of this.memStore.members.entries()) {
      if (member.userId === userId) {
        this.memStore.members.delete(memberId);
      }
    }
    const deleted = this.memStore.users.delete(userId);
    if (deleted) {
    }
    return deleted;
  }

  // --- SESSION OPERATIONS ---

  async createSession(data: { id?: string; sessionToken?: string; userId: string; activeOrgId?: string | null; expiresAt: Date; createdAt?: Date }): Promise<SessionRecord> {
    const sessionToken = data.sessionToken || crypto.randomBytes(32).toString('hex');
    if (await this.checkPrisma()) {
      try {
        const session = await prisma.session.create({
          data: {
            id: data.id || undefined,
            token: hashSessionToken(sessionToken),
            userId: data.userId,
            activeOrganizationId: data.activeOrgId || null,
            expiresAt: data.expiresAt,
          },
        });
        return {
          id: session.id,
          sessionToken,
          userId: session.userId,
          activeOrgId: session.activeOrganizationId,
          expiresAt: session.expiresAt,
          createdAt: session.createdAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const session: SessionRecord = {
      id: data.id || `ses_${crypto.randomBytes(12).toString('hex')}`,
      sessionToken,
      userId: data.userId,
      activeOrgId: data.activeOrgId || null,
      expiresAt: data.expiresAt,
      createdAt: data.createdAt || new Date(),
    };
    this.memStore.sessions.set(hashSessionToken(sessionToken), session);
    return session;
  }

  async findSessionByToken(token: string): Promise<SessionRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const hashed = hashSessionToken(token);
        let session = await prisma.session.findUnique({ where: { token: hashed } });
        if (!session) {
          // Sessions created before tokens were hashed: move them to the hashed form.
          session = await prisma.session.findUnique({ where: { token } });
          if (session) {
            session = await prisma.session.update({ where: { id: session.id }, data: { token: hashed } });
          }
        }
        if (session && session.expiresAt > new Date()) {
          return {
            id: session.id,
            sessionToken: token,
            userId: session.userId,
            activeOrgId: session.activeOrganizationId,
            expiresAt: session.expiresAt,
            createdAt: session.createdAt,
          };
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const session = this.memStore.sessions.get(hashSessionToken(token));
    if (!session) return null;
    if (new Date(session.expiresAt) < new Date()) {
      this.memStore.sessions.delete(hashSessionToken(token));
      return null;
    }
    return session;
  }

  async extendSession(token: string, expiresAt: Date): Promise<void> {
    if (await this.checkPrisma()) {
      try {
        await prisma.session.updateMany({ where: { token: { in: sessionTokenForms(token) } }, data: { expiresAt } });
        return;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const session = this.memStore.sessions.get(hashSessionToken(token));
    if (session) session.expiresAt = expiresAt;
  }

  async updateSessionActiveOrg(token: string, activeOrgId: string): Promise<void> {
    if (await this.checkPrisma()) {
      try {
        await prisma.session.updateMany({
          where: { token: { in: sessionTokenForms(token) } },
          data: { activeOrganizationId: activeOrgId },
        });
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const session = this.memStore.sessions.get(hashSessionToken(token));
    if (session) {
      session.activeOrgId = activeOrgId;
    }
  }

  async deleteSession(token: string): Promise<void> {
    if (await this.checkPrisma()) {
      try {
        await prisma.session.deleteMany({ where: { token: { in: sessionTokenForms(token) } } });
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    this.memStore.sessions.delete(hashSessionToken(token));
  }

  async getUserSessions(userId: string): Promise<SessionRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const sessions = await prisma.session.findMany({
          where: { userId, expiresAt: { gt: new Date() } },
          orderBy: { createdAt: 'desc' },
        });
        if (sessions.length > 0) {
          return sessions.map((s) => ({
            id: s.id,
            sessionToken: '',
            userId: s.userId,
            activeOrgId: s.activeOrganizationId,
            expiresAt: s.expiresAt,
            createdAt: s.createdAt,
          }));
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const results: SessionRecord[] = [];
    const now = new Date();
    for (const session of this.memStore.sessions.values()) {
      if (session.userId === userId && new Date(session.expiresAt) > now) {
        results.push(session);
      }
    }
    return results.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async deleteSessionById(userId: string, sessionId: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.session.deleteMany({ where: { id: sessionId, userId } });
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    for (const [token, session] of this.memStore.sessions.entries()) {
      if (session.id === sessionId && session.userId === userId) {
        this.memStore.sessions.delete(token);
        return true;
      }
    }
    return false;
  }

  // --- ORGANIZATION OPERATIONS ---

  async createOrganization(data: { id?: string; name: string; slug: string; metadata?: string | null }): Promise<OrganizationRecord> {
    if (await this.checkPrisma()) {
      try {
        const org = await prisma.organization.create({
          data: {
            id: data.id || undefined,
            name: data.name,
            slug: data.slug,
            metadata: data.metadata || null,
          },
        });
        return {
          id: org.id,
          name: org.name,
          slug: org.slug || '',
          metadata: org.metadata,
          createdAt: org.createdAt,
          updatedAt: org.createdAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const org: OrganizationRecord = {
      id: data.id || `org_${crypto.randomBytes(12).toString('hex')}`,
      name: data.name,
      slug: data.slug,
      metadata: data.metadata || null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.memStore.organizations.set(org.id, org);
    return org;
  }

  async findOrgById(id: string): Promise<OrganizationRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const org = await prisma.organization.findUnique({ where: { id } });
        if (org) {
          return {
            id: org.id,
            name: org.name,
            slug: org.slug || '',
            metadata: org.metadata,
            createdAt: org.createdAt,
            updatedAt: org.createdAt,
          };
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.organizations.get(id) || null;
  }

  async findOrgBySlug(slug: string): Promise<OrganizationRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const org = await prisma.organization.findUnique({ where: { slug } });
        if (org) {
          return {
            id: org.id,
            name: org.name,
            slug: org.slug || '',
            metadata: org.metadata,
            createdAt: org.createdAt,
            updatedAt: org.createdAt,
          };
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    for (const org of this.memStore.organizations.values()) {
      if (org.slug === slug) return org;
    }
    return null;
  }

  async updateOrg(id: string, data: { name?: string; metadata?: string | null }): Promise<OrganizationRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const org = await prisma.organization.update({
          where: { id },
          data,
        });
        return {
          id: org.id,
          name: org.name,
          slug: org.slug || '',
          metadata: org.metadata,
          createdAt: org.createdAt,
          updatedAt: org.createdAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const org = this.memStore.organizations.get(id);
    if (!org) return null;
    if (data.name) org.name = data.name;
    if (data.metadata !== undefined) org.metadata = data.metadata;
    org.updatedAt = new Date();
    return org;
  }

  async getUserOrganizations(userId: string): Promise<Array<{ organization: OrganizationRecord; role: Role }>> {
    if (await this.checkPrisma()) {
      try {
        const memberships = await prisma.member.findMany({
          where: { userId },
          include: { organization: true },
        });
        if (memberships.length > 0) {
          return memberships.map((m: any) => ({
            organization: {
              id: m.organization.id,
              name: m.organization.name,
              slug: m.organization.slug || '',
              createdAt: m.organization.createdAt,
              updatedAt: m.organization.createdAt,
            },
            role: fromDbRole(m.role),
          }));
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const results: Array<{ organization: OrganizationRecord; role: Role }> = [];
    for (const m of this.memStore.members.values()) {
      if (m.userId === userId) {
        const org = this.memStore.organizations.get(m.organizationId);
        if (org) {
          results.push({ organization: org, role: m.role });
        }
      }
    }
    return results;
  }

  async addMember(data: { organizationId: string; userId: string; role: Role }): Promise<MemberRecord> {
    if (await this.checkPrisma()) {
      try {
        const mem = await prisma.member.create({
          data: {
            organizationId: data.organizationId,
            userId: data.userId,
            role: toDbRole(data.role),
          },
        });
        return {
          id: mem.id,
          organizationId: mem.organizationId,
          userId: mem.userId,
          role: fromDbRole(mem.role),
          createdAt: mem.createdAt,
          updatedAt: mem.createdAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const mem: MemberRecord = {
      id: `mem_${crypto.randomBytes(12).toString('hex')}`,
      organizationId: data.organizationId,
      userId: data.userId,
      role: data.role,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.memStore.members.set(mem.id, mem);
    return mem;
  }

  async getMember(organizationId: string, userId: string): Promise<MemberRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const mem = await prisma.member.findUnique({
          where: {
            userId_organizationId: {
              userId,
              organizationId,
            },
          },
        });
        if (mem) {
          return {
            id: mem.id,
            organizationId: mem.organizationId,
            userId: mem.userId,
            role: fromDbRole(mem.role),
            createdAt: mem.createdAt,
            updatedAt: mem.createdAt,
          };
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    for (const m of this.memStore.members.values()) {
      if (m.organizationId === organizationId && m.userId === userId) {
        return m;
      }
    }
    return null;
  }

  async getOrgMembers(organizationId: string): Promise<Array<MemberRecord & { user: { email: string; name: string | null } }>> {
    if (await this.checkPrisma()) {
      try {
        const members = await prisma.member.findMany({
          where: { organizationId },
          include: { user: { select: { email: true, name: true } } },
        });
        if (members.length > 0) {
          return members.map((m: any) => ({
            id: m.id,
            organizationId: m.organizationId,
            userId: m.userId,
            role: fromDbRole(m.role),
            createdAt: m.createdAt,
            updatedAt: m.createdAt,
            user: {
              email: m.user?.email || 'unknown',
              name: m.user?.name || null,
            },
          }));
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const results: any[] = [];
    for (const m of this.memStore.members.values()) {
      if (m.organizationId === organizationId) {
        const u = this.memStore.users.get(m.userId);
        results.push({
          ...m,
          user: {
            email: u?.email || 'unknown',
            name: u?.name || null,
          },
        });
      }
    }
    return results;
  }

  async removeMember(organizationId: string, memberIdOrUserId: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.member.delete({
          where: {
            userId_organizationId: {
              organizationId,
              userId: memberIdOrUserId,
            },
          },
        }).catch(async () => {
          await prisma.member.delete({ where: { id: memberIdOrUserId } });
        });
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    // Check by id or by userId
    for (const [id, mem] of this.memStore.members.entries()) {
      if (mem.organizationId === organizationId && (mem.id === memberIdOrUserId || mem.userId === memberIdOrUserId)) {
        this.memStore.members.delete(id);
        return true;
      }
    }
    return false;
  }

  async updateMemberRole(organizationId: string, memberIdOrUserId: string, role: Role): Promise<MemberRecord | null> {
    if (await this.checkPrisma()) {
      try {
        let updated: any;
        try {
          updated = await prisma.member.update({
            where: {
              userId_organizationId: {
                organizationId,
                userId: memberIdOrUserId,
              },
            },
            data: { role: toDbRole(role) },
          });
        } catch {
          updated = await prisma.member.update({
            where: { id: memberIdOrUserId },
            data: { role: toDbRole(role) },
          });
        }
        if (updated) {
          return {
            id: updated.id,
            organizationId: updated.organizationId,
            userId: updated.userId,
            role: fromDbRole(updated.role),
            createdAt: updated.createdAt,
            updatedAt: updated.createdAt,
          };
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    for (const mem of this.memStore.members.values()) {
      if (mem.organizationId === organizationId && (mem.id === memberIdOrUserId || mem.userId === memberIdOrUserId)) {
        mem.role = role;
        mem.updatedAt = new Date();
        return mem;
      }
    }
    return null;
  }

  // --- PROJECT OPERATIONS ---

  async createProject(data: { organizationId: string; name: string; slug: string; description?: string }): Promise<ProjectRecord> {
    if (await this.checkPrisma()) {
      try {
        const project = await prisma.project.create({
          data: {
            organizationId: data.organizationId,
            name: data.name,
            slug: data.slug,
            description: data.description || null,
          },
          include: { environments: true },
        });
        return project as ProjectRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const project: ProjectRecord = {
      id: `prj_${crypto.randomBytes(12).toString('hex')}`,
      organizationId: data.organizationId,
      name: data.name,
      slug: data.slug,
      description: data.description || null,
      createdAt: new Date(),
      updatedAt: new Date(),
      environments: [],
    };
    this.memStore.projects.set(project.id, project);
    return project;
  }

  async getProjectsByOrg(organizationId: string): Promise<ProjectRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const projects = await prisma.project.findMany({
          where: { organizationId },
          include: { environments: true },
          orderBy: { createdAt: 'desc' },
        });
        if (projects.length > 0) return projects as ProjectRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const results: ProjectRecord[] = [];
    for (const p of this.memStore.projects.values()) {
      if (p.organizationId === organizationId) {
        const envs = Array.from(this.memStore.environments.values()).filter((e) => e.projectId === p.id);
        results.push({ ...p, environments: envs });
      }
    }
    return results.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getProjectById(projectId: string): Promise<ProjectRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const project = await prisma.project.findUnique({
          where: { id: projectId },
          include: { environments: true },
        });
        if (project) return project as ProjectRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const p = this.memStore.projects.get(projectId);
    if (!p) return null;
    const envs = Array.from(this.memStore.environments.values()).filter((e) => e.projectId === p.id);
    return { ...p, environments: envs };
  }

  async deleteProject(projectId: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.project.delete({ where: { id: projectId } });
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    if (this.memStore.projects.has(projectId)) {
      this.memStore.projects.delete(projectId);
      // Cascade delete environments
      for (const [envId, env] of this.memStore.environments.entries()) {
        if (env.projectId === projectId) {
          this.memStore.environments.delete(envId);
        }
      }
      return true;
    }
    return false;
  }

  async updateProject(projectId: string, data: { name?: string; description?: string }): Promise<ProjectRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const p = await prisma.project.update({
          where: { id: projectId },
          data: { ...data, updatedAt: new Date() },
          include: { environments: true },
        });
        return p as unknown as ProjectRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const p = this.memStore.projects.get(projectId);
    if (!p) return null;
    const updated: ProjectRecord = {
      ...p,
      ...data,
      updatedAt: new Date(),
    };
    this.memStore.projects.set(projectId, updated);
    return updated;
  }

  // --- ENVIRONMENT OPERATIONS ---

  async createEnvironment(data: { projectId: string; name: string; slug: string; type: string }): Promise<EnvironmentRecord> {
    if (await this.checkPrisma()) {
      try {
        const env = await prisma.environment.create({
          data: {
            projectId: data.projectId,
            name: data.name,
            slug: data.slug,
            type: data.type,
          },
        });
        return env as EnvironmentRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const env: EnvironmentRecord = {
      id: `env_${crypto.randomBytes(12).toString('hex')}`,
      projectId: data.projectId,
      name: data.name,
      slug: data.slug,
      type: data.type,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.memStore.environments.set(env.id, env);
    return env;
  }

  async getEnvironmentsByProject(projectId: string): Promise<EnvironmentRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const envs = await prisma.environment.findMany({
          where: { projectId },
          orderBy: { createdAt: 'asc' },
        });
        if (envs.length > 0) return envs as EnvironmentRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const results: EnvironmentRecord[] = [];
    for (const e of this.memStore.environments.values()) {
      if (e.projectId === projectId) results.push(e);
    }
    return results;
  }

  async getEnvironmentById(envId: string): Promise<EnvironmentRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const env = await prisma.environment.findUnique({ where: { id: envId } });
        if (env) return env as EnvironmentRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.environments.get(envId) || null;
  }

  async deleteEnvironment(envId: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.environment.delete({ where: { id: envId } });
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    if (this.memStore.environments.has(envId)) {
      this.memStore.environments.delete(envId);
      return true;
    }
    return false;
  }

  // --- API CREDENTIALS OPERATIONS ---

  async createApiCredential(data: {
    organizationId: string;
    projectId?: string | null;
    environmentId: string;
    name: string;
    prefix: string;
    keyHash: string;
    scopes?: string[];
    allowedIps?: string[] | null;
    status?: string;
    createdBy?: string;
    expiresAt?: Date | null;
  }): Promise<ApiCredentialRecord> {
    const scopes = data.scopes || [
      'keys:read',
      'keys:use',
      'crypto:read',
      'crypto:execute',
      'pqc:read',
      'pqc:execute',
      'certificates:read',
      'inventory:read',
      'cbom:read',
      'advanced_crypto:execute',
    ];
    const status = data.status || 'ACTIVE';

    if (await this.checkPrisma()) {
      try {
        const cred = await prisma.apiCredential.create({
          data: {
            organizationId: data.organizationId,
            projectId: data.projectId || null,
            environmentId: data.environmentId,
            name: data.name,
            prefix: data.prefix,
            keyHash: data.keyHash,
            scopes: scopes as any,
            ...(data.allowedIps && data.allowedIps.length ? { allowedIps: data.allowedIps as any } : {}),
            status,
            createdBy: data.createdBy || null,
            expiresAt: data.expiresAt || null,
          },
        });
        return {
          id: cred.id,
          organizationId: cred.organizationId || data.organizationId,
          projectId: cred.projectId,
          environmentId: cred.environmentId,
          name: cred.name,
          prefix: cred.prefix,
          keyHash: cred.keyHash,
          scopes: (cred.scopes as any) || scopes,
          allowedIps: ((cred as any).allowedIps as string[] | null) || null,
          status: cred.status,
          createdBy: cred.createdBy,
          lastUsedAt: cred.lastUsedAt,
          expiresAt: cred.expiresAt,
          revokedAt: cred.revokedAt,
          createdAt: cred.createdAt,
          updatedAt: cred.updatedAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const cred: ApiCredentialRecord = {
      id: `cred_${crypto.randomBytes(12).toString('hex')}`,
      organizationId: data.organizationId,
      projectId: data.projectId || null,
      environmentId: data.environmentId,
      name: data.name,
      prefix: data.prefix,
      keyHash: data.keyHash,
      scopes,
      allowedIps: data.allowedIps && data.allowedIps.length ? data.allowedIps : null,
      status,
      createdBy: data.createdBy || null,
      lastUsedAt: null,
      expiresAt: data.expiresAt || null,
      revokedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.memStore.credentials.set(cred.id, cred);
    return cred;
  }

  async getCredentialsByOrg(organizationId: string): Promise<ApiCredentialRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const creds = await prisma.apiCredential.findMany({
          where: {
            organizationId,
          },
          orderBy: { createdAt: 'desc' },
        });
        if (creds.length > 0) {
          return creds.map((c) => ({
            id: c.id,
            organizationId: c.organizationId || organizationId,
            projectId: c.projectId,
            environmentId: c.environmentId,
            name: c.name,
            prefix: c.prefix,
            keyHash: c.keyHash,
            scopes: (c.scopes as any) || [],
            allowedIps: ((c as any).allowedIps as string[] | null) || null,
            status: c.status,
            createdBy: c.createdBy,
            lastUsedAt: c.lastUsedAt,
            expiresAt: c.expiresAt,
            revokedAt: c.revokedAt,
            createdAt: c.createdAt,
            updatedAt: c.updatedAt,
          }));
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const results: ApiCredentialRecord[] = [];
    for (const c of this.memStore.credentials.values()) {
      if (c.organizationId === organizationId) results.push(c);
    }
    return results.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async findCredentialByHash(keyHash: string): Promise<ApiCredentialRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const cred = await prisma.apiCredential.findUnique({
          where: { keyHash },
        });
        if (cred) {
          return {
            id: cred.id,
            organizationId: cred.organizationId,
            projectId: cred.projectId,
            environmentId: cred.environmentId,
            name: cred.name,
            prefix: cred.prefix,
            keyHash: cred.keyHash,
            scopes: (cred.scopes as any) || [],
            allowedIps: ((cred as any).allowedIps as string[] | null) || null,
            status: cred.status,
            createdBy: cred.createdBy,
            lastUsedAt: cred.lastUsedAt,
            expiresAt: cred.expiresAt,
            revokedAt: cred.revokedAt,
            createdAt: cred.createdAt,
            updatedAt: cred.updatedAt,
          };
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    for (const c of this.memStore.credentials.values()) {
      if (c.keyHash === keyHash) return c;
    }
    return null;
  }

  async findCredentialById(id: string): Promise<ApiCredentialRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const cred = await prisma.apiCredential.findUnique({
          where: { id },
        });
        if (cred) {
          return {
            id: cred.id,
            organizationId: cred.organizationId,
            projectId: cred.projectId,
            environmentId: cred.environmentId,
            name: cred.name,
            prefix: cred.prefix,
            keyHash: cred.keyHash,
            scopes: (cred.scopes as any) || [],
            allowedIps: ((cred as any).allowedIps as string[] | null) || null,
            status: cred.status,
            createdBy: cred.createdBy,
            lastUsedAt: cred.lastUsedAt,
            expiresAt: cred.expiresAt,
            revokedAt: cred.revokedAt,
            createdAt: cred.createdAt,
            updatedAt: cred.updatedAt,
          };
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.credentials.get(id) || null;
  }

  /** Sets the IPs or CIDR ranges a key may be used from (null or [] means any address). */
  async updateCredentialAllowedIps(id: string, allowedIps: string[] | null): Promise<ApiCredentialRecord | null> {
    const value = allowedIps && allowedIps.length ? allowedIps : null;
    if (await this.checkPrisma()) {
      try {
        await prisma.apiCredential.update({ where: { id }, data: { allowedIps: (value as any) ?? null } as any });
        return this.findCredentialById(id);
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const cred = this.memStore.credentials.get(id);
    if (!cred) return null;
    cred.allowedIps = value;
    cred.updatedAt = new Date();
    return cred;
  }

  async updateCredentialStatus(id: string, status: 'ACTIVE' | 'DISABLED' | 'REVOKED' | 'EXPIRED'): Promise<ApiCredentialRecord | null> {
    const now = new Date();
    if (await this.checkPrisma()) {
      try {
        const cred = await prisma.apiCredential.update({
          where: { id },
          data: {
            status,
            revokedAt: status === 'REVOKED' ? now : undefined,
          },
        });
        return {
          id: cred.id,
          organizationId: cred.organizationId,
          projectId: cred.projectId,
          environmentId: cred.environmentId,
          name: cred.name,
          prefix: cred.prefix,
          keyHash: cred.keyHash,
          scopes: (cred.scopes as any) || [],
          status: cred.status,
          createdBy: cred.createdBy,
          lastUsedAt: cred.lastUsedAt,
          expiresAt: cred.expiresAt,
          revokedAt: cred.revokedAt,
          createdAt: cred.createdAt,
          updatedAt: cred.updatedAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const cred = this.memStore.credentials.get(id);
    if (cred) {
      cred.status = status;
      if (status === 'REVOKED') cred.revokedAt = now;
      cred.updatedAt = now;
      return cred;
    }
    return null;
  }

  async rotateCredential(id: string, newPrefix: string, newKeyHash: string): Promise<ApiCredentialRecord | null> {
    const now = new Date();
    if (await this.checkPrisma()) {
      try {
        const cred = await prisma.apiCredential.update({
          where: { id },
          data: {
            prefix: newPrefix,
            keyHash: newKeyHash,
            status: 'ACTIVE',
            revokedAt: null,
            updatedAt: now,
          },
        });
        return {
          id: cred.id,
          organizationId: cred.organizationId,
          projectId: cred.projectId,
          environmentId: cred.environmentId,
          name: cred.name,
          prefix: cred.prefix,
          keyHash: cred.keyHash,
          scopes: (cred.scopes as any) || [],
          status: cred.status,
          createdBy: cred.createdBy,
          lastUsedAt: cred.lastUsedAt,
          expiresAt: cred.expiresAt,
          revokedAt: cred.revokedAt,
          createdAt: cred.createdAt,
          updatedAt: cred.updatedAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const cred = this.memStore.credentials.get(id);
    if (cred) {
      cred.prefix = newPrefix;
      cred.keyHash = newKeyHash;
      cred.status = 'ACTIVE';
      cred.revokedAt = null;
      cred.updatedAt = now;
      return cred;
    }
    return null;
  }

  async updateCredentialLastUsed(id: string): Promise<void> {
    const now = new Date();
    if (await this.checkPrisma()) {
      try {
        await prisma.apiCredential.update({
          where: { id },
          data: { lastUsedAt: now },
        });
        return;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const cred = this.memStore.credentials.get(id);
    if (cred) {
      cred.lastUsedAt = now;
    }
  }

  /**
   * Replaces a credential's secret only if it still has the secret the caller knows, and only while
   * it is active. One atomic statement, so two concurrent refreshes cannot both succeed and a
   * revoked credential is never brought back.
   */
  async rotateCredentialIfCurrent(
    id: string,
    currentKeyHash: string,
    next: { prefix: string; keyHash: string; expiresAt: Date }
  ): Promise<boolean> {
    if (await this.checkPrisma()) {
      const { count } = await prisma.apiCredential.updateMany({
        where: { id, keyHash: currentKeyHash, status: 'ACTIVE', revokedAt: null },
        data: { prefix: next.prefix, keyHash: next.keyHash, expiresAt: next.expiresAt },
      });
      return count === 1;
    }
    const cred = this.memStore.credentials.get(id);
    if (!cred || cred.keyHash !== currentKeyHash || cred.status !== 'ACTIVE' || cred.revokedAt) return false;
    Object.assign(cred, next, { updatedAt: new Date() });
    return true;
  }

  async revokeCredential(credentialId: string): Promise<boolean> {
    return !!(await this.updateCredentialStatus(credentialId, 'REVOKED'));
  }

  // --- WEBHOOK OPERATIONS ---

  async createWebhookEndpoint(data: {
    organizationId: string;
    url: string;
    description?: string | null;
    secretHash: string;
    secretPrefix: string;
    events: string[];
    status?: string;
  }): Promise<WebhookEndpointRecord> {
    const now = new Date();
    const status = data.status || 'ACTIVE';

    if (await this.checkPrisma()) {
      try {
        const ep = await prisma.webhookEndpoint.create({
          data: {
            organizationId: data.organizationId,
            url: data.url,
            description: data.description || null,
            secretHash: data.secretHash,
            secretPrefix: data.secretPrefix,
            events: data.events as any,
            status,
          },
        });
        return {
          id: ep.id,
          organizationId: ep.organizationId,
          url: ep.url,
          description: ep.description,
          secretHash: ep.secretHash,
          secretPrefix: ep.secretPrefix,
          events: ep.events as any,
          status: ep.status,
          failureCount: ep.failureCount,
          createdAt: ep.createdAt,
          updatedAt: ep.updatedAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const ep: WebhookEndpointRecord = {
      id: `whep_${crypto.randomBytes(12).toString('hex')}`,
      organizationId: data.organizationId,
      url: data.url,
      description: data.description || null,
      secretHash: data.secretHash,
      secretPrefix: data.secretPrefix,
      events: data.events,
      status,
      failureCount: 0,
      createdAt: now,
      updatedAt: now,
    };
    this.memStore.webhookEndpoints.set(ep.id, ep);
    return ep;
  }

  async getWebhookEndpointsByOrg(organizationId: string): Promise<WebhookEndpointRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const eps = await prisma.webhookEndpoint.findMany({
          where: { organizationId },
          orderBy: { createdAt: 'desc' },
        });
        if (eps.length > 0) {
          return eps.map((ep) => ({
            id: ep.id,
            organizationId: ep.organizationId,
            url: ep.url,
            description: ep.description,
            secretHash: ep.secretHash,
            secretPrefix: ep.secretPrefix,
            events: ep.events as any,
            status: ep.status,
            failureCount: ep.failureCount,
            createdAt: ep.createdAt,
            updatedAt: ep.updatedAt,
          }));
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const results: WebhookEndpointRecord[] = [];
    for (const ep of this.memStore.webhookEndpoints.values()) {
      if (ep.organizationId === organizationId) results.push(ep);
    }
    return results.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getWebhookEndpointById(id: string): Promise<WebhookEndpointRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const ep = await prisma.webhookEndpoint.findUnique({
          where: { id },
        });
        if (ep) {
          return {
            id: ep.id,
            organizationId: ep.organizationId,
            url: ep.url,
            description: ep.description,
            secretHash: ep.secretHash,
            secretPrefix: ep.secretPrefix,
            events: ep.events as any,
            status: ep.status,
            failureCount: ep.failureCount,
            createdAt: ep.createdAt,
            updatedAt: ep.updatedAt,
          };
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.webhookEndpoints.get(id) || null;
  }

  async updateWebhookEndpoint(id: string, data: Partial<WebhookEndpointRecord>): Promise<WebhookEndpointRecord | null> {
    const now = new Date();
    if (await this.checkPrisma()) {
      try {
        const ep = await prisma.webhookEndpoint.update({
          where: { id },
          data: {
            url: data.url,
            description: data.description,
            status: data.status,
            events: data.events as any,
            failureCount: data.failureCount,
            updatedAt: now,
          },
        });
        return {
          id: ep.id,
          organizationId: ep.organizationId,
          url: ep.url,
          description: ep.description,
          secretHash: ep.secretHash,
          secretPrefix: ep.secretPrefix,
          events: ep.events as any,
          status: ep.status,
          failureCount: ep.failureCount,
          createdAt: ep.createdAt,
          updatedAt: ep.updatedAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const ep = this.memStore.webhookEndpoints.get(id);
    if (ep) {
      if (data.url !== undefined) ep.url = data.url;
      if (data.description !== undefined) ep.description = data.description;
      if (data.status !== undefined) ep.status = data.status;
      if (data.events !== undefined) ep.events = data.events;
      if (data.failureCount !== undefined) ep.failureCount = data.failureCount;
      ep.updatedAt = now;
      return ep;
    }
    return null;
  }

  async deleteWebhookEndpoint(id: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.webhookEndpoint.delete({ where: { id } });
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const deleted = this.memStore.webhookEndpoints.delete(id);
    return deleted;
  }

  async createWebhookDelivery(data: {
    endpointId: string;
    eventType: string;
    eventId: string;
    payload: any;
    responseStatus?: number | null;
    responseBody?: string | null;
    durationMs?: number | null;
    status: string;
    attempts?: number;
    nextRetryAt?: Date | null;
    error?: string | null;
  }): Promise<WebhookDeliveryRecord> {
    const now = new Date();
    if (await this.checkPrisma()) {
      try {
        const del = await prisma.webhookDelivery.create({
          data: {
            endpointId: data.endpointId,
            eventType: data.eventType,
            eventId: data.eventId,
            payload: data.payload,
            responseStatus: data.responseStatus || null,
            responseBody: data.responseBody || null,
            durationMs: data.durationMs || null,
            status: data.status,
            attempts: data.attempts || 1,
            nextRetryAt: data.nextRetryAt || null,
            error: data.error || null,
          },
        });
        return {
          id: del.id,
          endpointId: del.endpointId,
          eventType: del.eventType,
          eventId: del.eventId,
          payload: del.payload,
          responseStatus: del.responseStatus,
          responseBody: del.responseBody,
          durationMs: del.durationMs,
          status: del.status,
          attempts: del.attempts,
          nextRetryAt: del.nextRetryAt,
          error: del.error,
          createdAt: del.createdAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const del: WebhookDeliveryRecord = {
      id: `whdel_${crypto.randomBytes(12).toString('hex')}`,
      endpointId: data.endpointId,
      eventType: data.eventType,
      eventId: data.eventId,
      payload: data.payload,
      responseStatus: data.responseStatus || null,
      responseBody: data.responseBody || null,
      durationMs: data.durationMs || null,
      status: data.status,
      attempts: data.attempts || 1,
      nextRetryAt: data.nextRetryAt || null,
      error: data.error || null,
      createdAt: now,
    };
    this.memStore.webhookDeliveries.set(del.id, del);
    return del;
  }

  async updateWebhookDelivery(id: string, data: Partial<WebhookDeliveryRecord>): Promise<WebhookDeliveryRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const del = await prisma.webhookDelivery.update({
          where: { id },
          data: {
            responseStatus: data.responseStatus,
            responseBody: data.responseBody,
            durationMs: data.durationMs,
            status: data.status,
            attempts: data.attempts,
            nextRetryAt: data.nextRetryAt,
            error: data.error,
          },
        });
        return {
          id: del.id,
          endpointId: del.endpointId,
          eventType: del.eventType,
          eventId: del.eventId,
          payload: del.payload,
          responseStatus: del.responseStatus,
          responseBody: del.responseBody,
          durationMs: del.durationMs,
          status: del.status,
          attempts: del.attempts,
          nextRetryAt: del.nextRetryAt,
          error: del.error,
          createdAt: del.createdAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const del = this.memStore.webhookDeliveries.get(id);
    if (del) {
      if (data.responseStatus !== undefined) del.responseStatus = data.responseStatus;
      if (data.responseBody !== undefined) del.responseBody = data.responseBody;
      if (data.durationMs !== undefined) del.durationMs = data.durationMs;
      if (data.status !== undefined) del.status = data.status;
      if (data.attempts !== undefined) del.attempts = data.attempts;
      if (data.nextRetryAt !== undefined) del.nextRetryAt = data.nextRetryAt;
      if (data.error !== undefined) del.error = data.error;
      return del;
    }
    return null;
  }

  async getWebhookDeliveries(endpointId: string, limit = 50): Promise<WebhookDeliveryRecord[]> {
    return this.getWebhookDeliveriesByEndpoint(endpointId, limit);
  }

  async getWebhookDeliveriesByEndpoint(endpointId: string, limit = 50): Promise<WebhookDeliveryRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const dels = await prisma.webhookDelivery.findMany({
          where: { endpointId },
          orderBy: { createdAt: 'desc' },
          take: limit,
        });
        if (dels.length > 0) {
          return dels.map((d) => ({
            id: d.id,
            endpointId: d.endpointId,
            eventType: d.eventType,
            eventId: d.eventId,
            payload: d.payload,
            responseStatus: d.responseStatus,
            responseBody: d.responseBody,
            durationMs: d.durationMs,
            status: d.status,
            attempts: d.attempts,
            nextRetryAt: d.nextRetryAt,
            error: d.error,
            createdAt: d.createdAt,
          }));
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const results: WebhookDeliveryRecord[] = [];
    for (const d of this.memStore.webhookDeliveries.values()) {
      if (d.endpointId === endpointId) results.push(d);
    }
    return results.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()).slice(0, limit);
  }

  // --- ASYNC JOB OPERATIONS ---

  async createAsyncJob(data: {
    organizationId: string;
    projectId?: string | null;
    environmentId?: string | null;
    type: string;
    input?: any;
    expiresInMs?: number;
  }): Promise<AsyncJobRecord> {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + (data.expiresInMs || 24 * 60 * 60 * 1000));

    if (await this.checkPrisma()) {
      try {
        const job = await prisma.asyncJob.create({
          data: {
            organizationId: data.organizationId,
            projectId: data.projectId || null,
            environmentId: data.environmentId || null,
            type: data.type,
            status: 'QUEUED',
            progress: 0,
            input: data.input || null,
            expiresAt,
          },
        });
        return {
          id: job.id,
          organizationId: job.organizationId,
          projectId: job.projectId,
          environmentId: job.environmentId,
          type: job.type,
          status: job.status,
          progress: job.progress,
          input: job.input,
          result: job.result,
          error: job.error,
          durationMs: job.durationMs,
          expiresAt: job.expiresAt,
          createdAt: job.createdAt,
          updatedAt: job.updatedAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const job: AsyncJobRecord = {
      id: `job_${crypto.randomBytes(12).toString('hex')}`,
      organizationId: data.organizationId,
      projectId: data.projectId || null,
      environmentId: data.environmentId || null,
      type: data.type,
      status: 'QUEUED',
      progress: 0,
      input: data.input || null,
      result: null,
      error: null,
      durationMs: null,
      expiresAt,
      createdAt: now,
      updatedAt: now,
    };
    this.memStore.asyncJobs.set(job.id, job);
    return job;
  }

  async getAsyncJobById(id: string): Promise<AsyncJobRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const job = await prisma.asyncJob.findUnique({
          where: { id },
        });
        if (job) {
          return {
            id: job.id,
            organizationId: job.organizationId,
            projectId: job.projectId,
            environmentId: job.environmentId,
            type: job.type,
            status: job.status,
            progress: job.progress,
            input: job.input,
            result: job.result,
            error: job.error,
            durationMs: job.durationMs,
            expiresAt: job.expiresAt,
            createdAt: job.createdAt,
            updatedAt: job.updatedAt,
          };
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.asyncJobs.get(id) || null;
  }

  async updateAsyncJob(id: string, data: Partial<AsyncJobRecord>): Promise<AsyncJobRecord | null> {
    const now = new Date();
    if (await this.checkPrisma()) {
      try {
        const job = await prisma.asyncJob.update({
          where: { id },
          data: {
            status: data.status,
            progress: data.progress,
            result: data.result,
            error: data.error,
            durationMs: data.durationMs,
            updatedAt: now,
          },
        });
        return {
          id: job.id,
          organizationId: job.organizationId,
          projectId: job.projectId,
          environmentId: job.environmentId,
          type: job.type,
          status: job.status,
          progress: job.progress,
          input: job.input,
          result: job.result,
          error: job.error,
          durationMs: job.durationMs,
          expiresAt: job.expiresAt,
          createdAt: job.createdAt,
          updatedAt: job.updatedAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const job = this.memStore.asyncJobs.get(id);
    if (job) {
      if (data.status !== undefined) job.status = data.status;
      if (data.progress !== undefined) job.progress = data.progress;
      if (data.result !== undefined) job.result = data.result;
      if (data.error !== undefined) job.error = data.error;
      if (data.durationMs !== undefined) job.durationMs = data.durationMs;
      job.updatedAt = now;
      return job;
    }
    return null;
  }

  async getAsyncJobsByOrg(organizationId: string, limit = 50): Promise<AsyncJobRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const jobs = await prisma.asyncJob.findMany({
          where: { organizationId },
          orderBy: { createdAt: 'desc' },
          take: limit,
        });
        if (jobs.length > 0) {
          return jobs.map((j) => ({
            id: j.id,
            organizationId: j.organizationId,
            projectId: j.projectId,
            environmentId: j.environmentId,
            type: j.type,
            status: j.status,
            progress: j.progress,
            input: j.input,
            result: j.result,
            error: j.error,
            durationMs: j.durationMs,
            expiresAt: j.expiresAt,
            createdAt: j.createdAt,
            updatedAt: j.updatedAt,
          }));
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const results: AsyncJobRecord[] = [];
    for (const j of this.memStore.asyncJobs.values()) {
      if (j.organizationId === organizationId) results.push(j);
    }
    return results.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()).slice(0, limit);
  }

  // --- API USAGE OPERATIONS ---

  async recordApiUsage(data: {
    organizationId: string;
    projectId?: string | null;
    environmentId?: string | null;
    credentialId?: string | null;
    endpoint: string;
    method: string;
    statusCode: number;
    durationMs: number;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<void> {
    const record: ApiUsageRecord = {
      id: `usg_${crypto.randomBytes(12).toString('hex')}`,
      organizationId: data.organizationId,
      projectId: data.projectId || null,
      environmentId: data.environmentId || null,
      credentialId: data.credentialId || null,
      endpoint: data.endpoint,
      method: data.method,
      statusCode: data.statusCode,
      durationMs: data.durationMs,
      ipAddress: data.ipAddress || null,
      userAgent: data.userAgent || null,
      timestamp: new Date(),
    };

    if (await this.checkPrisma()) {
      try {
        await prisma.apiUsageRecord.create({
          data: {
            organizationId: data.organizationId,
            projectId: data.projectId || null,
            environmentId: data.environmentId || null,
            credentialId: data.credentialId || null,
            endpoint: data.endpoint,
            method: data.method,
            statusCode: data.statusCode,
            durationMs: data.durationMs,
            ipAddress: data.ipAddress || null,
            userAgent: data.userAgent || null,
          },
        });
        return;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.apiUsageRecords.push(record);
    if (this.memStore.apiUsageRecords.length > 10000) {
      this.memStore.apiUsageRecords = this.memStore.apiUsageRecords.slice(-5000);
    }
  }

  async getApiUsageMetrics(
    organizationId: string,
    options: { from?: Date; to?: Date; credentialId?: string } = {}
  ): Promise<{
    totalRequests: number;
    successRequests: number;
    errorRequests: number;
    averageLatencyMs: number;
    byEndpoint: { [endpoint: string]: number };
    byStatusCode: { [code: string]: number };
    recentRecords: ApiUsageRecord[];
  }> {
    let records: ApiUsageRecord[] = [];

    if (await this.checkPrisma()) {
      try {
        const whereClause: any = { organizationId };
        if (options.credentialId) whereClause.credentialId = options.credentialId;
        if (options.from || options.to) {
          whereClause.timestamp = {};
          if (options.from) whereClause.timestamp.gte = options.from;
          if (options.to) whereClause.timestamp.lte = options.to;
        }
        // Totals come from the database; counting a page of rows capped every figure at 500.
        const [aggregate, byEndpointRows, byStatusRows, dbRecords] = await Promise.all([
          prisma.apiUsageRecord.aggregate({ where: whereClause, _count: { _all: true }, _avg: { durationMs: true } }),
          prisma.apiUsageRecord.groupBy({ by: ['endpoint'], where: whereClause, _count: { _all: true } }),
          prisma.apiUsageRecord.groupBy({ by: ['statusCode'], where: whereClause, _count: { _all: true } }),
          prisma.apiUsageRecord.findMany({ where: whereClause, orderBy: { timestamp: 'desc' }, take: 50 }),
        ]);
        const byEndpoint: { [endpoint: string]: number } = {};
        for (const row of byEndpointRows) byEndpoint[row.endpoint] = row._count._all;
        const byStatusCode: { [code: string]: number } = {};
        let successRequests = 0;
        for (const row of byStatusRows) {
          byStatusCode[row.statusCode] = row._count._all;
          if (row.statusCode >= 200 && row.statusCode < 400) successRequests += row._count._all;
        }
        const totalRequests = aggregate._count._all;
        return {
          totalRequests,
          successRequests,
          errorRequests: totalRequests - successRequests,
          averageLatencyMs: Math.round(aggregate._avg.durationMs || 0),
          byEndpoint,
          byStatusCode,
          recentRecords: dbRecords.map((r) => ({
            id: r.id,
            organizationId: r.organizationId,
            projectId: r.projectId,
            environmentId: r.environmentId,
            credentialId: r.credentialId,
            endpoint: r.endpoint,
            method: r.method,
            statusCode: r.statusCode,
            durationMs: r.durationMs,
            ipAddress: r.ipAddress,
            userAgent: r.userAgent,
            timestamp: r.timestamp,
          })),
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    // Memory mode (tests): count every matching record.
    if (records.length === 0) {
      records = this.memStore.apiUsageRecords.filter((r) => {
        if (r.organizationId !== organizationId) return false;
        if (options.credentialId && r.credentialId !== options.credentialId) return false;
        if (options.from && r.timestamp < options.from) return false;
        if (options.to && r.timestamp > options.to) return false;
        return true;
      });
    }

    const byEndpoint: { [endpoint: string]: number } = {};
    const byStatusCode: { [code: string]: number } = {};
    let totalLatency = 0;
    let successCount = 0;
    let errorCount = 0;

    for (const r of records) {
      byEndpoint[r.endpoint] = (byEndpoint[r.endpoint] || 0) + 1;
      byStatusCode[r.statusCode] = (byStatusCode[r.statusCode] || 0) + 1;
      totalLatency += r.durationMs;
      if (r.statusCode >= 200 && r.statusCode < 400) {
        successCount++;
      } else {
        errorCount++;
      }
    }

    return {
      totalRequests: records.length,
      successRequests: successCount,
      errorRequests: errorCount,
      averageLatencyMs: records.length > 0 ? Math.round(totalLatency / records.length) : 0,
      byEndpoint,
      byStatusCode,
      recentRecords: records.slice(0, 50),
    };
  }

  // --- AUDIT EVENT OPERATIONS ---

  private scrubSensitiveAuditMetadata(metadata: any): any {
    if (!metadata || typeof metadata !== 'object') return metadata;
    const sensitiveKeys = [
      'password', 'passwordhash', 'secret', 'token', 'otp', 'code',
      'privatekey', 'rawkey', 'authorization', 'bearer', 'cvv', 'cardnumber'
    ];
    if (Array.isArray(metadata)) {
      return metadata.map(item => this.scrubSensitiveAuditMetadata(item));
    }
    const cleaned: Record<string, any> = {};
    for (const [key, val] of Object.entries(metadata)) {
      const lowerKey = key.toLowerCase();
      if (sensitiveKeys.some(s => lowerKey.includes(s))) {
        cleaned[key] = '[REDACTED_FOR_PRIVACY]';
      } else if (val && typeof val === 'object') {
        cleaned[key] = this.scrubSensitiveAuditMetadata(val);
      } else {
        cleaned[key] = val;
      }
    }
    return cleaned;
  }

  async createAuditEvent(data: {
    organizationId?: string | null;
    userId?: string | null;
    action: string;
    resourceType: string;
    resourceId?: string | null;
    metadata?: any;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<AuditEventRecord> {
    const sanitizedMetadata = this.scrubSensitiveAuditMetadata(data.metadata || {});
    const metaWithResource = {
      ...sanitizedMetadata,
      resourceType: data.resourceType,
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
    };

    if (await this.checkPrisma()) {
      try {
        const event = await prisma.auditEvent.create({
          data: {
            organizationId: data.organizationId || null,
            actorId: data.userId || null,
            action: data.action,
            resourceId: data.resourceId || null,
            metadata: metaWithResource,
          },
        });
        return {
          id: event.id,
          organizationId: event.organizationId,
          userId: event.actorId,
          action: event.action,
          resourceType: data.resourceType,
          resourceId: event.resourceId,
          metadata: event.metadata,
          ipAddress: data.ipAddress || null,
          userAgent: data.userAgent || null,
          createdAt: event.createdAt,
        };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const event: AuditEventRecord = {
      id: `aud_${crypto.randomBytes(12).toString('hex')}`,
      organizationId: data.organizationId || null,
      userId: data.userId || null,
      action: data.action,
      resourceType: data.resourceType,
      resourceId: data.resourceId || null,
      metadata: sanitizedMetadata,
      ipAddress: data.ipAddress || null,
      userAgent: data.userAgent || null,
      createdAt: new Date(),
    };
    this.memStore.auditEvents.unshift(event);
    if (this.memStore.auditEvents.length > 500) {
      this.memStore.auditEvents.pop();
    }
    return event;
  }

  /**
   * Newest first. `before` returns only events older than that time (to page back through the
   * log); `action` keeps only one action, e.g. "crypto.decrypt".
   */
  async getAuditEventsByOrg(
    organizationId: string,
    limit = 50,
    options: { before?: Date; action?: string } = {}
  ): Promise<AuditEventRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const events = await prisma.auditEvent.findMany({
          where: {
            organizationId,
            ...(options.before ? { createdAt: { lt: options.before } } : {}),
            ...(options.action ? { action: options.action } : {}),
          },
          orderBy: { createdAt: 'desc' },
          take: limit,
        });
        if (events.length > 0) {
          return events.map((e) => {
            const meta = (e.metadata as any) || {};
            return {
              id: e.id,
              organizationId: e.organizationId,
              userId: e.actorId,
              action: e.action,
              resourceType: meta.resourceType || 'Resource',
              resourceId: e.resourceId,
              metadata: meta,
              ipAddress: meta.ipAddress || null,
              userAgent: meta.userAgent || null,
              createdAt: e.createdAt,
            };
          });
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.auditEvents
      .filter((a) => a.organizationId === organizationId)
      .filter((a) => !options.before || new Date(a.createdAt).getTime() < options.before.getTime())
      .filter((a) => !options.action || a.action === options.action)
      .sort((x, y) => new Date(y.createdAt).getTime() - new Date(x.createdAt).getTime())
      .slice(0, limit);
  }

  // --- CRYPTOGRAPHIC KEY OPERATIONS ---

  async createKey(data: {
    name: string;
    description?: string | null;
    organizationId: string;
    projectId: string;
    environmentId: string;
    algorithm: string;
    purpose: string;
    provider: string;
    status?: string;
    metadata?: any;
  }): Promise<CryptographicKeyRecord> {
    if (await this.checkPrisma()) {
      try {
        const record = await prisma.cryptographicKey.create({
          data: {
            name: data.name,
            description: data.description || null,
            organizationId: data.organizationId,
            projectId: data.projectId,
            environmentId: data.environmentId,
            algorithm: data.algorithm,
            purpose: data.purpose,
            provider: data.provider,
            status: data.status || 'ACTIVE',
            metadata: data.metadata || null,
          },
          include: {
            versions: true,
            project: true,
            environment: true,
          },
        });
        return record as CryptographicKeyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const id = `key_${crypto.randomBytes(12).toString('hex')}`;
    const now = new Date();
    const keyRecord: CryptographicKeyRecord = {
      id,
      name: data.name,
      description: data.description || null,
      organizationId: data.organizationId,
      projectId: data.projectId,
      environmentId: data.environmentId,
      algorithm: data.algorithm,
      purpose: data.purpose,
      provider: data.provider,
      status: data.status || 'ACTIVE',
      currentVersion: 1,
      metadata: data.metadata || null,
      createdAt: now,
      updatedAt: now,
      activatedAt: now,
    };
    this.memStore.keys.set(id, keyRecord);
    return keyRecord;
  }

  async findKeyById(id: string, orgId?: string): Promise<CryptographicKeyRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { id };
        if (orgId) where.organizationId = orgId;
        const key = await prisma.cryptographicKey.findFirst({
          where,
          include: {
            versions: { orderBy: { version: 'desc' } },
            project: true,
            environment: true,
          },
        });
        if (key) return key as CryptographicKeyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const key = this.memStore.keys.get(id);
    if (!key) return null;
    if (orgId && key.organizationId !== orgId) return null;

    const versions = Array.from(this.memStore.keyVersions.values())
      .filter((v) => v.keyId === key.id)
      .sort((a, b) => b.version - a.version);
    const project = this.memStore.projects.get(key.projectId);
    const environment = this.memStore.environments.get(key.environmentId);

    return {
      ...key,
      versions,
      project,
      environment,
    };
  }

  async getKey(id: string, orgId?: string): Promise<CryptographicKeyRecord | null> {
    return this.findKeyById(id, orgId);
  }

  async findKeyByName(
    orgId: string,
    projectId: string,
    environmentId: string,
    name: string
  ): Promise<CryptographicKeyRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const key = await prisma.cryptographicKey.findFirst({
          where: {
            organizationId: orgId,
            projectId,
            environmentId,
            name,
          },
          include: {
            versions: { orderBy: { version: 'desc' } },
          },
        });
        if (key) return key as CryptographicKeyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    for (const key of this.memStore.keys.values()) {
      if (
        key.organizationId === orgId &&
        key.projectId === projectId &&
        key.environmentId === environmentId &&
        key.name.toLowerCase() === name.toLowerCase()
      ) {
        return key;
      }
    }
    return null;
  }

  async listKeys(params: {
    organizationId: string;
    projectId?: string;
    environmentId?: string;
    status?: string;
    search?: string;
  }): Promise<CryptographicKeyRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { organizationId: params.organizationId };
        if (params.projectId) where.projectId = params.projectId;
        if (params.environmentId) where.environmentId = params.environmentId;
        if (params.status) where.status = params.status;
        if (params.search) {
          where.OR = [
            { name: { contains: params.search, mode: 'insensitive' } },
            { description: { contains: params.search, mode: 'insensitive' } },
          ];
        }
        const keys = await prisma.cryptographicKey.findMany({
          where,
          include: {
            versions: { orderBy: { version: 'desc' } },
            project: true,
            environment: true,
          },
          orderBy: { createdAt: 'desc' },
        });
        return keys as CryptographicKeyRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    let list = Array.from(this.memStore.keys.values()).filter(
      (k) => k.organizationId === params.organizationId
    );
    if (params.projectId) list = list.filter((k) => k.projectId === params.projectId);
    if (params.environmentId) list = list.filter((k) => k.environmentId === params.environmentId);
    if (params.status) list = list.filter((k) => k.status === params.status);
    if (params.search) {
      const q = params.search.toLowerCase();
      list = list.filter((k) => k.name.toLowerCase().includes(q) || k.description?.toLowerCase().includes(q));
    }

    return list.map((key) => {
      const versions = Array.from(this.memStore.keyVersions.values())
        .filter((v) => v.keyId === key.id)
        .sort((a, b) => b.version - a.version);
      const project = this.memStore.projects.get(key.projectId);
      const environment = this.memStore.environments.get(key.environmentId);
      return { ...key, versions, project, environment };
    });
  }

  async updateKey(id: string, data: Partial<CryptographicKeyRecord>): Promise<CryptographicKeyRecord> {
    if (await this.checkPrisma()) {
      try {
        const { versions: _versions, project: _project, environment: _environment, ...fields } = data;
        const updated = await prisma.cryptographicKey.update({
          where: { id },
          data: {
            ...fields,
            updatedAt: new Date(),
          },
          include: {
            versions: { orderBy: { version: 'desc' } },
            project: true,
            environment: true,
          },
        });
        return updated as CryptographicKeyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const current = this.memStore.keys.get(id);
    if (!current) throw new Error(`Key ${id} not found.`);
    const updated: CryptographicKeyRecord = {
      ...current,
      ...data,
      updatedAt: new Date(),
    };
    this.memStore.keys.set(id, updated);
    return updated;
  }

  async createKeyVersion(data: {
    keyId: string;
    version: number;
    providerKeyId: string;
    status?: string;
    publicKey?: string | null;
    encryptedKeyMaterial?: string | null;
    keyFingerprint?: string | null;
    metadata?: any;
  }): Promise<CryptographicKeyVersionRecord> {
    if (await this.checkPrisma()) {
      try {
        const created = await prisma.cryptographicKeyVersion.create({
          data: {
            keyId: data.keyId,
            version: data.version,
            providerKeyId: data.providerKeyId,
            status: data.status || 'ACTIVE',
            publicKey: data.publicKey || null,
            encryptedKeyMaterial: data.encryptedKeyMaterial || null,
            keyFingerprint: data.keyFingerprint || null,
            metadata: data.metadata || null,
          },
        });
        return created as CryptographicKeyVersionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const id = `ver_${crypto.randomBytes(12).toString('hex')}`;
    const now = new Date();
    const verRecord: CryptographicKeyVersionRecord = {
      id,
      keyId: data.keyId,
      version: data.version,
      providerKeyId: data.providerKeyId,
      status: data.status || 'ACTIVE',
      publicKey: data.publicKey || null,
      encryptedKeyMaterial: data.encryptedKeyMaterial || null,
      keyFingerprint: data.keyFingerprint || null,
      metadata: data.metadata || null,
      createdAt: now,
      activatedAt: now,
    };
    this.memStore.keyVersions.set(id, verRecord);
    return verRecord;
  }

  async addKeyVersion(data: {
    keyId: string;
    version: number;
    providerKeyId: string;
    status?: string;
    publicKey?: string | null;
    encryptedKeyMaterial?: string | null;
    keyFingerprint?: string | null;
    metadata?: any;
  }): Promise<CryptographicKeyVersionRecord> {
    return this.createKeyVersion(data);
  }

  async findKeyVersionByNumber(keyId: string, versionNumber: number): Promise<CryptographicKeyVersionRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const ver = await prisma.cryptographicKeyVersion.findUnique({
          where: {
            keyId_version: {
              keyId,
              version: versionNumber,
            },
          },
        });
        if (ver) return ver as CryptographicKeyVersionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    for (const v of this.memStore.keyVersions.values()) {
      if (v.keyId === keyId && v.version === versionNumber) {
        return v;
      }
    }
    return null;
  }

  async findKeyVersionById(versionId: string): Promise<CryptographicKeyVersionRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const ver = await prisma.cryptographicKeyVersion.findUnique({
          where: { id: versionId },
        });
        if (ver) return ver as CryptographicKeyVersionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.keyVersions.get(versionId) || null;
  }

  async listKeyVersions(keyId: string): Promise<CryptographicKeyVersionRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const vers = await prisma.cryptographicKeyVersion.findMany({
          where: { keyId },
          orderBy: { version: 'desc' },
        });
        return vers as CryptographicKeyVersionRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return Array.from(this.memStore.keyVersions.values())
      .filter((v) => v.keyId === keyId)
      .sort((a, b) => b.version - a.version);
  }

  async updateKeyVersion(id: string, data: Partial<CryptographicKeyVersionRecord>): Promise<CryptographicKeyVersionRecord> {
    if (await this.checkPrisma()) {
      try {
        const updated = await prisma.cryptographicKeyVersion.update({
          where: { id },
          data,
        });
        return updated as CryptographicKeyVersionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const current = this.memStore.keyVersions.get(id);
    if (!current) throw new Error(`Key version ${id} not found.`);
    const updated: CryptographicKeyVersionRecord = {
      ...current,
      ...data,
    };
    this.memStore.keyVersions.set(id, updated);
    return updated;
  }

  // =========================================================================
  // Phase 5.2 — Customer BYOK / HSM Provider Persistence
  // =========================================================================

  async createCustomerProvider(data: {
    organizationId: string;
    projectId: string;
    environmentId: string;
    name: string;
    displayName?: string | null;
    providerType: 'AZURE_KEY_VAULT' | 'AZURE_MANAGED_HSM';
    resourceType?: string;
    ownershipType?: string;
    vaultUrl: string;
    hsmUrl?: string | null;
    resourceId?: string | null;
    authType?: string;
    authenticationMethod?: string;
    encryptedAuthConfig?: string | null;
    status?: string;
    connectionStatus?: string;
    onboardingState?: string;
    capabilityDiscoveryStatus?: string;
    isHsmBacked?: boolean;
    capabilities?: any;
    lastHealthCheckAt?: Date | null;
    healthStatus?: string | null;
    healthMessage?: string | null;
    lastHealthCheckError?: string | null;
  }): Promise<CustomerKeyProviderRecord> {
    const id = `ckp_${crypto.randomUUID()}`;
    const now = new Date();
    const record: CustomerKeyProviderRecord = {
      id,
      organizationId: data.organizationId,
      projectId: data.projectId,
      environmentId: data.environmentId,
      name: data.name,
      displayName: data.displayName || data.name,
      providerType: data.providerType,
      resourceType: data.resourceType || (data.providerType === 'AZURE_MANAGED_HSM' ? 'MANAGED_HSM' : 'KEY_VAULT'),
      ownershipType: data.ownershipType || 'CUSTOMER_OWNED',
      vaultUrl: data.vaultUrl,
      hsmUrl: data.hsmUrl || null,
      resourceId: data.resourceId || null,
      authType: data.authType || 'SERVICE_PRINCIPAL',
      authenticationMethod: data.authenticationMethod || data.authType || 'SERVICE_PRINCIPAL',
      encryptedAuthConfig: data.encryptedAuthConfig || null,
      // A new provider has not been tested; it only becomes CONNECTED/HEALTHY through a real
      // connection test (POST .../byok/providers/test).
      status: data.status || 'PENDING_CONNECTION',
      connectionStatus: data.connectionStatus || 'NOT_TESTED',
      onboardingState: data.onboardingState || ((data.status === 'CONNECTED' || data.connectionStatus === 'CONNECTED') ? 'READY' : 'CONFIGURED'),
      capabilityDiscoveryStatus: data.capabilityDiscoveryStatus || (data.status === 'CONNECTED' ? 'COMPLETED' : 'NOT_STARTED'),
      isHsmBacked: !!data.isHsmBacked,
      capabilities: data.capabilities || null,
      lastHealthCheckAt: data.lastHealthCheckAt || null,
      healthStatus: data.healthStatus || 'UNKNOWN',
      healthMessage: data.healthMessage || 'Connection not tested yet.',
      lastHealthCheckError: data.lastHealthCheckError || null,
      createdAt: now,
      updatedAt: now,
    };

    if (await this.checkPrisma()) {
      try {
        const created = await prisma.customerKeyProvider.create({
          data: {
            id: record.id,
            organization: { connect: { id: record.organizationId } },
            project: { connect: { id: record.projectId } },
            environment: { connect: { id: record.environmentId } },
            name: record.name,
            displayName: record.displayName,
            providerType: record.providerType,
            resourceType: record.resourceType,
            ownershipType: record.ownershipType,
            vaultUrl: record.vaultUrl,
            hsmUrl: record.hsmUrl,
            resourceId: record.resourceId,
            authType: record.authType,
            authenticationMethod: record.authenticationMethod,
            encryptedAuthConfig: record.encryptedAuthConfig,
            status: record.status,
            connectionStatus: record.connectionStatus,
            onboardingState: record.onboardingState,
            capabilityDiscoveryStatus: record.capabilityDiscoveryStatus,
            isHsmBacked: record.isHsmBacked,
            capabilities: record.capabilities,
            lastHealthCheckAt: record.lastHealthCheckAt,
            healthStatus: record.healthStatus,
            healthMessage: record.healthMessage,
            lastHealthCheckError: record.lastHealthCheckError,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt,
          },
        });
        this.memStore.customerProviders.set(id, created as CustomerKeyProviderRecord);
        return created as CustomerKeyProviderRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.customerProviders.set(id, record);
    return record;
  }

  async findCustomerProviderById(id: string): Promise<CustomerKeyProviderRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const p = await prisma.customerKeyProvider.findUnique({
          where: { id },
          include: { registeredKeys: true },
        });
        if (p) return p as CustomerKeyProviderRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.customerProviders.get(id) || null;
  }

  async listCustomerProviders(filters: {
    organizationId: string;
    projectId?: string;
    environmentId?: string;
  }): Promise<CustomerKeyProviderRecord[]> {
    const memList = Array.from(this.memStore.customerProviders.values()).filter((p) => {
      if (p.organizationId !== filters.organizationId) return false;
      if (filters.projectId && p.projectId !== filters.projectId) return false;
      if (filters.environmentId && p.environmentId !== filters.environmentId) return false;
      return true;
    });

    if (await this.checkPrisma()) {
      try {
        const where: any = { organizationId: filters.organizationId };
        if (filters.projectId) where.projectId = filters.projectId;
        if (filters.environmentId) where.environmentId = filters.environmentId;
        const list = await prisma.customerKeyProvider.findMany({
          where,
          include: { registeredKeys: true },
          orderBy: { createdAt: 'desc' },
        });
        
        const map = new Map<string, CustomerKeyProviderRecord>();
        for (const item of (list || [])) {
          map.set(item.id, item as CustomerKeyProviderRecord);
        }
        for (const item of memList) {
          if (!map.has(item.id)) {
            map.set(item.id, item);
          }
        }
        return Array.from(map.values());
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return memList;
  }

  async updateCustomerProvider(
    id: string,
    data: Partial<CustomerKeyProviderRecord>
  ): Promise<CustomerKeyProviderRecord> {
    if (await this.checkPrisma()) {
      try {
        const updated = await prisma.customerKeyProvider.update({
          where: { id },
          data: { ...data, updatedAt: new Date() },
        });
        return updated as CustomerKeyProviderRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const current = this.memStore.customerProviders.get(id);
    if (!current) throw new Error(`Customer provider ${id} not found.`);
    const updated: CustomerKeyProviderRecord = {
      ...current,
      ...data,
      updatedAt: new Date(),
    };
    this.memStore.customerProviders.set(id, updated);
    return updated;
  }

  async deleteCustomerProvider(id: string): Promise<void> {
    if (await this.checkPrisma()) {
      try {
        await prisma.customerKeyProvider.delete({
          where: { id },
        });
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    this.memStore.customerProviders.delete(id);
  }

  async createCustomerRegisteredKey(data: {
    providerId: string;
    organizationId: string;
    projectId: string;
    environmentId: string;
    keyIdentifier: string;
    displayName?: string | null;
    keyVaultUrl: string;
    keyType: string;
    algorithm?: string;
    purpose?: string;
    ownershipType?: string;
    isHsmBacked?: boolean;
    hsmBackedStatus?: string;
    status?: string;
    keyState?: string;
    currentVersion: string;
    publicKey?: string | null;
    keyFingerprint?: string | null;
    operations?: any;
    capabilities?: any;
    metadata?: any;
  }): Promise<CustomerRegisteredKeyRecord> {
    const id = `crk_${crypto.randomUUID()}`;
    const now = new Date();
    const record: CustomerRegisteredKeyRecord = {
      id,
      providerId: data.providerId,
      organizationId: data.organizationId,
      projectId: data.projectId,
      environmentId: data.environmentId,
      keyIdentifier: data.keyIdentifier,
      displayName: data.displayName || data.keyIdentifier,
      keyVaultUrl: data.keyVaultUrl,
      keyType: data.keyType,
      algorithm: data.algorithm || 'AES-256-GCM',
      purpose: data.purpose || 'ENCRYPTION',
      ownershipType: data.ownershipType || 'CUSTOMER_OWNED',
      isHsmBacked: !!data.isHsmBacked,
      hsmBackedStatus: data.hsmBackedStatus || (data.isHsmBacked ? 'VERIFIED_HSM' : 'STANDARD_VAULT'),
      status: data.status || 'ACTIVE',
      keyState: data.keyState || (data.status === 'ACTIVE' ? 'ACTIVE' : data.status || 'ACTIVE'),
      currentVersion: data.currentVersion,
      publicKey: data.publicKey || null,
      keyFingerprint: data.keyFingerprint || null,
      operations: data.operations || ['encrypt', 'decrypt', 'wrap', 'unwrap'],
      capabilities: data.capabilities || null,
      metadata: data.metadata || null,
      lastSyncedAt: now,
      lastDiscoveredAt: now,
      createdAt: now,
      updatedAt: now,
    };

    if (await this.checkPrisma()) {
      try {
        const created = await prisma.customerRegisteredKey.create({
          data: {
            id: record.id,
            provider: { connect: { id: record.providerId } },
            organization: { connect: { id: record.organizationId } },
            project: { connect: { id: record.projectId } },
            environment: { connect: { id: record.environmentId } },
            keyIdentifier: record.keyIdentifier,
            displayName: record.displayName,
            keyVaultUrl: record.keyVaultUrl,
            keyType: record.keyType,
            algorithm: record.algorithm,
            purpose: record.purpose,
            ownershipType: record.ownershipType,
            isHsmBacked: record.isHsmBacked,
            hsmBackedStatus: record.hsmBackedStatus,
            status: record.status,
            keyState: record.keyState,
            currentVersion: record.currentVersion,
            publicKey: record.publicKey,
            keyFingerprint: record.keyFingerprint,
            operations: record.operations,
            capabilities: record.capabilities,
            metadata: record.metadata,
            lastSyncedAt: record.lastSyncedAt,
            lastDiscoveredAt: record.lastDiscoveredAt,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt,
          },
        });
        this.memStore.customerRegisteredKeys.set(id, created as CustomerRegisteredKeyRecord);
        return created as CustomerRegisteredKeyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.customerRegisteredKeys.set(id, record);
    return record;
  }

  async findCustomerRegisteredKeyById(id: string): Promise<CustomerRegisteredKeyRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const k = await prisma.customerRegisteredKey.findUnique({
          where: { id },
          include: { versions: true, provider: true },
        });
        if (k) return k as CustomerRegisteredKeyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.customerRegisteredKeys.get(id) || null;
  }

  async findCustomerRegisteredKeyByIdentifier(providerId: string, keyIdentifier: string): Promise<CustomerRegisteredKeyRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const k = await prisma.customerRegisteredKey.findUnique({
          where: {
            providerId_keyIdentifier: {
              providerId,
              keyIdentifier,
            },
          },
          include: { versions: true, provider: true },
        });
        if (k) return k as CustomerRegisteredKeyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return Array.from(this.memStore.customerRegisteredKeys.values()).find(
      (k) => k.providerId === providerId && k.keyIdentifier === keyIdentifier
    ) || null;
  }

  async listCustomerRegisteredKeys(filters: {
    providerId?: string;
    organizationId: string;
    projectId?: string;
    environmentId?: string;
  }): Promise<CustomerRegisteredKeyRecord[]> {
    const memList = Array.from(this.memStore.customerRegisteredKeys.values()).filter((k) => {
      if (k.organizationId !== filters.organizationId) return false;
      if (filters.providerId && k.providerId !== filters.providerId) return false;
      if (filters.projectId && k.projectId !== filters.projectId) return false;
      if (filters.environmentId && k.environmentId !== filters.environmentId) return false;
      return true;
    });

    if (await this.checkPrisma()) {
      try {
        const where: any = { organizationId: filters.organizationId };
        if (filters.providerId) where.providerId = filters.providerId;
        if (filters.projectId) where.projectId = filters.projectId;
        if (filters.environmentId) where.environmentId = filters.environmentId;
        const list = await prisma.customerRegisteredKey.findMany({
          where,
          include: { versions: true, provider: true },
          orderBy: { createdAt: 'desc' },
        });
        
        const map = new Map<string, CustomerRegisteredKeyRecord>();
        for (const item of (list || [])) {
          map.set(item.id, item as CustomerRegisteredKeyRecord);
        }
        for (const item of memList) {
          if (!map.has(item.id)) {
            map.set(item.id, item);
          }
        }
        return Array.from(map.values());
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return memList;
  }

  async updateCustomerRegisteredKey(
    id: string,
    data: Partial<CustomerRegisteredKeyRecord>
  ): Promise<CustomerRegisteredKeyRecord> {
    if (await this.checkPrisma()) {
      try {
        const { versions: _versions, ...fields } = data;
        const updated = await prisma.customerRegisteredKey.update({
          where: { id },
          data: { ...fields, updatedAt: new Date() },
        });
        return updated as CustomerRegisteredKeyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const current = this.memStore.customerRegisteredKeys.get(id);
    if (!current) throw new Error(`Registered key ${id} not found.`);
    const updated: CustomerRegisteredKeyRecord = {
      ...current,
      ...data,
      updatedAt: new Date(),
    };
    this.memStore.customerRegisteredKeys.set(id, updated);
    return updated;
  }

  async deleteCustomerRegisteredKey(id: string): Promise<void> {
    if (await this.checkPrisma()) {
      try {
        await prisma.customerRegisteredKey.delete({
          where: { id },
        });
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    this.memStore.customerRegisteredKeys.delete(id);
  }

  async createCustomerKeyVersion(data: {
    registeredKeyId: string;
    version: string;
    status?: string;
    publicKey?: string | null;
    keyFingerprint?: string | null;
    isCurrent?: boolean;
    expiresAt?: Date | null;
  }): Promise<CustomerKeyVersionRecord> {
    const id = `ckv_${crypto.randomUUID()}`;
    const record: CustomerKeyVersionRecord = {
      id,
      registeredKeyId: data.registeredKeyId,
      version: data.version,
      status: data.status || 'ACTIVE',
      publicKey: data.publicKey || null,
      keyFingerprint: data.keyFingerprint || null,
      isCurrent: !!data.isCurrent,
      createdAt: new Date(),
      expiresAt: data.expiresAt || null,
    };

    if (await this.checkPrisma()) {
      try {
        const created = await prisma.customerKeyVersion.create({
          data: record,
        });
        return created as CustomerKeyVersionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.customerKeyVersions.set(id, record);
    return record;
  }

  async listCustomerKeyVersions(registeredKeyId: string): Promise<CustomerKeyVersionRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const list = await prisma.customerKeyVersion.findMany({
          where: { registeredKeyId },
          orderBy: { createdAt: 'desc' },
        });
        return list as CustomerKeyVersionRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return Array.from(this.memStore.customerKeyVersions.values())
      .filter((v) => v.registeredKeyId === registeredKeyId);
  }

  // =========================================================================
  // PHASE 7: PKI & CERTIFICATE MANAGEMENT DATASTORE METHODS
  // =========================================================================

  async createCertificateAuthority(
    data: Omit<CertificateAuthorityRecord, 'id' | 'createdAt' | 'updatedAt'> & { id?: string }
  ): Promise<CertificateAuthorityRecord> {
    const id = data.id || `ca_${crypto.randomUUID()}`;
    const now = new Date();
    const record: CertificateAuthorityRecord = {
      ...data,
      id,
      description: data.description || null,
      parentAuthorityId: data.parentAuthorityId || null,
      pathLenConstraint: data.pathLenConstraint !== undefined ? data.pathLenConstraint : null,
      crlDistributionPoint: data.crlDistributionPoint || null,
      ocspUrl: data.ocspUrl || null,
      metadata: data.metadata || null,
      createdAt: now,
      updatedAt: now,
    };

    if (await this.checkPrisma()) {
      try {
        const created = await prisma.certificateAuthority.create({
          data: record,
        });
        return created as CertificateAuthorityRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.certificateAuthorities.set(id, record);
    return record;
  }

  async getCertificateAuthority(
    id: string,
    organizationId?: string
  ): Promise<CertificateAuthorityRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { id };
        if (organizationId) where.organizationId = organizationId;
        const ca = await prisma.certificateAuthority.findFirst({ where });
        if (ca) return ca as CertificateAuthorityRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const ca = this.memStore.certificateAuthorities.get(id);
    if (!ca) return null;
    if (organizationId && ca.organizationId !== organizationId) return null;
    return ca;
  }

  async listCertificateAuthorities(filter: {
    organizationId: string;
    projectId?: string;
    environmentId?: string;
    status?: string;
  }): Promise<CertificateAuthorityRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { organizationId: filter.organizationId };
        if (filter.projectId) where.projectId = filter.projectId;
        if (filter.environmentId) where.environmentId = filter.environmentId;
        if (filter.status) where.status = filter.status;
        const list = await prisma.certificateAuthority.findMany({
          where,
          orderBy: { createdAt: 'desc' },
        });
        return list as CertificateAuthorityRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return Array.from(this.memStore.certificateAuthorities.values()).filter((ca) => {
      if (ca.organizationId !== filter.organizationId) return false;
      if (filter.projectId && ca.projectId !== filter.projectId) return false;
      if (filter.environmentId && ca.environmentId !== filter.environmentId) return false;
      if (filter.status && ca.status !== filter.status) return false;
      return true;
    }).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async updateCertificateAuthority(
    id: string,
    data: Partial<CertificateAuthorityRecord>
  ): Promise<CertificateAuthorityRecord | null> {
    const existing = await this.getCertificateAuthority(id);
    if (!existing) return null;

    const updated: CertificateAuthorityRecord = {
      ...existing,
      ...data,
      updatedAt: new Date(),
    };

    if (await this.checkPrisma()) {
      try {
        const res = await prisma.certificateAuthority.update({
          where: { id },
          data: updated,
        });
        return res as CertificateAuthorityRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.certificateAuthorities.set(id, updated);
    return updated;
  }

  async createCertificate(
    data: Omit<CertificateRecord, 'id' | 'createdAt' | 'updatedAt'> & { id?: string }
  ): Promise<CertificateRecord> {
    const id = data.id || `cert_${crypto.randomUUID()}`;
    const now = new Date();
    const record: CertificateRecord = {
      ...data,
      id,
      name: data.name || null,
      authorityId: data.authorityId || null,
      chainPem: data.chainPem || null,
      chainReference: data.chainReference || null,
      san: data.san || null,
      keyUsage: data.keyUsage || null,
      extendedKeyUsage: data.extendedKeyUsage || null,
      renewalOfId: data.renewalOfId || null,
      replacedById: data.replacedById || null,
      metadata: data.metadata || null,
      revocation: null,
      createdAt: now,
      updatedAt: now,
    };

    if (await this.checkPrisma()) {
      try {
        const { revocation, ...prismaData } = record;
        const created = await prisma.certificate.create({
          data: prismaData,
        });
        return created as CertificateRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.certificates.set(id, record);
    return record;
  }

  async getCertificate(
    id: string,
    organizationId?: string
  ): Promise<CertificateRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { id };
        if (organizationId) where.organizationId = organizationId;
        const cert = await prisma.certificate.findFirst({
          where,
          include: { revocation: true },
        });
        if (cert) return cert as CertificateRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const cert = this.memStore.certificates.get(id);
    if (!cert) return null;
    if (organizationId && cert.organizationId !== organizationId) return null;
    const revocation = this.memStore.certificateRevocations.get(id) || null;
    return { ...cert, revocation };
  }

  async getCertificateBySerial(
    organizationId: string,
    serialNumber: string
  ): Promise<CertificateRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const cert = await prisma.certificate.findFirst({
          where: { organizationId, serialNumber },
          include: { revocation: true },
        });
        if (cert) return cert as CertificateRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    for (const cert of this.memStore.certificates.values()) {
      if (cert.organizationId === organizationId && cert.serialNumber.toLowerCase() === serialNumber.toLowerCase()) {
        const revocation = this.memStore.certificateRevocations.get(cert.id) || null;
        return { ...cert, revocation };
      }
    }
    return null;
  }

  async listCertificates(filter: {
    organizationId: string;
    projectId?: string;
    environmentId?: string;
    status?: string;
    authorityId?: string;
    certificateType?: string;
    keyAlgorithm?: string;
  }): Promise<CertificateRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { organizationId: filter.organizationId };
        if (filter.projectId) where.projectId = filter.projectId;
        if (filter.environmentId) where.environmentId = filter.environmentId;
        if (filter.status) where.status = filter.status;
        if (filter.authorityId) where.authorityId = filter.authorityId;
        if (filter.certificateType) where.certificateType = filter.certificateType;
        if (filter.keyAlgorithm) where.keyAlgorithm = filter.keyAlgorithm;
        const list = await prisma.certificate.findMany({
          where,
          include: { revocation: true },
          orderBy: { createdAt: 'desc' },
        });
        return list as CertificateRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return Array.from(this.memStore.certificates.values()).filter((c) => {
      if (c.organizationId !== filter.organizationId) return false;
      if (filter.projectId && c.projectId !== filter.projectId) return false;
      if (filter.environmentId && c.environmentId !== filter.environmentId) return false;
      if (filter.status && c.status !== filter.status) return false;
      if (filter.authorityId && c.authorityId !== filter.authorityId) return false;
      if (filter.certificateType && c.certificateType !== filter.certificateType) return false;
      if (filter.keyAlgorithm && c.keyAlgorithm !== filter.keyAlgorithm) return false;
      return true;
    }).map((c) => ({
      ...c,
      revocation: this.memStore.certificateRevocations.get(c.id) || null,
    })).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async updateCertificate(
    id: string,
    data: Partial<CertificateRecord>
  ): Promise<CertificateRecord | null> {
    const existing = await this.getCertificate(id);
    if (!existing) return null;

    const updated: CertificateRecord = {
      ...existing,
      ...data,
      updatedAt: new Date(),
    };

    if (await this.checkPrisma()) {
      try {
        const { revocation, ...prismaData } = updated;
        const res = await prisma.certificate.update({
          where: { id },
          data: prismaData,
          include: { revocation: true },
        });
        return res as CertificateRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.certificates.set(id, updated);
    return updated;
  }

  async createCertificateRequest(
    data: Omit<CertificateRequestRecord, 'id' | 'createdAt' | 'updatedAt'> & { id?: string }
  ): Promise<CertificateRequestRecord> {
    const id = data.id || `csr_${crypto.randomUUID()}`;
    const now = new Date();
    const record: CertificateRequestRecord = {
      ...data,
      id,
      keyReference: data.keyReference || null,
      publicKey: data.publicKey || null,
      san: data.san || null,
      keyUsage: data.keyUsage || null,
      extendedKeyUsage: data.extendedKeyUsage || null,
      certificateId: data.certificateId || null,
      metadata: data.metadata || null,
      createdAt: now,
      updatedAt: now,
    };

    if (await this.checkPrisma()) {
      try {
        const created = await prisma.certificateRequest.create({
          data: record,
        });
        return created as CertificateRequestRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.certificateRequests.set(id, record);
    return record;
  }

  async getCertificateRequest(
    id: string,
    organizationId?: string
  ): Promise<CertificateRequestRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { id };
        if (organizationId) where.organizationId = organizationId;
        const req = await prisma.certificateRequest.findFirst({ where });
        if (req) return req as CertificateRequestRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const req = this.memStore.certificateRequests.get(id);
    if (!req) return null;
    if (organizationId && req.organizationId !== organizationId) return null;
    return req;
  }

  async listCertificateRequests(filter: {
    organizationId: string;
    projectId?: string;
    environmentId?: string;
    status?: string;
  }): Promise<CertificateRequestRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { organizationId: filter.organizationId };
        if (filter.projectId) where.projectId = filter.projectId;
        if (filter.environmentId) where.environmentId = filter.environmentId;
        if (filter.status) where.status = filter.status;
        const list = await prisma.certificateRequest.findMany({
          where,
          orderBy: { createdAt: 'desc' },
        });
        return list as CertificateRequestRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return Array.from(this.memStore.certificateRequests.values()).filter((r) => {
      if (r.organizationId !== filter.organizationId) return false;
      if (filter.projectId && r.projectId !== filter.projectId) return false;
      if (filter.environmentId && r.environmentId !== filter.environmentId) return false;
      if (filter.status && r.status !== filter.status) return false;
      return true;
    }).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async updateCertificateRequest(
    id: string,
    data: Partial<CertificateRequestRecord>
  ): Promise<CertificateRequestRecord | null> {
    const existing = await this.getCertificateRequest(id);
    if (!existing) return null;

    const updated: CertificateRequestRecord = {
      ...existing,
      ...data,
      updatedAt: new Date(),
    };

    if (await this.checkPrisma()) {
      try {
        const res = await prisma.certificateRequest.update({
          where: { id },
          data: updated,
        });
        return res as CertificateRequestRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.certificateRequests.set(id, updated);
    return updated;
  }

  async createCertificateRevocation(
    data: Omit<CertificateRevocationRecord, 'id' | 'createdAt'> & { id?: string }
  ): Promise<CertificateRevocationRecord> {
    const id = data.id || `rev_${crypto.randomUUID()}`;
    const now = new Date();
    const record: CertificateRevocationRecord = {
      ...data,
      id,
      revokedBy: data.revokedBy || null,
      invalidityDate: data.invalidityDate || null,
      comment: data.comment || null,
      createdAt: now,
    };

    if (await this.checkPrisma()) {
      try {
        const created = await prisma.certificateRevocation.create({
          data: record,
        });
        return created as CertificateRevocationRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.certificateRevocations.set(data.certificateId, record);
    return record;
  }

  async getCertificateRevocation(
    certificateId: string
  ): Promise<CertificateRevocationRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const rev = await prisma.certificateRevocation.findUnique({
          where: { certificateId },
        });
        if (rev) return rev as CertificateRevocationRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return this.memStore.certificateRevocations.get(certificateId) || null;
  }

  async listCertificateRevocations(
    organizationId: string
  ): Promise<CertificateRevocationRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const list = await prisma.certificateRevocation.findMany({
          where: { organizationId },
          orderBy: { revokedAt: 'desc' },
        });
        return list as CertificateRevocationRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return Array.from(this.memStore.certificateRevocations.values()).filter(
      (r) => r.organizationId === organizationId
    ).sort((a, b) => b.revokedAt.getTime() - a.revokedAt.getTime());
  }

  // ==========================================
  // PHASE 8: CRYPTO INTELLIGENCE & CBOM
  // ==========================================

  // --- CRYPTO ASSETS ---
  async upsertCryptoAsset(data: CryptoAssetRecord): Promise<CryptoAssetRecord> {
    if (await this.checkPrisma()) {
      try {
        const upserted = await prisma.cryptoAsset.upsert({
          where: {
            organizationId_assetType_name_source: {
              organizationId: data.organizationId,
              assetType: data.assetType,
              name: data.name,
              source: data.source,
            },
          },
          create: data,
          update: {
            algorithm: data.algorithm,
            provider: data.provider,
            status: data.status,
            quantumStatus: data.quantumStatus,
            fingerprint: data.fingerprint,
            lastSeenAt: data.lastSeenAt,
            metadata: data.metadata,
            updatedAt: new Date(),
          },
        });
        return upserted as CryptoAssetRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const existing = Array.from(this.memStore.cryptoAssets.values()).find(
      (a) =>
        a.organizationId === data.organizationId &&
        a.assetType === data.assetType &&
        a.name === data.name &&
        a.source === data.source
    );

    if (existing) {
      const updated: CryptoAssetRecord = {
        ...existing,
        ...data,
        id: existing.id,
        firstSeenAt: existing.firstSeenAt,
        updatedAt: new Date(),
      };
      this.memStore.cryptoAssets.set(existing.id, updated);
      return updated;
    }

    this.memStore.cryptoAssets.set(data.id, data);
    return data;
  }

  async listCryptoAssets(
    organizationId: string,
    filters?: { assetType?: string; status?: string; algorithm?: string; quantumStatus?: string }
  ): Promise<CryptoAssetRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { organizationId };
        if (filters?.assetType) where.assetType = filters.assetType;
        if (filters?.status) where.status = filters.status;
        if (filters?.algorithm) where.algorithm = filters.algorithm;
        if (filters?.quantumStatus) where.quantumStatus = filters.quantumStatus;

        const list = await prisma.cryptoAsset.findMany({
          where,
          orderBy: { createdAt: 'desc' },
        });
        return list as CryptoAssetRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    let items = Array.from(this.memStore.cryptoAssets.values()).filter(
      (a) => a.organizationId === organizationId
    );
    if (filters?.assetType) items = items.filter((a) => a.assetType === filters.assetType);
    if (filters?.status) items = items.filter((a) => a.status === filters.status);
    if (filters?.algorithm) items = items.filter((a) => a.algorithm?.toLowerCase() === filters.algorithm?.toLowerCase());
    if (filters?.quantumStatus) items = items.filter((a) => a.quantumStatus === filters.quantumStatus);

    return items.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getCryptoAsset(organizationId: string, id: string): Promise<CryptoAssetRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const item = await prisma.cryptoAsset.findFirst({
          where: { id, organizationId },
        });
        if (item) return item as CryptoAssetRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const item = this.memStore.cryptoAssets.get(id);
    if (item && item.organizationId === organizationId) return item;
    return null;
  }

  async deleteCryptoAsset(organizationId: string, id: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.cryptoAsset.deleteMany({
          where: { id, organizationId },
        });
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const item = this.memStore.cryptoAssets.get(id);
    if (item && item.organizationId === organizationId) {
      this.memStore.cryptoAssets.delete(id);
      return true;
    }
    return false;
  }

  // --- CRYPTO RELATIONSHIPS ---
  async createCryptoRelationship(data: CryptoRelationshipRecord): Promise<CryptoRelationshipRecord> {
    if (await this.checkPrisma()) {
      try {
        const created = await prisma.cryptoRelationship.upsert({
          where: {
            organizationId_sourceAssetId_targetAssetId_relationshipType: {
              organizationId: data.organizationId,
              sourceAssetId: data.sourceAssetId,
              targetAssetId: data.targetAssetId,
              relationshipType: data.relationshipType,
            },
          },
          create: data,
          update: {
            confidence: data.confidence,
            metadata: data.metadata,
          },
        });
        return created as CryptoRelationshipRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.cryptoRelationships.set(data.id, data);
    return data;
  }

  async listCryptoRelationships(organizationId: string): Promise<CryptoRelationshipRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const list = await prisma.cryptoRelationship.findMany({
          where: { organizationId },
        });
        return list as CryptoRelationshipRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return Array.from(this.memStore.cryptoRelationships.values()).filter(
      (r) => r.organizationId === organizationId
    );
  }

  async deleteCryptoRelationshipsForOrg(organizationId: string): Promise<void> {
    if (await this.checkPrisma()) {
      try {
        await prisma.cryptoRelationship.deleteMany({
          where: { organizationId },
        });
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    for (const [id, r] of this.memStore.cryptoRelationships.entries()) {
      if (r.organizationId === organizationId) {
        this.memStore.cryptoRelationships.delete(id);
      }
    }
  }

  // --- CRYPTO FINDINGS ---
  async upsertCryptoFinding(data: CryptoFindingRecord): Promise<CryptoFindingRecord> {
    if (await this.checkPrisma()) {
      try {
        const existing = await prisma.cryptoFinding.findUnique({
          where: { id: data.id },
        });

        if (existing) {
          const updated = await prisma.cryptoFinding.update({
            where: { id: data.id },
            data: {
              lastDetectedAt: data.lastDetectedAt,
              severity: data.severity,
              description: data.description,
              evidence: data.evidence,
              updatedAt: new Date(),
            },
          });
          return updated as CryptoFindingRecord;
        } else {
          const created = await prisma.cryptoFinding.create({
            data,
          });
          return created as CryptoFindingRecord;
        }
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const existing = this.memStore.cryptoFindings.get(data.id);
    if (existing) {
      const updated: CryptoFindingRecord = {
        ...existing,
        lastDetectedAt: data.lastDetectedAt,
        severity: data.severity,
        description: data.description,
        evidence: data.evidence,
        updatedAt: new Date(),
      };
      this.memStore.cryptoFindings.set(data.id, updated);
      return updated;
    }

    this.memStore.cryptoFindings.set(data.id, data);
    return data;
  }

  async listCryptoFindings(
    organizationId: string,
    filters?: { severity?: string; status?: string; category?: string }
  ): Promise<CryptoFindingRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { organizationId };
        if (filters?.severity) where.severity = filters.severity;
        if (filters?.status) where.status = filters.status;
        if (filters?.category) where.category = filters.category;

        const list = await prisma.cryptoFinding.findMany({
          where,
          orderBy: { createdAt: 'desc' },
        });
        return list as CryptoFindingRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    let items = Array.from(this.memStore.cryptoFindings.values()).filter(
      (f) => f.organizationId === organizationId
    );
    if (filters?.severity) items = items.filter((f) => f.severity === filters.severity);
    if (filters?.status) items = items.filter((f) => f.status === filters.status);
    if (filters?.category) items = items.filter((f) => f.category === filters.category);

    return items.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getCryptoFinding(organizationId: string, id: string): Promise<CryptoFindingRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const item = await prisma.cryptoFinding.findFirst({
          where: { id, organizationId },
        });
        if (item) return item as CryptoFindingRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const item = this.memStore.cryptoFindings.get(id);
    if (item && item.organizationId === organizationId) return item;
    return null;
  }

  async updateCryptoFinding(
    organizationId: string,
    id: string,
    data: Partial<CryptoFindingRecord>
  ): Promise<CryptoFindingRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const item = await prisma.cryptoFinding.findFirst({
          where: { id, organizationId },
        });
        if (!item) return null;

        const updated = await prisma.cryptoFinding.update({
          where: { id },
          data: {
            ...data,
            updatedAt: new Date(),
          },
        });
        return updated as CryptoFindingRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const item = this.memStore.cryptoFindings.get(id);
    if (!item || item.organizationId !== organizationId) return null;

    const updated: CryptoFindingRecord = {
      ...item,
      ...data,
      updatedAt: new Date(),
    };
    this.memStore.cryptoFindings.set(id, updated);
    return updated;
  }

  // --- CRYPTO SNAPSHOTS ---
  async createCryptoSnapshot(data: CryptoSnapshotRecord): Promise<CryptoSnapshotRecord> {
    if (await this.checkPrisma()) {
      try {
        const created = await prisma.cryptoInventorySnapshot.create({
          data,
        });
        return created as CryptoSnapshotRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.cryptoSnapshots.set(data.id, data);
    return data;
  }

  async listCryptoSnapshots(organizationId: string): Promise<CryptoSnapshotRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const list = await prisma.cryptoInventorySnapshot.findMany({
          where: { organizationId },
          orderBy: { snapshotDate: 'desc' },
        });
        return list as CryptoSnapshotRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return Array.from(this.memStore.cryptoSnapshots.values())
      .filter((s) => s.organizationId === organizationId)
      .sort((a, b) => b.snapshotDate.getTime() - a.snapshotDate.getTime());
  }

  async getLatestCryptoSnapshot(organizationId: string): Promise<CryptoSnapshotRecord | null> {
    const list = await this.listCryptoSnapshots(organizationId);
    return list.length > 0 ? list[0] : null;
  }

  // --- CRYPTO MIGRATION PLANS ---
  async createCryptoMigrationPlan(data: CryptoMigrationPlanRecord): Promise<CryptoMigrationPlanRecord> {
    if (await this.checkPrisma()) {
      try {
        const created = await prisma.cryptoMigrationPlan.create({
          data,
        });
        return created as CryptoMigrationPlanRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.cryptoMigrationPlans.set(data.id, data);
    return data;
  }

  async listCryptoMigrationPlans(organizationId: string): Promise<CryptoMigrationPlanRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const list = await prisma.cryptoMigrationPlan.findMany({
          where: { organizationId },
          orderBy: { createdAt: 'desc' },
        });
        return list as CryptoMigrationPlanRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return Array.from(this.memStore.cryptoMigrationPlans.values())
      .filter((p) => p.organizationId === organizationId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getCryptoMigrationPlan(organizationId: string, id: string): Promise<CryptoMigrationPlanRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const item = await prisma.cryptoMigrationPlan.findFirst({
          where: { id, organizationId },
        });
        if (item) return item as CryptoMigrationPlanRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const item = this.memStore.cryptoMigrationPlans.get(id);
    if (item && item.organizationId === organizationId) return item;
    return null;
  }

  async updateCryptoMigrationPlan(
    organizationId: string,
    id: string,
    data: Partial<CryptoMigrationPlanRecord>
  ): Promise<CryptoMigrationPlanRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const item = await prisma.cryptoMigrationPlan.findFirst({
          where: { id, organizationId },
        });
        if (!item) return null;

        const updated = await prisma.cryptoMigrationPlan.update({
          where: { id },
          data: {
            ...data,
            updatedAt: new Date(),
          },
        });
        return updated as CryptoMigrationPlanRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const item = this.memStore.cryptoMigrationPlans.get(id);
    if (!item || item.organizationId !== organizationId) return null;

    const updated: CryptoMigrationPlanRecord = {
      ...item,
      ...data,
      updatedAt: new Date(),
    };
    this.memStore.cryptoMigrationPlans.set(id, updated);
    return updated;
  }

  // ==========================================
  // Phase 9: Advanced Cryptography Store Methods
  // ==========================================

  // --- ZK CIRCUITS ---
  async createZkCircuit(data: ZkCircuitRecord): Promise<ZkCircuitRecord> {
    if (await this.checkPrisma()) {
      try {
        const created = await prisma.zkCircuit.create({ data });
        return created as ZkCircuitRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    this.memStore.zkCircuits.set(data.id, data);
    return data;
  }

  async getZkCircuit(organizationId: string, id: string): Promise<ZkCircuitRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const found = await prisma.zkCircuit.findFirst({
          where: { id, organizationId },
        });
        if (found) return found as ZkCircuitRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const item = this.memStore.zkCircuits.get(id);
    if (item && (item.organizationId === organizationId || item.organizationId === 'org-default')) {
      return item;
    }
    return null;
  }

  async listZkCircuits(organizationId: string): Promise<ZkCircuitRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const list = await prisma.zkCircuit.findMany({
          where: {
            OR: [{ organizationId }, { organizationId: 'org-default' }],
          },
          orderBy: { createdAt: 'desc' },
        });
        return list as ZkCircuitRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return Array.from(this.memStore.zkCircuits.values())
      .filter((c) => c.organizationId === organizationId || c.organizationId === 'org-default')
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  // --- ZK PROOFS ---
  async createZkProofRecord(data: ZkProofRecordDb): Promise<ZkProofRecordDb> {
    if (await this.checkPrisma()) {
      try {
        const created = await prisma.zkProofRecord.create({ data });
        return created as ZkProofRecordDb;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    this.memStore.zkProofRecords.set(data.id, data);
    return data;
  }

  async listZkProofRecords(organizationId: string): Promise<ZkProofRecordDb[]> {
    if (await this.checkPrisma()) {
      try {
        const list = await prisma.zkProofRecord.findMany({
          where: { organizationId },
          orderBy: { createdAt: 'desc' },
        });
        return list as ZkProofRecordDb[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return Array.from(this.memStore.zkProofRecords.values())
      .filter((p) => p.organizationId === organizationId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  // --- FHE KEYS ---
  async createFheKey(data: FheKeyRecord): Promise<FheKeyRecord> {
    if (await this.checkPrisma()) {
      try {
        const created = await prisma.fheKey.create({ data });
        return created as FheKeyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    this.memStore.fheKeys.set(data.id, data);
    return data;
  }

  async getFheKey(organizationId: string, id: string): Promise<FheKeyRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const found = await prisma.fheKey.findFirst({
          where: { id, organizationId },
        });
        if (found) return found as FheKeyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const item = this.memStore.fheKeys.get(id);
    if (item && item.organizationId === organizationId) return item;
    return null;
  }

  async listFheKeys(organizationId: string): Promise<FheKeyRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const list = await prisma.fheKey.findMany({
          where: { organizationId },
          orderBy: { createdAt: 'desc' },
        });
        return list as FheKeyRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return Array.from(this.memStore.fheKeys.values())
      .filter((k) => k.organizationId === organizationId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  // --- MPC SESSIONS ---
  async createMpcSession(data: MpcSessionRecord): Promise<MpcSessionRecord> {
    if (await this.checkPrisma()) {
      try {
        const created = await prisma.mpcSession.create({ data });
        return created as MpcSessionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    this.memStore.mpcSessions.set(data.id, data);
    return data;
  }

  async getMpcSession(organizationId: string, id: string): Promise<MpcSessionRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const found = await prisma.mpcSession.findFirst({
          where: { id, organizationId },
        });
        if (found) return found as MpcSessionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const item = this.memStore.mpcSessions.get(id);
    if (item && item.organizationId === organizationId) return item;
    return null;
  }

  async listMpcSessions(organizationId: string): Promise<MpcSessionRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const list = await prisma.mpcSession.findMany({
          where: { organizationId },
          orderBy: { createdAt: 'desc' },
        });
        return list as MpcSessionRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return Array.from(this.memStore.mpcSessions.values())
      .filter((s) => s.organizationId === organizationId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async updateMpcSession(organizationId: string, id: string, data: Partial<MpcSessionRecord>): Promise<MpcSessionRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const updated = await prisma.mpcSession.update({
          where: { id },
          data: { ...data, updatedAt: new Date() },
        });
        return updated as MpcSessionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const item = this.memStore.mpcSessions.get(id);
    if (!item || item.organizationId !== organizationId) return null;
    const updated: MpcSessionRecord = {
      ...item,
      ...data,
      updatedAt: new Date(),
    };
    this.memStore.mpcSessions.set(id, updated);
    return updated;
  }

  // --- THRESHOLD KEYS & SESSIONS ---
  async createThresholdKey(data: ThresholdKeyRecord): Promise<ThresholdKeyRecord> {
    if (await this.checkPrisma()) {
      try {
        const created = await prisma.thresholdKey.create({ data });
        return created as ThresholdKeyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    this.memStore.thresholdKeys.set(data.id, data);
    return data;
  }

  async getThresholdKey(organizationId: string, id: string): Promise<ThresholdKeyRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const found = await prisma.thresholdKey.findFirst({
          where: { id, organizationId },
        });
        if (found) return found as ThresholdKeyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const item = this.memStore.thresholdKeys.get(id);
    if (item && item.organizationId === organizationId) return item;
    return null;
  }

  async listThresholdKeys(organizationId: string): Promise<ThresholdKeyRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const list = await prisma.thresholdKey.findMany({
          where: { organizationId },
          orderBy: { createdAt: 'desc' },
        });
        return list as ThresholdKeyRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return Array.from(this.memStore.thresholdKeys.values())
      .filter((k) => k.organizationId === organizationId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async createThresholdSession(data: ThresholdSessionRecord): Promise<ThresholdSessionRecord> {
    if (await this.checkPrisma()) {
      try {
        const created = await prisma.thresholdSession.create({ data });
        return created as ThresholdSessionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    this.memStore.thresholdSessions.set(data.id, data);
    return data;
  }

  async getThresholdSession(organizationId: string, id: string): Promise<ThresholdSessionRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const found = await prisma.thresholdSession.findFirst({
          where: { id, organizationId },
        });
        if (found) return found as ThresholdSessionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const item = this.memStore.thresholdSessions.get(id);
    if (item && item.organizationId === organizationId) return item;
    return null;
  }

  async updateThresholdSession(
    organizationId: string,
    id: string,
    data: Partial<ThresholdSessionRecord>
  ): Promise<ThresholdSessionRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const updated = await prisma.thresholdSession.update({
          where: { id },
          data: { ...data, updatedAt: new Date() },
        });
        return updated as ThresholdSessionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const item = this.memStore.thresholdSessions.get(id);
    if (!item || item.organizationId !== organizationId) return null;
    const updated: ThresholdSessionRecord = {
      ...item,
      ...data,
      updatedAt: new Date(),
    };
    this.memStore.thresholdSessions.set(id, updated);
    return updated;
  }

  // --- PHASE 11: BILLING, SUBSCRIPTIONS, USAGE & SAFETY ---

  async getBillingCustomer(organizationId: string): Promise<BillingCustomerRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const found = await prisma.billingCustomer.findUnique({
          where: { organizationId },
        });
        if (found) return found as BillingCustomerRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.billingCustomers.get(organizationId) || null;
  }

  async getBillingCustomerByPolarId(polarCustomerId: string): Promise<BillingCustomerRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const found = await prisma.billingCustomer.findUnique({
          where: { polarCustomerId },
        });
        if (found) return found as BillingCustomerRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    for (const c of this.memStore.billingCustomers.values()) {
      if (c.polarCustomerId === polarCustomerId) return c;
    }
    return null;
  }

  async upsertBillingCustomer(data: Partial<BillingCustomerRecord> & { organizationId: string }): Promise<BillingCustomerRecord> {
    if (await this.checkPrisma()) {
      try {
        const upserted = await prisma.billingCustomer.upsert({
          where: { organizationId: data.organizationId },
          create: {
            id: data.id || `cus_${crypto.randomUUID().slice(0, 12)}`,
            organizationId: data.organizationId,
            polarCustomerId: data.polarCustomerId || null,
            email: data.email || null,
            name: data.name || null,
          },
          update: {
            polarCustomerId: data.polarCustomerId !== undefined ? data.polarCustomerId : undefined,
            email: data.email !== undefined ? data.email : undefined,
            name: data.name !== undefined ? data.name : undefined,
            updatedAt: new Date(),
          },
        });
        return upserted as BillingCustomerRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const existing = this.memStore.billingCustomers.get(data.organizationId);
    const now = new Date();
    const updated: BillingCustomerRecord = {
      id: existing?.id || data.id || `cus_${crypto.randomUUID().slice(0, 12)}`,
      organizationId: data.organizationId,
      polarCustomerId: data.polarCustomerId !== undefined ? data.polarCustomerId : existing?.polarCustomerId,
      email: data.email !== undefined ? data.email : existing?.email,
      name: data.name !== undefined ? data.name : existing?.name,
      createdAt: existing?.createdAt || now,
      updatedAt: now,
    };
    this.memStore.billingCustomers.set(data.organizationId, updated);
    return updated;
  }

  async getBillingSubscription(organizationId: string): Promise<BillingSubscriptionRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const found = await prisma.billingSubscription.findFirst({
          where: { organizationId },
          orderBy: { createdAt: 'desc' },
        });
        if (found) return found as BillingSubscriptionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const orgSubs = Array.from(this.memStore.billingSubscriptions.values())
      .filter((s) => s.organizationId === organizationId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    return orgSubs[0] || null;
  }

  async getBillingSubscriptionByPolarId(polarSubscriptionId: string): Promise<BillingSubscriptionRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const found = await prisma.billingSubscription.findUnique({
          where: { polarSubscriptionId },
        });
        if (found) return found as BillingSubscriptionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    for (const sub of this.memStore.billingSubscriptions.values()) {
      if (sub.polarSubscriptionId === polarSubscriptionId) return sub;
    }
    return null;
  }

  async upsertBillingSubscription(data: Partial<BillingSubscriptionRecord> & { organizationId: string }): Promise<BillingSubscriptionRecord> {
    const existing = await this.getBillingSubscription(data.organizationId);
    const id = data.id || existing?.id || `sub_${crypto.randomUUID().slice(0, 12)}`;
    const now = new Date();

    if (await this.checkPrisma()) {
      try {
        const upserted = await prisma.billingSubscription.upsert({
          where: { id },
          create: {
            id,
            organizationId: data.organizationId,
            polarSubscriptionId: data.polarSubscriptionId || null,
            plan: data.plan || 'FREE',
            status: data.status || 'ACTIVE',
            currentPeriodStart: data.currentPeriodStart || now,
            currentPeriodEnd: data.currentPeriodEnd || null,
            cancelAtPeriodEnd: data.cancelAtPeriodEnd ?? false,
            canceledAt: data.canceledAt || null,
            metadata: data.metadata || null,
          },
          update: {
            polarSubscriptionId: data.polarSubscriptionId !== undefined ? data.polarSubscriptionId : undefined,
            plan: data.plan !== undefined ? data.plan : undefined,
            status: data.status !== undefined ? data.status : undefined,
            currentPeriodStart: data.currentPeriodStart !== undefined ? data.currentPeriodStart : undefined,
            currentPeriodEnd: data.currentPeriodEnd !== undefined ? data.currentPeriodEnd : undefined,
            cancelAtPeriodEnd: data.cancelAtPeriodEnd !== undefined ? data.cancelAtPeriodEnd : undefined,
            canceledAt: data.canceledAt !== undefined ? data.canceledAt : undefined,
            metadata: data.metadata !== undefined ? data.metadata : undefined,
            updatedAt: now,
          },
        });
        return upserted as BillingSubscriptionRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const updated: BillingSubscriptionRecord = {
      id,
      organizationId: data.organizationId,
      polarSubscriptionId: data.polarSubscriptionId !== undefined ? data.polarSubscriptionId : existing?.polarSubscriptionId,
      plan: data.plan !== undefined ? data.plan : existing?.plan || 'FREE',
      status: data.status !== undefined ? data.status : existing?.status || 'ACTIVE',
      currentPeriodStart: data.currentPeriodStart || existing?.currentPeriodStart || now,
      currentPeriodEnd: data.currentPeriodEnd !== undefined ? data.currentPeriodEnd : existing?.currentPeriodEnd,
      cancelAtPeriodEnd: data.cancelAtPeriodEnd !== undefined ? data.cancelAtPeriodEnd : existing?.cancelAtPeriodEnd || false,
      canceledAt: data.canceledAt !== undefined ? data.canceledAt : existing?.canceledAt,
      metadata: data.metadata !== undefined ? data.metadata : existing?.metadata,
      createdAt: existing?.createdAt || now,
      updatedAt: now,
    };
    this.memStore.billingSubscriptions.set(id, updated);
    return updated;
  }

  async getActiveBillingPeriod(organizationId: string): Promise<{ periodStart: Date; periodEnd: Date }> {
    const sub = await this.getBillingSubscription(organizationId);
    if (sub && sub.currentPeriodStart && sub.currentPeriodEnd) {
      return monthlySliceOfPeriod(new Date(sub.currentPeriodStart), new Date(sub.currentPeriodEnd), new Date());
    }
    const now = new Date();
    return {
      periodStart: new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)),
      periodEnd: new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1)),
    };
  }

  async getCurrentBillingUsage(organizationId: string): Promise<BillingUsageRecord> {
    const now = new Date();
    const { periodStart, periodEnd } = await this.getActiveBillingPeriod(organizationId);

    if (await this.checkPrisma()) {
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          const usage = await prisma.billingUsage.upsert({
            where: {
              organizationId_periodStart_periodEnd: {
                organizationId,
                periodStart,
                periodEnd,
              },
            },
            create: {
              organizationId,
              periodStart,
              periodEnd,
              operationCount: 0,
              includedAllowance: 0,
              overageCount: 0,
              estimatedCostCents: 0,
            },
            update: {},
          });
          return usage as BillingUsageRecord;
        } catch (err) {
          try {
            const found = await prisma.billingUsage.findUnique({
              where: {
                organizationId_periodStart_periodEnd: {
                  organizationId,
                  periodStart,
                  periodEnd,
                },
              },
            });
            if (found) return found as BillingUsageRecord;
          } catch {}
          if (attempt === 4) {
            this.rethrowUnlessNotFound(err);
            throw err;
          }
          await new Promise((r) => setTimeout(r, 20 * (attempt + 1)));
        }
      }
    }

    const key = `${organizationId}_${periodStart.toISOString()}_${periodEnd.toISOString()}`;
    let record = this.memStore.billingUsages.get(key);
    if (!record) {
      record = {
        id: `usg_${crypto.randomUUID().slice(0, 12)}`,
        organizationId,
        periodStart,
        periodEnd,
        operationCount: 0,
        includedAllowance: 0,
        overageCount: 0,
        estimatedCostCents: 0,
        createdAt: now,
        updatedAt: now,
      };
      this.memStore.billingUsages.set(key, record);
    }
    return { ...record };
  }

  /** The usage record of one exact billing period, or null if nothing was recorded in it. */
  async getBillingUsageForPeriod(organizationId: string, periodStart: Date, periodEnd: Date): Promise<BillingUsageRecord | null> {
    if (await this.checkPrisma()) {
      const found = await prisma.billingUsage.findUnique({
        where: { organizationId_periodStart_periodEnd: { organizationId, periodStart, periodEnd } },
      });
      return (found as BillingUsageRecord) || null;
    }
    const record = this.memStore.billingUsages.get(`${organizationId}_${periodStart.toISOString()}_${periodEnd.toISOString()}`);
    return record ? { ...record } : null;
  }

  async incrementBillingUsage(
    organizationId: string,
    quantity: number = 1,
    includedAllowance: number = 0,
    costPer1kCents: number = 15 // 15 cents per 1k ops for PAYG or overage
  ): Promise<BillingUsageRecord> {
    const now = new Date();
    const { periodStart, periodEnd } = await this.getActiveBillingPeriod(organizationId);

    if (await this.checkPrisma()) {
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          const updated = await prisma.billingUsage.upsert({
            where: {
              organizationId_periodStart_periodEnd: {
                organizationId,
                periodStart,
                periodEnd,
              },
            },
            create: {
              organizationId,
              periodStart,
              periodEnd,
              operationCount: quantity,
              includedAllowance,
              overageCount: Math.max(0, quantity - includedAllowance),
              estimatedCostCents: Math.round((Math.max(0, quantity - includedAllowance) / 1000) * costPer1kCents),
            },
            update: {
              operationCount: { increment: quantity },
              includedAllowance: includedAllowance > 0 ? { set: includedAllowance } : undefined,
              updatedAt: now,
            },
          });

          const overage = Math.max(0, updated.operationCount - updated.includedAllowance);
          const estimatedCostCents = Math.round((overage / 1000) * costPer1kCents);
          if (updated.overageCount !== overage || updated.estimatedCostCents !== estimatedCostCents) {
            await prisma.billingUsage.update({
              where: { id: updated.id },
              data: { overageCount: overage, estimatedCostCents },
            });
            updated.overageCount = overage;
            updated.estimatedCostCents = estimatedCostCents;
          }
          return updated as BillingUsageRecord;
        } catch (err) {
          if (attempt === 4) {
            this.rethrowUnlessNotFound(err);
            throw err;
          }
          await new Promise((r) => setTimeout(r, 20 * (attempt + 1)));
        }
      }
    }

    const key = `${organizationId}_${periodStart.toISOString()}_${periodEnd.toISOString()}`;
    let item = this.memStore.billingUsages.get(key);
    if (!item) {
      item = {
        id: `usg_${crypto.randomUUID().slice(0, 12)}`,
        organizationId,
        periodStart,
        periodEnd,
        operationCount: 0,
        includedAllowance: 0,
        overageCount: 0,
        estimatedCostCents: 0,
        createdAt: now,
        updatedAt: now,
      };
      this.memStore.billingUsages.set(key, item);
    }
    item.operationCount += quantity;
    item.includedAllowance = Math.max(item.includedAllowance, includedAllowance);
    item.overageCount = Math.max(0, item.operationCount - item.includedAllowance);
    item.estimatedCostCents = Math.round((item.overageCount / 1000) * costPer1kCents);
    item.updatedAt = now;
    return { ...item };
  }

  async createBillingUsageEvent(data: BillingUsageEventRecord): Promise<{ created: boolean; event: BillingUsageEventRecord }> {
    if (await this.checkPrisma()) {
      try {
        const existing = await prisma.billingUsageEvent.findUnique({
          where: { operationId: data.operationId },
        });
        if (existing) {
          return { created: false, event: existing as BillingUsageEventRecord };
        }
        const created = await prisma.billingUsageEvent.create({
          data: {
            id: data.id || `bue_${crypto.randomUUID().slice(0, 12)}`,
            organizationId: data.organizationId,
            operationId: data.operationId,
            operationType: data.operationType,
            quantity: data.quantity || 1,
            keyId: data.keyId || null,
            projectId: data.projectId || null,
            timestamp: data.timestamp || new Date(),
            reportedToPolar: data.reportedToPolar ?? false,
            polarEventId: data.polarEventId || null,
          },
        });
        return { created: true, event: created as BillingUsageEventRecord };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    if (this.memStore.billingUsageEvents.has(data.operationId)) {
      return { created: false, event: this.memStore.billingUsageEvents.get(data.operationId)! };
    }

    const event: BillingUsageEventRecord = {
      id: data.id || `bue_${crypto.randomUUID().slice(0, 12)}`,
      organizationId: data.organizationId,
      operationId: data.operationId,
      operationType: data.operationType,
      quantity: data.quantity || 1,
      keyId: data.keyId || null,
      projectId: data.projectId || null,
      timestamp: data.timestamp || new Date(),
      reportedToPolar: data.reportedToPolar ?? false,
      polarEventId: data.polarEventId || null,
    };
    this.memStore.billingUsageEvents.set(data.operationId, event);
    return { created: true, event };
  }

  async markBillingUsageEventReported(operationId: string, polarEventId?: string): Promise<void> {
    if (await this.checkPrisma()) {
      try {
        await prisma.billingUsageEvent.update({
          where: { operationId },
          data: {
            reportedToPolar: true,
            polarEventId: polarEventId || null,
          },
        });
        return;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const event = this.memStore.billingUsageEvents.get(operationId);
    if (event) {
      event.reportedToPolar = true;
      event.polarEventId = polarEventId || null;
    }
  }

  async getPendingBillingUsageEvents(organizationId?: string, limit: number = 100): Promise<BillingUsageEventRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const events = await prisma.billingUsageEvent.findMany({
          where: {
            reportedToPolar: false,
            ...(organizationId ? { organizationId } : {}),
          },
          take: limit,
          orderBy: { timestamp: 'asc' },
        });
        return events as BillingUsageEventRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const list: BillingUsageEventRecord[] = [];
    for (const ev of this.memStore.billingUsageEvents.values()) {
      if (!ev.reportedToPolar) {
        if (!organizationId || ev.organizationId === organizationId) {
          list.push(ev);
          if (list.length >= limit) break;
        }
      }
    }
    return list;
  }

  async getBillingSafetyState(organizationId: string): Promise<BillingSafetyStateRecord> {
    const now = new Date();
    if (await this.checkPrisma()) {
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          const state = await prisma.billingSafetyState.upsert({
            where: { organizationId },
            create: {
              organizationId,
              circuitBreakerStatus: 'NORMAL',
              opsPerMinute: 0,
              opsPerHour: 0,
              opsPerDay: 0,
              lastWindowReset: now,
              paygSpendingLimitCents: 25000,
              alertThresholdPercent: 80,
              autoHaltEnabled: true,
              overagePolicy: 'HARD_STOP',
              authorizedOverageSpendingLimitCents: 0,
            },
            update: {},
          });
          const res = state as BillingSafetyStateRecord;
          if (!res.overagePolicy) res.overagePolicy = 'HARD_STOP';
          if (res.authorizedOverageSpendingLimitCents === undefined) res.authorizedOverageSpendingLimitCents = 0;
          return res;
        } catch (err) {
          try {
            const found = await prisma.billingSafetyState.findUnique({ where: { organizationId } });
            if (found) {
              const res = found as BillingSafetyStateRecord;
              if (!res.overagePolicy) res.overagePolicy = 'HARD_STOP';
              if (res.authorizedOverageSpendingLimitCents === undefined) res.authorizedOverageSpendingLimitCents = 0;
              return res;
            }
          } catch {}
          if (attempt === 4) {
            this.rethrowUnlessNotFound(err);
            throw err;
          }
          await new Promise((r) => setTimeout(r, 20 * (attempt + 1)));
        }
      }
    }

    let state = this.memStore.billingSafetyStates.get(organizationId);
    if (!state) {
      state = {
        id: `bss_${crypto.randomUUID().slice(0, 12)}`,
        organizationId,
        circuitBreakerStatus: 'NORMAL',
        opsPerMinute: 0,
        opsPerHour: 0,
        opsPerDay: 0,
        lastWindowReset: now,
        paygSpendingLimitCents: 25000, // $250.00 default hard cap
        alertThresholdPercent: 80,
        autoHaltEnabled: true,
        overagePolicy: 'HARD_STOP',
        authorizedOverageSpendingLimitCents: 0,
        createdAt: now,
        updatedAt: now,
      };
      this.memStore.billingSafetyStates.set(organizationId, state);
    }
    if (!state.overagePolicy) state.overagePolicy = 'HARD_STOP';
    if (state.authorizedOverageSpendingLimitCents === undefined) state.authorizedOverageSpendingLimitCents = 0;
    return state;
  }

  async updateBillingSafetyState(
    organizationId: string,
    data: Partial<BillingSafetyStateRecord>
  ): Promise<BillingSafetyStateRecord> {
    const now = new Date();

    if (await this.checkPrisma()) {
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          const updated = await prisma.billingSafetyState.upsert({
            where: { organizationId },
            create: {
              organizationId,
              circuitBreakerStatus: data.circuitBreakerStatus || 'NORMAL',
              opsPerMinute: data.opsPerMinute ?? 0,
              opsPerHour: data.opsPerHour ?? 0,
              opsPerDay: data.opsPerDay ?? 0,
              lastWindowReset: data.lastWindowReset || now,
              paygSpendingLimitCents: data.paygSpendingLimitCents ?? 25000,
              alertThresholdPercent: data.alertThresholdPercent ?? 80,
              autoHaltEnabled: data.autoHaltEnabled ?? true,
              overagePolicy: data.overagePolicy || 'HARD_STOP',
              authorizedOverageSpendingLimitCents: data.authorizedOverageSpendingLimitCents ?? 0,
              suspensionReason: data.suspensionReason || null,
            },
            update: {
              ...data,
              updatedAt: now,
            },
          });
          const res = updated as BillingSafetyStateRecord;
          if (!res.overagePolicy) res.overagePolicy = data.overagePolicy || 'HARD_STOP';
          if (res.authorizedOverageSpendingLimitCents === undefined) res.authorizedOverageSpendingLimitCents = data.authorizedOverageSpendingLimitCents ?? 0;
          return res;
        } catch (err) {
          if (attempt === 4) {
            this.rethrowUnlessNotFound(err);
            throw err;
          }
          await new Promise((r) => setTimeout(r, 20 * (attempt + 1)));
        }
      }
    }

    const current = await this.getBillingSafetyState(organizationId);
    const updated: BillingSafetyStateRecord = {
      ...current,
      ...data,
      updatedAt: now,
    };
    this.memStore.billingSafetyStates.set(organizationId, updated);
    return updated;
  }

  async recordBillingWebhookEvent(
    eventId: string,
    eventType: string,
    payload: any
  ): Promise<{ isDuplicate: boolean; record: BillingWebhookEventRecord }> {
    const now = new Date();
    if (await this.checkPrisma()) {
      try {
        const existing = await prisma.billingWebhookEvent.findUnique({
          where: { eventId },
        });
        if (existing) {
          // If the event was previously recorded AND successfully processed without error, it is a duplicate
          if (existing.processed && !existing.error) {
            return { isDuplicate: true, record: existing as BillingWebhookEventRecord };
          }
          // Prior attempt failed or was unprocessed; allow safe retry processing
          return { isDuplicate: false, record: existing as BillingWebhookEventRecord };
        }
        const created = await prisma.billingWebhookEvent.create({
          data: {
            eventId,
            eventType,
            payload,
            processed: false,
          },
        });
        return { isDuplicate: false, record: created as BillingWebhookEventRecord };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    if (this.memStore.billingWebhookEvents.has(eventId)) {
      const existing = this.memStore.billingWebhookEvents.get(eventId)!;
      if (existing.processed && !existing.error) {
        return { isDuplicate: true, record: existing };
      }
      return { isDuplicate: false, record: existing };
    }

    const record: BillingWebhookEventRecord = {
      id: `bwe_${crypto.randomUUID().slice(0, 12)}`,
      eventId,
      eventType,
      payload,
      processed: false,
      createdAt: now,
    };
    this.memStore.billingWebhookEvents.set(eventId, record);
    return { isDuplicate: false, record };
  }

  /**
   * Atomically claims a one-time billing token (e.g. `checkout:<id>`) using the unique eventId.
   * Returns false if it was already claimed, whether that claim finished or is still running.
   */
  async claimBillingToken(eventId: string, eventType: string, payload: any): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.billingWebhookEvent.create({
          data: { eventId, eventType, payload, processed: false },
        });
        return true;
      } catch (err) {
        if ((err as { code?: string } | null)?.code === 'P2002') return false;
        this.rethrowUnlessNotFound(err);
      }
    }

    if (this.memStore.billingWebhookEvents.has(eventId)) return false;
    this.memStore.billingWebhookEvents.set(eventId, {
      id: `bwe_${crypto.randomUUID().slice(0, 12)}`,
      eventId,
      eventType,
      payload,
      processed: false,
      createdAt: new Date(),
    } as BillingWebhookEventRecord);
    return true;
  }

  /** Releases a claim whose work failed, so the same token can be retried. */
  async releaseBillingToken(eventId: string): Promise<void> {
    if (await this.checkPrisma()) {
      try {
        await prisma.billingWebhookEvent.delete({ where: { eventId } });
        return;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    this.memStore.billingWebhookEvents.delete(eventId);
  }

  async markBillingWebhookProcessed(eventId: string, error?: string): Promise<void> {
    const now = new Date();
    if (await this.checkPrisma()) {
      try {
        await prisma.billingWebhookEvent.update({
          where: { eventId },
          data: {
            processed: !error,
            processedAt: now,
            error: error || null,
          },
        });
        return;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const record = this.memStore.billingWebhookEvents.get(eventId);
    if (record) {
      record.processed = !error;
      record.processedAt = now;
      record.error = error || null;
    }
  }

  // --- Cryptographic Operations (Phase 10.5 Unified Runtime) ---

  async createCryptographicOperation(
    data: Partial<CryptographicOperationRecord> & { organizationId: string; operationType: string }
  ): Promise<CryptographicOperationRecord> {
    const now = new Date();
    const id = data.id || `op_${crypto.randomUUID()}`;
    const record: CryptographicOperationRecord = {
      id,
      requestId: data.requestId || null,
      idempotencyKey: data.idempotencyKey || null,
      organizationId: data.organizationId,
      projectId: data.projectId || null,
      environmentId: data.environmentId || null,
      operationType: data.operationType,
      algorithm: data.algorithm || null,
      keyId: data.keyId || null,
      providerId: data.providerId || null,
      status: data.status || 'REQUESTED',
      durationMs: data.durationMs || null,
      retryCount: data.retryCount || 0,
      result: data.result || null,
      metadata: data.metadata || null,
      error: data.error || null,
      expiresAt: data.expiresAt || null,
      createdAt: data.createdAt || now,
      updatedAt: now,
    };

    if (await this.checkPrisma()) {
      try {
        const created = await prisma.cryptographicOperation.create({
          data: {
            id: record.id,
            requestId: record.requestId,
            idempotencyKey: record.idempotencyKey,
            organizationId: record.organizationId,
            projectId: record.projectId,
            environmentId: record.environmentId,
            operationType: record.operationType,
            algorithm: record.algorithm,
            keyId: record.keyId,
            providerId: record.providerId,
            status: record.status,
            durationMs: record.durationMs,
            retryCount: record.retryCount,
            result: record.result,
            metadata: record.metadata,
            error: record.error,
            expiresAt: record.expiresAt,
          },
        });
        return created as CryptographicOperationRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.cryptographicOperations.set(id, record);
    return record;
  }

  async updateCryptographicOperation(
    id: string,
    data: Partial<CryptographicOperationRecord>
  ): Promise<CryptographicOperationRecord | null> {
    const now = data.updatedAt || new Date();
    if (await this.checkPrisma()) {
      try {
        const updated = await prisma.cryptographicOperation.update({
          where: { id },
          data: {
            ...data,
            updatedAt: now,
          },
        });
        return updated as CryptographicOperationRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const existing = this.memStore.cryptographicOperations.get(id);
    if (!existing) return null;
    const updated: CryptographicOperationRecord = {
      ...existing,
      ...data,
      updatedAt: now,
    };
    this.memStore.cryptographicOperations.set(id, updated);
    return updated;
  }

  async getCryptographicOperation(id: string): Promise<CryptographicOperationRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const op = await prisma.cryptographicOperation.findUnique({
          where: { id },
        });
        if (op) return op as CryptographicOperationRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.cryptographicOperations.get(id) || null;
  }

  async getCryptographicOperationByIdempotencyKey(
    organizationId: string,
    idempotencyKey: string
  ): Promise<CryptographicOperationRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const op = await prisma.cryptographicOperation.findFirst({
          where: { organizationId, idempotencyKey },
          orderBy: { createdAt: 'desc' },
        });
        if (op) return op as CryptographicOperationRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    for (const op of this.memStore.cryptographicOperations.values()) {
      if (op.organizationId === organizationId && op.idempotencyKey === idempotencyKey) {
        return op;
      }
    }
    return null;
  }

  async listCryptographicOperations(
    organizationId: string,
    options?: { limit?: number; offset?: number; status?: string; operationType?: string }
  ): Promise<CryptographicOperationRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { organizationId };
        if (options?.status) where.status = options.status;
        if (options?.operationType) where.operationType = options.operationType;
        const ops = await prisma.cryptographicOperation.findMany({
          where,
          take: options?.limit || 50,
          skip: options?.offset || 0,
          orderBy: { createdAt: 'desc' },
        });
        return ops as CryptographicOperationRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    let results = Array.from(this.memStore.cryptographicOperations.values())
      .filter((op) => op.organizationId === organizationId);
    if (options?.status) results = results.filter((op) => op.status === options.status);
    if (options?.operationType) results = results.filter((op) => op.operationType === options.operationType);
    results.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    const offset = options?.offset || 0;
    const limit = options?.limit || 50;
    return results.slice(offset, offset + limit);
  }

  async deleteCryptographicOperation(id: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.cryptographicOperation.delete({ where: { id } });
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.cryptographicOperations.delete(id);
  }

  async listStaleCryptographicOperations(
    statuses: string[],
    olderThan: Date
  ): Promise<CryptographicOperationRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const ops = await prisma.cryptographicOperation.findMany({
          where: {
            status: { in: statuses },
            updatedAt: { lt: olderThan },
          },
          take: 100,
          orderBy: { updatedAt: 'asc' },
        });
        return ops as CryptographicOperationRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const results: CryptographicOperationRecord[] = [];
    const thresholdTime = olderThan.getTime();
    for (const op of this.memStore.cryptographicOperations.values()) {
      if (statuses.includes(op.status) && op.updatedAt.getTime() < thresholdTime) {
        results.push(op);
        if (results.length >= 100) break;
      }
    }
    return results;
  }


  // =========================================================================
  // PHASE 15: CRYPTOGRAPHIC POLICY ENGINE DATASTORE METHODS
  // =========================================================================

  async createPolicy(data: {
    id?: string;
    organizationId: string;
    name: string;
    description?: string | null;
    rules: any;
    enforcementMode?: string;
    metadata?: any;
    actorId?: string | null;
  }): Promise<CryptographicPolicyRecord> {
    const id = data.id || `pol_${crypto.randomUUID()}`;
    const now = new Date();
    const record: CryptographicPolicyRecord = {
      id,
      organizationId: data.organizationId,
      name: data.name,
      description: data.description || null,
      currentVersion: 1,
      isActive: true,
      enforcementMode: data.enforcementMode || 'ENFORCE',
      rules: data.rules,
      metadata: data.metadata || null,
      createdAt: now,
      updatedAt: now,
    };

    if (await this.checkPrisma()) {
      try {
        const created = await prisma.cryptographicPolicy.create({
          data: {
            id,
            organizationId: data.organizationId,
            name: data.name,
            description: data.description || null,
            currentVersion: 1,
            isActive: true,
            enforcementMode: data.enforcementMode || 'ENFORCE',
            rules: data.rules,
            metadata: data.metadata || undefined,
            versions: {
              create: {
                version: 1,
                rules: data.rules,
                changeSummary: 'Initial policy creation',
                actorId: data.actorId || null,
              },
            },
          },
        });
        return created as CryptographicPolicyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.policies.set(id, record);
    const versionRecord: CryptographicPolicyVersionRecord = {
      id: `polver_${crypto.randomUUID()}`,
      policyId: id,
      version: 1,
      rules: data.rules,
      changeSummary: 'Initial policy creation',
      actorId: data.actorId || null,
      createdAt: now,
    };
    this.memStore.policyVersions.set(versionRecord.id, versionRecord);
    return record;
  }

  async getPolicy(id: string, organizationId?: string): Promise<CryptographicPolicyRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { id };
        if (organizationId) where.organizationId = organizationId;
        const pol = await prisma.cryptographicPolicy.findFirst({
          where,
          include: { versions: { orderBy: { version: 'desc' } } },
        });
        if (pol) return pol as CryptographicPolicyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const pol = this.memStore.policies.get(id);
    if (pol) {
      if (organizationId && pol.organizationId !== organizationId) return null;
      return pol;
    }
    return null;
  }

  async getPolicyByName(organizationId: string, name: string): Promise<CryptographicPolicyRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const pol = await prisma.cryptographicPolicy.findFirst({
          where: { organizationId, name },
          include: { versions: { orderBy: { version: 'desc' } } },
        });
        if (pol) return pol as CryptographicPolicyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    for (const p of this.memStore.policies.values()) {
      if (p.organizationId === organizationId && p.name === name) {
        return p;
      }
    }
    return null;
  }

  async listPolicies(organizationId: string): Promise<CryptographicPolicyRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const list = await prisma.cryptographicPolicy.findMany({
          where: { organizationId },
          orderBy: { createdAt: 'desc' },
          include: { versions: { orderBy: { version: 'desc' }, take: 1 } },
        });
        return list as CryptographicPolicyRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return Array.from(this.memStore.policies.values())
      .filter((p) => p.organizationId === organizationId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async updatePolicy(
    id: string,
    organizationId: string,
    data: Partial<CryptographicPolicyRecord>,
    actorId?: string | null,
    changeSummary?: string | null
  ): Promise<CryptographicPolicyRecord> {
    const existing = await this.getPolicy(id, organizationId);
    if (!existing) {
      throw new Error(`Policy '${id}' not found in organization.`);
    }

    const nextVersion = existing.currentVersion + 1;
    const now = new Date();
    const effectiveRules = data.rules || existing.rules;

    if (await this.checkPrisma()) {
      try {
        const updateData: any = {
          ...data,
          currentVersion: nextVersion,
          updatedAt: now,
          versions: {
            create: {
              version: nextVersion,
              rules: effectiveRules,
              changeSummary: changeSummary || (data.rules ? 'Policy rules update' : 'Policy update'),
              actorId: actorId || null,
            },
          },
        };
        delete updateData.id;
        delete updateData.organizationId;
        delete updateData.assignments;

        const updated = await prisma.cryptographicPolicy.update({
          where: { id },
          data: updateData,
          include: { versions: { orderBy: { version: 'desc' } } },
        });
        return updated as CryptographicPolicyRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const updatedRecord: CryptographicPolicyRecord = {
      ...existing,
      ...data,
      currentVersion: nextVersion,
      updatedAt: now,
    };
    this.memStore.policies.set(id, updatedRecord);

    const verRecord: CryptographicPolicyVersionRecord = {
      id: `polver_${crypto.randomUUID()}`,
      policyId: id,
      version: nextVersion,
      rules: effectiveRules,
      changeSummary: changeSummary || (data.rules ? 'Policy rules update' : 'Policy update'),
      actorId: actorId || null,
      createdAt: now,
    };
    this.memStore.policyVersions.set(verRecord.id, verRecord);

    return updatedRecord;
  }

  async deletePolicy(id: string, organizationId: string): Promise<boolean> {
    const existing = await this.getPolicy(id, organizationId);
    if (!existing) return false;

    if (await this.checkPrisma()) {
      try {
        await prisma.cryptographicPolicy.delete({ where: { id } });
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return this.memStore.policies.delete(id);
  }

  async listPolicyVersions(policyId: string): Promise<CryptographicPolicyVersionRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const vers = await prisma.cryptographicPolicyVersion.findMany({
          where: { policyId },
          orderBy: { version: 'desc' },
        });
        return vers as CryptographicPolicyVersionRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return Array.from(this.memStore.policyVersions.values())
      .filter((v) => v.policyId === policyId)
      .sort((a, b) => b.version - a.version);
  }

  async assignPolicy(data: {
    policyId: string;
    organizationId: string;
    scopeType: string;
    scopeId: string;
    priority?: number;
  }): Promise<CryptographicPolicyAssignmentRecord> {
    const id = `pass_${crypto.randomUUID()}`;
    const now = new Date();
    const record: CryptographicPolicyAssignmentRecord = {
      id,
      policyId: data.policyId,
      organizationId: data.organizationId,
      scopeType: data.scopeType,
      scopeId: data.scopeId,
      priority: data.priority ?? 100,
      createdAt: now,
    };

    if (await this.checkPrisma()) {
      try {
        const assigned = await prisma.cryptographicPolicyAssignment.upsert({
          where: {
            organizationId_scopeType_scopeId: {
              organizationId: data.organizationId,
              scopeType: data.scopeType,
              scopeId: data.scopeId,
            },
          },
          update: {
            policyId: data.policyId,
            priority: data.priority ?? 100,
          },
          create: { ...record, policy: undefined },
        });
        return assigned as CryptographicPolicyAssignmentRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.policyAssignments.set(id, record);
    return record;
  }

  async listPolicyAssignments(organizationId: string): Promise<CryptographicPolicyAssignmentRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const list = await prisma.cryptographicPolicyAssignment.findMany({
          where: { organizationId },
          include: { policy: true },
        });
        return list as CryptographicPolicyAssignmentRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return Array.from(this.memStore.policyAssignments.values()).filter(
      (a) => a.organizationId === organizationId
    );
  }

  async deletePolicyAssignment(id: string, organizationId: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.cryptographicPolicyAssignment.delete({ where: { id } });
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.policyAssignments.delete(id);
  }

  // ==========================================
  // PHASE 16: TEAMS & ENTERPRISE COLLABORATION
  // ==========================================

  async createTeam(data: { organizationId: string; name: string; description?: string }): Promise<TeamRecord> {
    const id = `team_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const now = new Date();
    const record: TeamRecord = {
      id,
      organizationId: data.organizationId,
      name: data.name,
      description: data.description || null,
      createdAt: now,
      updatedAt: now,
    };

    if (await this.checkPrisma()) {
      try {
        const team = await prisma.team.create({ data: { ...record, members: undefined } });
        return team as TeamRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.teams.set(id, record);
    return record;
  }

  async getTeamById(id: string): Promise<TeamRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const team = await prisma.team.findUnique({
          where: { id },
          include: { members: { include: { user: true } } },
        });
        return team as TeamRecord | null;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.teams.get(id) || null;
  }

  async listTeams(organizationId: string): Promise<TeamRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const teams = await prisma.team.findMany({
          where: { organizationId },
          include: { members: true },
          orderBy: { createdAt: 'desc' },
        });
        return teams as TeamRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return Array.from(this.memStore.teams.values()).filter((t) => t.organizationId === organizationId);
  }

  async updateTeam(id: string, data: { name?: string; description?: string }): Promise<TeamRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const updated = await prisma.team.update({
          where: { id },
          data: { ...data, updatedAt: new Date() },
        });
        return updated as TeamRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const team = this.memStore.teams.get(id);
    if (!team) return null;
    const updated = { ...team, ...data, updatedAt: new Date() };
    this.memStore.teams.set(id, updated);
    return updated;
  }

  async deleteTeam(id: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.team.delete({ where: { id } });
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.teams.delete(id);
  }

  async addTeamMember(data: { teamId: string; userId: string; role?: string }): Promise<TeamMemberRecord> {
    const id = `tm_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const now = new Date();
    const record: TeamMemberRecord = {
      id,
      teamId: data.teamId,
      userId: data.userId,
      role: data.role || 'MEMBER',
      createdAt: now,
    };

    if (await this.checkPrisma()) {
      try {
        const member = await prisma.teamMember.upsert({
          where: { teamId_userId: { teamId: data.teamId, userId: data.userId } },
          update: { role: data.role || 'MEMBER' },
          create: { ...record, user: undefined },
        });
        return member as TeamMemberRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.teamMembers.set(id, record);
    return record;
  }

  async removeTeamMember(teamId: string, userId: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.teamMember.delete({
          where: { teamId_userId: { teamId, userId } },
        });
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    for (const [id, tm] of this.memStore.teamMembers.entries()) {
      if (tm.teamId === teamId && tm.userId === userId) {
        this.memStore.teamMembers.delete(id);
        return true;
      }
    }
    return false;
  }

  async listTeamMembers(teamId: string): Promise<TeamMemberRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const members = await prisma.teamMember.findMany({
          where: { teamId },
          include: { user: true },
        });
        return members as TeamMemberRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return Array.from(this.memStore.teamMembers.values()).filter((tm) => tm.teamId === teamId);
  }

  // ==========================================
  // PHASE 16: SERVICE IDENTITIES & MACHINE AUTH
  // ==========================================

  async createServiceIdentity(data: {
    organizationId: string;
    projectId?: string;
    environmentId?: string;
    name: string;
    description?: string;
    scopes: string[];
    prefix: string;
    keyHash: string;
    createdBy?: string;
    expiresAt?: Date;
  }): Promise<ServiceIdentityRecord> {
    const id = `si_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const now = new Date();
    const record: ServiceIdentityRecord = {
      id,
      organizationId: data.organizationId,
      projectId: data.projectId || null,
      environmentId: data.environmentId || null,
      name: data.name,
      description: data.description || null,
      status: 'ACTIVE',
      scopes: data.scopes,
      prefix: data.prefix,
      keyHash: data.keyHash,
      createdBy: data.createdBy || null,
      expiresAt: data.expiresAt || null,
      createdAt: now,
      updatedAt: now,
    };

    if (await this.checkPrisma()) {
      try {
        const created = await prisma.serviceIdentity.create({ data: record });
        return created as ServiceIdentityRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.serviceIdentities.set(id, record);
    return record;
  }

  async getServiceIdentityById(id: string): Promise<ServiceIdentityRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const si = await prisma.serviceIdentity.findUnique({ where: { id } });
        return si as ServiceIdentityRecord | null;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    return this.memStore.serviceIdentities.get(id) || null;
  }

  async getServiceIdentityByHash(keyHash: string): Promise<ServiceIdentityRecord | null> {
    if (await this.checkPrisma()) {
      try {
        const si = await prisma.serviceIdentity.findUnique({ where: { keyHash } });
        return si as ServiceIdentityRecord | null;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    for (const si of this.memStore.serviceIdentities.values()) {
      if (si.keyHash === keyHash) return si;
    }
    return null;
  }

  async listServiceIdentities(organizationId: string, filters?: { projectId?: string; environmentId?: string }): Promise<ServiceIdentityRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { organizationId };
        if (filters?.projectId) where.projectId = filters.projectId;
        if (filters?.environmentId) where.environmentId = filters.environmentId;
        const list = await prisma.serviceIdentity.findMany({
          where,
          orderBy: { createdAt: 'desc' },
        });
        return list as ServiceIdentityRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return Array.from(this.memStore.serviceIdentities.values()).filter((si) => {
      if (si.organizationId !== organizationId) return false;
      if (filters?.projectId && si.projectId !== filters.projectId) return false;
      if (filters?.environmentId && si.environmentId !== filters.environmentId) return false;
      return true;
    });
  }

  async revokeServiceIdentity(id: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.serviceIdentity.update({
          where: { id },
          data: { status: 'REVOKED', updatedAt: new Date() },
        });
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const si = this.memStore.serviceIdentities.get(id);
    if (!si) return false;
    si.status = 'REVOKED';
    si.updatedAt = new Date();
    return true;
  }

  // ==========================================
  // PHASE 16: CONFIGURATION DRIFT DETECTION
  // ==========================================

  async recordDrift(data: {
    organizationId: string;
    resourceType: string;
    resourceId: string;
    expectedState?: any;
    actualState?: any;
    driftSummary?: string;
    description?: string;
    severity?: string;
  }): Promise<ConfigurationDriftRecord> {
    const id = `drift_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const now = new Date();
    const record: ConfigurationDriftRecord = {
      id,
      organizationId: data.organizationId,
      resourceType: data.resourceType,
      resourceId: data.resourceId,
      expectedState: data.expectedState || { configured: true },
      actualState: data.actualState || { drifted: true },
      driftSummary: data.driftSummary || data.description || 'Configuration drift detected',
      status: 'DETECTED',
      detectedAt: now,
    };

    if (await this.checkPrisma()) {
      try {
        const created = await prisma.configurationDrift.create({ data: record });
        this.memStore.configurationDrifts.set(id, record);
        return created as ConfigurationDriftRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    this.memStore.configurationDrifts.set(id, record);
    return record;
  }

  async listDriftRecords(organizationId: string, status?: string): Promise<ConfigurationDriftRecord[]> {
    if (await this.checkPrisma()) {
      try {
        const where: any = { organizationId };
        if (status) where.status = status;
        const list = await prisma.configurationDrift.findMany({
          where,
          orderBy: { detectedAt: 'desc' },
        });
        return list as ConfigurationDriftRecord[];
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    return Array.from(this.memStore.configurationDrifts.values()).filter((d) => {
      if (d.organizationId !== organizationId) return false;
      if (status && d.status !== status) return false;
      return true;
    });
  }

  async resolveDrift(id: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      try {
        await prisma.configurationDrift.update({
          where: { id },
          data: { status: 'RESOLVED', resolvedAt: new Date() },
        });
        const cached = this.memStore.configurationDrifts.get(id);
        if (cached) {
          cached.status = 'RESOLVED';
          cached.resolvedAt = new Date();
        }
        return true;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }
    const d = this.memStore.configurationDrifts.get(id);
    if (!d) return false;
    d.status = 'RESOLVED';
    d.resolvedAt = new Date();
    return true;
  }

  // ==========================================
  // PHASE 16: SECURITY SETTINGS
  // ==========================================

  async getOrganizationSecuritySettings(organizationId: string): Promise<OrganizationSecuritySettingRecord> {
    if (await this.checkPrisma()) {
      try {
        let settings = await prisma.organizationSecuritySetting.findUnique({
          where: { organizationId },
        });
        if (!settings) {
          settings = await prisma.organizationSecuritySetting.create({
            data: {
              organizationId,
              enforceMfa: false,
              allowedIpRanges: [],
              defaultKeyRotationDays: 90,
              requireHsmInProduction: false,
              requirePqcInProduction: false,
            },
          });
        }
        return settings as OrganizationSecuritySettingRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    let settings = this.memStore.securitySettings.get(organizationId);
    if (!settings) {
      settings = {
        id: `sec_${Date.now()}`,
        organizationId,
        enforceMfa: false,
        allowedIpRanges: [],
        defaultKeyRotationDays: 90,
        requireHsmInProduction: false,
        requirePqcInProduction: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      this.memStore.securitySettings.set(organizationId, settings);
    }
    return settings;
  }

  async updateOrganizationSecuritySettings(
    organizationId: string,
    data: Partial<{
      enforceMfa: boolean;
      allowedIpRanges: string[];
      defaultKeyRotationDays: number;
      requireHsmInProduction: boolean;
      requirePqcInProduction: boolean;
    }>
  ): Promise<OrganizationSecuritySettingRecord> {
    if (await this.checkPrisma()) {
      try {
        const updated = await prisma.organizationSecuritySetting.upsert({
          where: { organizationId },
          update: data,
          create: {
            organizationId,
            enforceMfa: data.enforceMfa ?? false,
            allowedIpRanges: data.allowedIpRanges ?? [],
            defaultKeyRotationDays: data.defaultKeyRotationDays ?? 90,
            requireHsmInProduction: data.requireHsmInProduction ?? false,
            requirePqcInProduction: data.requirePqcInProduction ?? false,
          },
        });
        return updated as OrganizationSecuritySettingRecord;
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    const current = await this.getOrganizationSecuritySettings(organizationId);
    const updated = { ...current, ...data, updatedAt: new Date() };
    this.memStore.securitySettings.set(organizationId, updated);
    return updated;
  }

  // ==========================================
  // PHASE 16: CRYPTOGRAPHIC POSTURE AGGREGATOR
  // ==========================================

  async generateCryptographicPosture(organizationId: string) {
    // 1. Keys aggregation
    const keys = await this.listKeys({ organizationId });
    const totalKeys = keys.length;
    let activeKeys = 0;
    let disabledKeys = 0;
    let destroyedKeys = 0;
    let rotationRequiredKeys = 0;
    let pqcKeys = 0;
    const algorithmDistribution: Record<string, number> = {};

    const now = Date.now();
    for (const key of keys) {
      const algo = (key.algorithm || 'UNKNOWN').toUpperCase();
      algorithmDistribution[algo] = (algorithmDistribution[algo] || 0) + 1;

      if (algo.includes('ML-KEM') || algo.includes('ML-DSA') || algo.includes('HYBRID')) {
        pqcKeys++;
      }

      if (key.status === 'ACTIVE') {
        activeKeys++;
        const ageDays = (now - new Date(key.createdAt).getTime()) / (1000 * 60 * 60 * 24);
        if (ageDays > 90) {
          rotationRequiredKeys++;
        }
      } else if (key.status === 'DISABLED') {
        disabledKeys++;
      } else if (key.status === 'DESTROYED') {
        destroyedKeys++;
      }
    }

    // 2. Policies aggregation
    const policies = await this.listPolicies(organizationId);
    const activePolicies = policies.filter((p) => p.isActive).length;

    // 3. Certificates aggregation
    const certs = await this.listCertificates({ organizationId });
    let expiringCertificates = 0;
    for (const cert of certs) {
      if (cert.notAfter) {
        const daysToExpiry = (new Date(cert.notAfter).getTime() - now) / (1000 * 60 * 60 * 24);
        if (daysToExpiry > 0 && daysToExpiry < 30) {
          expiringCertificates++;
        }
      }
    }

    // 4. Configuration Drifts
    const drifts = await this.listDriftRecords(organizationId, 'DETECTED');

    // 5. Findings & Scores
    const findings: Array<{ category: string; severity: string; title: string; detail: string }> = [];

    if (rotationRequiredKeys > 0) {
      findings.push({
        category: 'KEY_LIFECYCLE',
        severity: 'MEDIUM',
        title: `${rotationRequiredKeys} keys exceed recommended 90-day rotation age`,
        detail: 'Plan rotation to maintain cryptoperiod hygiene according to NIST SP 800-57.',
      });
    }

    if (expiringCertificates > 0) {
      findings.push({
        category: 'CERTIFICATES',
        severity: 'HIGH',
        title: `${expiringCertificates} certificates expiring within 30 days`,
        detail: 'Renew or re-issue expiring certificates to avoid TLS/mTLS service disruptions.',
      });
    }

    if (drifts.length > 0) {
      findings.push({
        category: 'CONFIGURATION_DRIFT',
        severity: 'HIGH',
        title: `${drifts.length} unresolved configuration drifts detected`,
        detail: 'Inspect and reconcile configuration deviations between desired and actual state.',
      });
    }

    const pqcReadinessScore = totalKeys > 0 ? Math.round((pqcKeys / totalKeys) * 100) : 100;
    const overallPostureScore = Math.max(0, 100 - rotationRequiredKeys * 5 - expiringCertificates * 10 - drifts.length * 15);

    const keyData = {
      total: totalKeys,
      active: activeKeys,
      disabled: disabledKeys,
      destroyed: destroyedKeys,
      rotationRequired: rotationRequiredKeys,
      pqcCount: pqcKeys,
      algorithmDistribution,
    };

    const certData = {
      total: certs.length,
      expiringSoon: expiringCertificates,
    };

    const driftData = {
      unresolvedCount: drifts.length,
      items: drifts.slice(0, 5),
    };

    return {
      organizationId,
      timestamp: new Date().toISOString(),
      overallPostureScore,
      postureScore: overallPostureScore,
      pqcReadinessScore,
      keys: keyData,
      keySummary: keyData,
      certificates: certData,
      certificateSummary: certData,
      policies: {
        total: policies.length,
        active: activePolicies,
      },
      drifts: driftData,
      driftSummary: driftData,
      findings,
    };
  }

  async listManagedOperations(filters: {
    organizationId: string;
    status?: string;
    type?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ operations: any[]; total: number }> {
    const limit = filters.limit ?? 50;
    const offset = filters.offset ?? 0;

    if (await this.checkPrisma()) {
      try {
        const where: any = { organizationId: filters.organizationId };
        if (filters.status) where.status = filters.status;
        if (filters.type) where.operationType = filters.type;

        const [operations, total] = await Promise.all([
          prisma.cryptographicOperation.findMany({
            where,
            orderBy: { createdAt: 'desc' },
            skip: offset,
            take: limit,
          }),
          prisma.cryptographicOperation.count({ where }),
        ]);

        return { operations, total };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    let allOps = Array.from(this.memStore.cryptographicOperations.values()).filter(
      (op) => op.organizationId === filters.organizationId
    );
    if (filters.status) allOps = allOps.filter((op) => op.status === filters.status);
    if (filters.type) allOps = allOps.filter((op) => (op as any).type === filters.type || (op as any).operationType === filters.type);

    const total = allOps.length;
    const paginated = allOps.slice(offset, offset + limit);
    return { operations: paginated, total };
  }

  async listAuditEvents(filters: {
    organizationId?: string;
    actorId?: string;
    action?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<{ events: any[]; total: number }> {
    const limit = filters.limit ?? 50;
    const offset = filters.offset ?? 0;

    if (await this.checkPrisma()) {
      try {
        const where: any = {};
        if (filters.organizationId) where.organizationId = filters.organizationId;
        if (filters.actorId) where.actorId = filters.actorId;
        if (filters.action) where.action = filters.action;

        const [events, total] = await Promise.all([
          prisma.auditEvent.findMany({
            where,
            orderBy: { createdAt: 'desc' },
            skip: offset,
            take: limit,
          }),
          prisma.auditEvent.count({ where }),
        ]);

        return { events, total };
      } catch (err) {
        this.rethrowUnlessNotFound(err);
      }
    }

    let allEvents = filters.organizationId
      ? this.memStore.auditEvents.filter((ev) => ev.organizationId === filters.organizationId)
      : [...this.memStore.auditEvents];
    if (filters.actorId) allEvents = allEvents.filter((ev) => ev.userId === filters.actorId);
    if (filters.action) allEvents = allEvents.filter((ev) => ev.action === filters.action);

    const total = allEvents.length;
    const paginated = allEvents.slice(offset, offset + limit);
    return { events: paginated, total };
  }

  async createUpload(data: Omit<UploadRecord, 'id' | 'createdAt' | 'updatedAt'> & { id?: string }): Promise<UploadRecord> {
    const id = data.id || `upl_${crypto.randomUUID()}`;
    if (await this.checkPrisma()) {
      const created = await prisma.upload.create({
        data: { ...data, id, metadata: data.metadata ?? undefined },
      });
      return toUploadRecord(created);
    }
    const record: UploadRecord = {
      ...data,
      id,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.memStore.uploads.set(id, record);
    return record;
  }

  async getUploadById(organizationId: string, id: string): Promise<UploadRecord | null> {
    if (await this.checkPrisma()) {
      const found = await prisma.upload.findFirst({ where: { id, organizationId } });
      return found ? toUploadRecord(found) : null;
    }
    const record = this.memStore.uploads.get(id);
    if (!record || record.organizationId !== organizationId) return null;
    return record;
  }

  async listUploads(organizationId: string, options?: { limit?: number; offset?: number }): Promise<{ uploads: UploadRecord[]; total: number }> {
    const limit = options?.limit ?? 50;
    const offset = options?.offset ?? 0;
    if (await this.checkPrisma()) {
      const [rows, total] = await Promise.all([
        prisma.upload.findMany({ where: { organizationId }, orderBy: { createdAt: 'desc' }, skip: offset, take: limit }),
        prisma.upload.count({ where: { organizationId } }),
      ]);
      return { uploads: rows.map(toUploadRecord), total };
    }
    const list = Array.from(this.memStore.uploads.values())
      .filter((u) => u.organizationId === organizationId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    return {
      uploads: list.slice(offset, offset + limit),
      total: list.length,
    };
  }

  async deleteUpload(organizationId: string, id: string): Promise<boolean> {
    if (await this.checkPrisma()) {
      const { count } = await prisma.upload.deleteMany({ where: { id, organizationId } });
      return count > 0;
    }
    const record = this.memStore.uploads.get(id);
    if (!record || record.organizationId !== organizationId) return false;
    this.memStore.uploads.delete(id);
    return true;
  }

  async createHackathonSubmission(
    data: Omit<HackathonSubmissionRecord, 'id' | 'createdAt' | 'updatedAt' | 'status'> & { id?: string; status?: HackathonSubmissionRecord['status'] }
  ): Promise<HackathonSubmissionRecord> {
    const id = data.id || `hck_${crypto.randomUUID()}`;
    const status = data.status || 'SUBMITTED';
    if (await this.checkPrisma()) {
      const created = await prisma.hackathonSubmission.create({ data: { ...data, id, status } });
      return toHackathonRecord(created);
    }
    const record: HackathonSubmissionRecord = {
      ...data,
      id,
      status,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.memStore.hackathonSubmissions.set(id, record);
    return record;
  }

  async updateHackathonSubmission(
    id: string,
    updates: Partial<HackathonSubmissionRecord>
  ): Promise<HackathonSubmissionRecord | null> {
    const { id: _id, createdAt: _createdAt, updatedAt: _updatedAt, ...fields } = updates;
    if (await this.checkPrisma()) {
      try {
        const updated = await prisma.hackathonSubmission.update({ where: { id }, data: fields });
        return toHackathonRecord(updated);
      } catch (err) {
        this.rethrowUnlessNotFound(err);
        return null;
      }
    }
    const existing = this.memStore.hackathonSubmissions.get(id);
    if (!existing) return null;
    const updated: HackathonSubmissionRecord = {
      ...existing,
      ...fields,
      updatedAt: new Date(),
    };
    this.memStore.hackathonSubmissions.set(id, updated);
    return updated;
  }

  async getHackathonSubmissionById(id: string): Promise<HackathonSubmissionRecord | null> {
    if (await this.checkPrisma()) {
      const found = await prisma.hackathonSubmission.findUnique({ where: { id } });
      return found ? toHackathonRecord(found) : null;
    }
    return this.memStore.hackathonSubmissions.get(id) || null;
  }

  async listHackathonSubmissions(organizationId?: string): Promise<HackathonSubmissionRecord[]> {
    if (await this.checkPrisma()) {
      const rows = await prisma.hackathonSubmission.findMany({
        where: organizationId ? { organizationId } : undefined,
        orderBy: { createdAt: 'desc' },
      });
      return rows.map(toHackathonRecord);
    }
    const list = Array.from(this.memStore.hackathonSubmissions.values());
    if (organizationId) {
      return list.filter((s) => s.organizationId === organizationId).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    }
    return list.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getPlatformUserCount(): Promise<number> {
    if (await this.checkPrisma()) {
      return prisma.user.count();
    }
    return this.memStore.users.size;
  }

  // --- VERIFICATIONS (short-lived codes, keyed by identifier) ---
  // Shares the Better Auth `verification` table, so callers namespace their identifiers.

  async saveVerification(record: VerificationRecord): Promise<void> {
    if (await this.checkPrisma()) {
      await prisma.$transaction([
        prisma.verification.deleteMany({ where: { identifier: record.identifier } }),
        prisma.verification.create({ data: record }),
      ]);
      return;
    }
    this.memStore.verifications.set(record.identifier, { ...record });
  }

  async getVerification(identifier: string): Promise<VerificationRecord | null> {
    if (await this.checkPrisma()) {
      const row = await prisma.verification.findFirst({ where: { identifier }, orderBy: { createdAt: 'desc' } });
      return row ? { identifier: row.identifier, value: row.value, expiresAt: row.expiresAt } : null;
    }
    const record = this.memStore.verifications.get(identifier);
    return record ? { ...record } : null;
  }

  async deleteVerification(identifier: string): Promise<void> {
    if (await this.checkPrisma()) {
      await prisma.verification.deleteMany({ where: { identifier } });
      return;
    }
    this.memStore.verifications.delete(identifier);
  }

  /** Webhook deliveries in RETRYING state whose next attempt is due. */
  async listDueWebhookRetries(now: Date = new Date(), limit = 100): Promise<WebhookDeliveryRecord[]> {
    if (await this.checkPrisma()) {
      const rows = await prisma.webhookDelivery.findMany({
        where: { status: 'RETRYING', nextRetryAt: { lte: now } },
        orderBy: { nextRetryAt: 'asc' },
        take: limit,
      });
      return rows.map((d) => ({ ...d, payload: d.payload as any }));
    }
    return Array.from(this.memStore.webhookDeliveries.values())
      .filter((d) => d.status === 'RETRYING' && d.nextRetryAt && d.nextRetryAt <= now)
      .slice(0, limit);
  }
}

function toUploadRecord(row: any): UploadRecord {
  return { ...row, metadata: (row.metadata ?? undefined) as Record<string, any> | undefined };
}

function toHackathonRecord(row: any): HackathonSubmissionRecord {
  return {
    ...row,
    sourceCodeType: row.sourceCodeType as HackathonSubmissionRecord['sourceCodeType'],
    apiUsageEndpoints: Array.isArray(row.apiUsageEndpoints) ? (row.apiUsageEndpoints as string[]) : [],
    status: row.status as HackathonSubmissionRecord['status'],
  };
}

export const db = new DataStore();
