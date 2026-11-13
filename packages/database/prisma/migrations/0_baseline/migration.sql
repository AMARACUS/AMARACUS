-- CreateTable
CREATE TABLE "user" (
    "id" TEXT NOT NULL,
    "name" TEXT,
    "email" TEXT NOT NULL,
    "emailVerified" BOOLEAN NOT NULL DEFAULT false,
    "image" TEXT,
    "passwordHash" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "session" (
    "id" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "token" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "userId" TEXT NOT NULL,
    "activeOrganizationId" TEXT,

    CONSTRAINT "session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "account" (
    "id" TEXT NOT NULL,
    "accountId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "accessToken" TEXT,
    "refreshToken" TEXT,
    "idToken" TEXT,
    "accessTokenExpiresAt" TIMESTAMP(3),
    "refreshTokenExpiresAt" TIMESTAMP(3),
    "scope" TEXT,
    "password" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "account_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "verification" (
    "id" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3),

    CONSTRAINT "verification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "organization" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT,
    "logo" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "metadata" TEXT,

    CONSTRAINT "organization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "member" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'member',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "member_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "invitation" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "role" TEXT DEFAULT 'member',
    "status" TEXT NOT NULL DEFAULT 'pending',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "inviterId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "invitation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "project" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "description" TEXT,
    "organizationId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "project_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "environment" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "environment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "api_credential" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT,
    "projectId" TEXT,
    "environmentId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "prefix" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "scopes" JSONB,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "createdBy" TEXT,
    "lastUsedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "api_credential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_event" (
    "id" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "actorId" TEXT,
    "organizationId" TEXT,
    "resourceId" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cryptographic_key" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "purpose" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "currentVersion" INTEGER NOT NULL DEFAULT 1,
    "expiresAt" TIMESTAMP(3),
    "activatedAt" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "rotatedAt" TIMESTAMP(3),
    "disabledAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "scheduledDeletionAt" TIMESTAMP(3),
    "destroyedAt" TIMESTAMP(3),
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "cryptographic_key_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cryptographic_key_version" (
    "id" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "providerKeyId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "publicKey" TEXT,
    "encryptedKeyMaterial" TEXT,
    "keyFingerprint" TEXT,
    "activatedAt" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),
    "destroyedAt" TIMESTAMP(3),
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "cryptographic_key_version_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "customer_key_provider" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "displayName" TEXT,
    "providerType" TEXT NOT NULL,
    "resourceType" TEXT NOT NULL DEFAULT 'KEY_VAULT',
    "ownershipType" TEXT NOT NULL DEFAULT 'CUSTOMER_MANAGED',
    "vaultUrl" TEXT NOT NULL,
    "hsmUrl" TEXT,
    "resourceId" TEXT,
    "authType" TEXT NOT NULL DEFAULT 'SERVICE_PRINCIPAL',
    "authenticationMethod" TEXT NOT NULL DEFAULT 'SERVICE_PRINCIPAL',
    "encryptedAuthConfig" TEXT,
    "status" TEXT NOT NULL DEFAULT 'CONNECTED',
    "connectionStatus" TEXT NOT NULL DEFAULT 'CONNECTED',
    "onboardingState" TEXT NOT NULL DEFAULT 'CONFIGURED',
    "capabilityDiscoveryStatus" TEXT NOT NULL DEFAULT 'NOT_STARTED',
    "isHsmBacked" BOOLEAN NOT NULL DEFAULT false,
    "capabilities" JSONB,
    "lastHealthCheckAt" TIMESTAMP(3),
    "healthStatus" TEXT,
    "healthMessage" TEXT,
    "lastHealthCheckError" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "customer_key_provider_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "customer_registered_key" (
    "id" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "keyIdentifier" TEXT NOT NULL,
    "displayName" TEXT,
    "keyVaultUrl" TEXT NOT NULL,
    "keyType" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "purpose" TEXT NOT NULL,
    "ownershipType" TEXT NOT NULL DEFAULT 'CUSTOMER_MANAGED',
    "isHsmBacked" BOOLEAN NOT NULL DEFAULT false,
    "hsmBackedStatus" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "keyState" TEXT NOT NULL DEFAULT 'ACTIVE',
    "currentVersion" TEXT NOT NULL,
    "publicKey" TEXT,
    "keyFingerprint" TEXT,
    "operations" JSONB,
    "capabilities" JSONB,
    "lastSyncedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastDiscoveredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "customer_registered_key_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "customer_key_version" (
    "id" TEXT NOT NULL,
    "registeredKeyId" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "publicKey" TEXT,
    "keyFingerprint" TEXT,
    "isCurrent" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),

    CONSTRAINT "customer_key_version_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "certificate_authority" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "subject" TEXT NOT NULL,
    "issuer" TEXT NOT NULL,
    "parentAuthorityId" TEXT,
    "keyReference" TEXT NOT NULL,
    "keyAlgorithm" TEXT NOT NULL,
    "signatureAlgorithm" TEXT NOT NULL,
    "certificatePem" TEXT NOT NULL,
    "serialNumber" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "notBefore" TIMESTAMP(3) NOT NULL,
    "notAfter" TIMESTAMP(3) NOT NULL,
    "pathLenConstraint" INTEGER,
    "crlDistributionPoint" TEXT,
    "ocspUrl" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "certificate_authority_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "certificate" (
    "id" TEXT NOT NULL,
    "name" TEXT,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "authorityId" TEXT,
    "keyReference" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "issuer" TEXT NOT NULL,
    "serialNumber" TEXT NOT NULL,
    "certificateType" TEXT NOT NULL,
    "keyAlgorithm" TEXT NOT NULL,
    "signatureAlgorithm" TEXT NOT NULL,
    "publicKeyAlgorithm" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "notBefore" TIMESTAMP(3) NOT NULL,
    "notAfter" TIMESTAMP(3) NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "fingerprintSha1" TEXT,
    "certificatePem" TEXT NOT NULL,
    "chainPem" TEXT,
    "chainReference" TEXT,
    "san" JSONB,
    "keyUsage" JSONB,
    "extendedKeyUsage" JSONB,
    "renewalOfId" TEXT,
    "replacedById" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "certificate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "certificate_request" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "environmentId" TEXT NOT NULL,
    "keyReference" TEXT,
    "subject" TEXT NOT NULL,
    "csrPem" TEXT NOT NULL,
    "publicKey" TEXT,
    "keyAlgorithm" TEXT NOT NULL,
    "signatureAlgorithm" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "san" JSONB,
    "keyUsage" JSONB,
    "extendedKeyUsage" JSONB,
    "certificateId" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "certificate_request_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "certificate_revocation" (
    "id" TEXT NOT NULL,
    "certificateId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "reason" TEXT NOT NULL DEFAULT 'UNSPECIFIED',
    "revokedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedBy" TEXT,
    "invalidityDate" TIMESTAMP(3),
    "comment" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "certificate_revocation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "crypto_asset" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT,
    "environmentId" TEXT,
    "assetType" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "confidence" TEXT NOT NULL DEFAULT 'HIGH',
    "algorithm" TEXT,
    "provider" TEXT,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "quantumStatus" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "fingerprint" TEXT,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "crypto_asset_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "crypto_relationship" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "sourceAssetId" TEXT NOT NULL,
    "targetAssetId" TEXT NOT NULL,
    "relationshipType" TEXT NOT NULL,
    "confidence" TEXT NOT NULL DEFAULT 'HIGH',
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "crypto_relationship_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "crypto_finding" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT,
    "environmentId" TEXT,
    "affectedAssetId" TEXT,
    "severity" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "evidence" JSONB,
    "policySource" TEXT,
    "firstDetectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastDetectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "remediationGuidance" TEXT,
    "resolvedBy" TEXT,
    "resolvedAt" TIMESTAMP(3),
    "resolutionComment" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "crypto_finding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "crypto_inventory_snapshot" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "snapshotDate" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "totalAssets" INTEGER NOT NULL DEFAULT 0,
    "assetsByType" JSONB,
    "findingsBySeverity" JSONB,
    "quantumStatusSummary" JSONB,
    "assetFingerprints" JSONB,
    "drift" JSONB,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "crypto_inventory_snapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "crypto_migration_plan" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "affectedAssetIds" JSONB NOT NULL,
    "currentAlgorithm" TEXT NOT NULL,
    "targetAlgorithm" TEXT NOT NULL,
    "migrationStrategy" TEXT NOT NULL,
    "dependencies" JSONB,
    "blockers" JSONB,
    "owner" TEXT,
    "environmentId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'NOT_STARTED',
    "validationRequirements" JSONB,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "crypto_migration_plan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "zk_circuit" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT,
    "environmentId" TEXT,
    "name" TEXT NOT NULL,
    "version" TEXT NOT NULL DEFAULT '1.0.0',
    "description" TEXT,
    "provingSystem" TEXT NOT NULL,
    "publicInputsSchema" JSONB NOT NULL,
    "privateInputsSchema" JSONB NOT NULL,
    "constraintsDescription" TEXT NOT NULL,
    "verificationKey" JSONB NOT NULL,
    "provingKeyMetadata" JSONB,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "zk_circuit_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "zk_proof_record" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "circuitId" TEXT NOT NULL,
    "circuitVersion" TEXT NOT NULL,
    "publicInputs" JSONB NOT NULL,
    "proofData" JSONB NOT NULL,
    "verified" BOOLEAN NOT NULL DEFAULT false,
    "durationMs" INTEGER NOT NULL DEFAULT 0,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "zk_proof_record_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "fhe_key" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT,
    "environmentId" TEXT,
    "scheme" TEXT NOT NULL DEFAULT 'BFV',
    "polyModulusDegree" INTEGER NOT NULL DEFAULT 4096,
    "publicKeyBase64" TEXT NOT NULL,
    "relinKeysBase64" TEXT,
    "encryptedSecretKey" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "fhe_key_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mpc_session" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT,
    "environmentId" TEXT,
    "title" TEXT NOT NULL,
    "protocol" TEXT NOT NULL DEFAULT 'ADDITIVE_SECRET_SHARING',
    "operation" TEXT NOT NULL DEFAULT 'SECURE_SUM',
    "requiredParties" INTEGER NOT NULL DEFAULT 2,
    "threshold" INTEGER NOT NULL DEFAULT 2,
    "status" TEXT NOT NULL DEFAULT 'WAITING_FOR_PARTIES',
    "currentRound" INTEGER NOT NULL DEFAULT 0,
    "totalRounds" INTEGER NOT NULL DEFAULT 2,
    "result" JSONB,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "mpc_session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mpc_party" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "partyId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'INPUT_PARTY',
    "hasSubmittedInput" BOOLEAN NOT NULL DEFAULT false,
    "blindedShareHash" TEXT,
    "joinedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "mpc_party_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "threshold_key" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT,
    "environmentId" TEXT,
    "name" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL DEFAULT 'ED25519_FROST',
    "threshold" INTEGER NOT NULL,
    "totalParticipants" INTEGER NOT NULL,
    "groupPublicKey" TEXT NOT NULL,
    "participants" JSONB NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "threshold_key_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "threshold_session" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "operation" TEXT NOT NULL DEFAULT 'THRESHOLD_SIGN',
    "messageToSign" TEXT,
    "payloadToAuthorize" TEXT,
    "threshold" INTEGER NOT NULL,
    "totalParticipants" INTEGER NOT NULL,
    "approvals" JSONB NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING_APPROVALS',
    "combinedResult" JSONB,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "threshold_session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webhook_endpoint" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "description" TEXT,
    "secretHash" TEXT NOT NULL,
    "secretPrefix" TEXT NOT NULL,
    "events" JSONB NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "failureCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "webhook_endpoint_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webhook_delivery" (
    "id" TEXT NOT NULL,
    "endpointId" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "responseStatus" INTEGER,
    "responseBody" TEXT,
    "durationMs" INTEGER,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "nextRetryAt" TIMESTAMP(3),
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "webhook_delivery_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "async_job" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT,
    "environmentId" TEXT,
    "type" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'QUEUED',
    "progress" INTEGER NOT NULL DEFAULT 0,
    "input" JSONB,
    "result" JSONB,
    "error" TEXT,
    "durationMs" INTEGER,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "async_job_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "api_usage_record" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT,
    "environmentId" TEXT,
    "credentialId" TEXT,
    "endpoint" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "statusCode" INTEGER NOT NULL,
    "durationMs" INTEGER NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "api_usage_record_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cryptographic_operation" (
    "id" TEXT NOT NULL,
    "requestId" TEXT,
    "idempotencyKey" TEXT,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT,
    "environmentId" TEXT,
    "operationType" TEXT NOT NULL,
    "algorithm" TEXT,
    "keyId" TEXT,
    "providerId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'REQUESTED',
    "retryCount" INTEGER NOT NULL DEFAULT 0,
    "durationMs" INTEGER,
    "metadata" JSONB,
    "result" JSONB,
    "error" JSONB,
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "cryptographic_operation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "billing_customer" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "polarCustomerId" TEXT,
    "email" TEXT,
    "name" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "billing_customer_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "billing_subscription" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "polarSubscriptionId" TEXT,
    "plan" TEXT NOT NULL DEFAULT 'FREE',
    "status" TEXT NOT NULL DEFAULT 'INCOMPLETE',
    "currentPeriodStart" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "currentPeriodEnd" TIMESTAMP(3),
    "cancelAtPeriodEnd" BOOLEAN NOT NULL DEFAULT false,
    "canceledAt" TIMESTAMP(3),
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "billing_subscription_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "billing_usage" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "periodStart" TIMESTAMP(3) NOT NULL,
    "periodEnd" TIMESTAMP(3) NOT NULL,
    "operationCount" INTEGER NOT NULL DEFAULT 0,
    "includedAllowance" INTEGER NOT NULL DEFAULT 0,
    "overageCount" INTEGER NOT NULL DEFAULT 0,
    "estimatedCostCents" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "billing_usage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "billing_usage_event" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "operationId" TEXT NOT NULL,
    "operationType" TEXT NOT NULL,
    "quantity" INTEGER NOT NULL DEFAULT 1,
    "keyId" TEXT,
    "projectId" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reportedToPolar" BOOLEAN NOT NULL DEFAULT false,
    "polarEventId" TEXT,

    CONSTRAINT "billing_usage_event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "billing_safety_state" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "circuitBreakerStatus" TEXT NOT NULL DEFAULT 'NORMAL',
    "opsPerMinute" INTEGER NOT NULL DEFAULT 0,
    "opsPerHour" INTEGER NOT NULL DEFAULT 0,
    "opsPerDay" INTEGER NOT NULL DEFAULT 0,
    "lastWindowReset" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "paygSpendingLimitCents" INTEGER NOT NULL DEFAULT 25000,
    "alertThresholdPercent" INTEGER NOT NULL DEFAULT 80,
    "autoHaltEnabled" BOOLEAN NOT NULL DEFAULT true,
    "overagePolicy" TEXT NOT NULL DEFAULT 'HARD_STOP',
    "authorizedOverageSpendingLimitCents" INTEGER NOT NULL DEFAULT 0,
    "lastAlertSentAt" TIMESTAMP(3),
    "suspensionReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "billing_safety_state_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "billing_webhook_event" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "processed" BOOLEAN NOT NULL DEFAULT false,
    "processedAt" TIMESTAMP(3),
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "billing_webhook_event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cryptographic_policy" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "currentVersion" INTEGER NOT NULL DEFAULT 1,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "enforcementMode" TEXT NOT NULL DEFAULT 'ENFORCE',
    "rules" JSONB NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "cryptographic_policy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cryptographic_policy_version" (
    "id" TEXT NOT NULL,
    "policyId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "rules" JSONB NOT NULL,
    "changeSummary" TEXT,
    "actorId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "cryptographic_policy_version_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cryptographic_policy_assignment" (
    "id" TEXT NOT NULL,
    "policyId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "scopeType" TEXT NOT NULL,
    "scopeId" TEXT NOT NULL,
    "priority" INTEGER NOT NULL DEFAULT 100,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "cryptographic_policy_assignment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "team" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "team_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "team_member" (
    "id" TEXT NOT NULL,
    "teamId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'MEMBER',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "team_member_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "service_identity" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT,
    "environmentId" TEXT,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "scopes" JSONB,
    "prefix" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "createdBy" TEXT,
    "lastUsedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "service_identity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "configuration_drift" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "resourceType" TEXT NOT NULL,
    "resourceId" TEXT NOT NULL,
    "expectedState" JSONB NOT NULL,
    "actualState" JSONB NOT NULL,
    "driftSummary" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'DETECTED',
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolvedAt" TIMESTAMP(3),

    CONSTRAINT "configuration_drift_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "organization_security_setting" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "enforceMfa" BOOLEAN NOT NULL DEFAULT false,
    "allowedIpRanges" JSONB,
    "defaultKeyRotationDays" INTEGER NOT NULL DEFAULT 90,
    "requireHsmInProduction" BOOLEAN NOT NULL DEFAULT false,
    "requirePqcInProduction" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "organization_security_setting_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "user_email_key" ON "user"("email");

-- CreateIndex
CREATE UNIQUE INDEX "session_token_key" ON "session"("token");

-- CreateIndex
CREATE UNIQUE INDEX "organization_slug_key" ON "organization"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "member_userId_organizationId_key" ON "member"("userId", "organizationId");

-- CreateIndex
CREATE INDEX "project_organizationId_idx" ON "project"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "project_organizationId_slug_key" ON "project"("organizationId", "slug");

-- CreateIndex
CREATE INDEX "environment_projectId_idx" ON "environment"("projectId");

-- CreateIndex
CREATE UNIQUE INDEX "environment_projectId_slug_key" ON "environment"("projectId", "slug");

-- CreateIndex
CREATE UNIQUE INDEX "api_credential_keyHash_key" ON "api_credential"("keyHash");

-- CreateIndex
CREATE INDEX "api_credential_organizationId_idx" ON "api_credential"("organizationId");

-- CreateIndex
CREATE INDEX "api_credential_environmentId_idx" ON "api_credential"("environmentId");

-- CreateIndex
CREATE INDEX "api_credential_keyHash_idx" ON "api_credential"("keyHash");

-- CreateIndex
CREATE INDEX "api_credential_status_idx" ON "api_credential"("status");

-- CreateIndex
CREATE INDEX "audit_event_organizationId_createdAt_idx" ON "audit_event"("organizationId", "createdAt");

-- CreateIndex
CREATE INDEX "cryptographic_key_organizationId_idx" ON "cryptographic_key"("organizationId");

-- CreateIndex
CREATE INDEX "cryptographic_key_projectId_idx" ON "cryptographic_key"("projectId");

-- CreateIndex
CREATE INDEX "cryptographic_key_environmentId_idx" ON "cryptographic_key"("environmentId");

-- CreateIndex
CREATE INDEX "cryptographic_key_status_idx" ON "cryptographic_key"("status");

-- CreateIndex
CREATE UNIQUE INDEX "cryptographic_key_organizationId_projectId_environmentId_na_key" ON "cryptographic_key"("organizationId", "projectId", "environmentId", "name");

-- CreateIndex
CREATE INDEX "cryptographic_key_version_keyId_idx" ON "cryptographic_key_version"("keyId");

-- CreateIndex
CREATE INDEX "cryptographic_key_version_status_idx" ON "cryptographic_key_version"("status");

-- CreateIndex
CREATE UNIQUE INDEX "cryptographic_key_version_keyId_version_key" ON "cryptographic_key_version"("keyId", "version");

-- CreateIndex
CREATE INDEX "customer_key_provider_organizationId_idx" ON "customer_key_provider"("organizationId");

-- CreateIndex
CREATE INDEX "customer_key_provider_projectId_idx" ON "customer_key_provider"("projectId");

-- CreateIndex
CREATE INDEX "customer_key_provider_environmentId_idx" ON "customer_key_provider"("environmentId");

-- CreateIndex
CREATE INDEX "customer_key_provider_providerType_idx" ON "customer_key_provider"("providerType");

-- CreateIndex
CREATE UNIQUE INDEX "customer_key_provider_organizationId_projectId_environmentI_key" ON "customer_key_provider"("organizationId", "projectId", "environmentId", "name");

-- CreateIndex
CREATE INDEX "customer_registered_key_organizationId_idx" ON "customer_registered_key"("organizationId");

-- CreateIndex
CREATE INDEX "customer_registered_key_projectId_idx" ON "customer_registered_key"("projectId");

-- CreateIndex
CREATE INDEX "customer_registered_key_environmentId_idx" ON "customer_registered_key"("environmentId");

-- CreateIndex
CREATE INDEX "customer_registered_key_providerId_idx" ON "customer_registered_key"("providerId");

-- CreateIndex
CREATE INDEX "customer_registered_key_status_idx" ON "customer_registered_key"("status");

-- CreateIndex
CREATE UNIQUE INDEX "customer_registered_key_providerId_keyIdentifier_key" ON "customer_registered_key"("providerId", "keyIdentifier");

-- CreateIndex
CREATE INDEX "customer_key_version_registeredKeyId_idx" ON "customer_key_version"("registeredKeyId");

-- CreateIndex
CREATE UNIQUE INDEX "customer_key_version_registeredKeyId_version_key" ON "customer_key_version"("registeredKeyId", "version");

-- CreateIndex
CREATE INDEX "certificate_authority_organizationId_idx" ON "certificate_authority"("organizationId");

-- CreateIndex
CREATE INDEX "certificate_authority_projectId_idx" ON "certificate_authority"("projectId");

-- CreateIndex
CREATE INDEX "certificate_authority_environmentId_idx" ON "certificate_authority"("environmentId");

-- CreateIndex
CREATE INDEX "certificate_authority_status_idx" ON "certificate_authority"("status");

-- CreateIndex
CREATE UNIQUE INDEX "certificate_authority_organizationId_projectId_environmentI_key" ON "certificate_authority"("organizationId", "projectId", "environmentId", "name");

-- CreateIndex
CREATE INDEX "certificate_organizationId_idx" ON "certificate"("organizationId");

-- CreateIndex
CREATE INDEX "certificate_projectId_idx" ON "certificate"("projectId");

-- CreateIndex
CREATE INDEX "certificate_environmentId_idx" ON "certificate"("environmentId");

-- CreateIndex
CREATE INDEX "certificate_authorityId_idx" ON "certificate"("authorityId");

-- CreateIndex
CREATE INDEX "certificate_keyReference_idx" ON "certificate"("keyReference");

-- CreateIndex
CREATE INDEX "certificate_status_idx" ON "certificate"("status");

-- CreateIndex
CREATE INDEX "certificate_fingerprint_idx" ON "certificate"("fingerprint");

-- CreateIndex
CREATE UNIQUE INDEX "certificate_organizationId_serialNumber_key" ON "certificate"("organizationId", "serialNumber");

-- CreateIndex
CREATE INDEX "certificate_request_organizationId_idx" ON "certificate_request"("organizationId");

-- CreateIndex
CREATE INDEX "certificate_request_projectId_idx" ON "certificate_request"("projectId");

-- CreateIndex
CREATE INDEX "certificate_request_environmentId_idx" ON "certificate_request"("environmentId");

-- CreateIndex
CREATE INDEX "certificate_request_status_idx" ON "certificate_request"("status");

-- CreateIndex
CREATE UNIQUE INDEX "certificate_revocation_certificateId_key" ON "certificate_revocation"("certificateId");

-- CreateIndex
CREATE INDEX "certificate_revocation_organizationId_idx" ON "certificate_revocation"("organizationId");

-- CreateIndex
CREATE INDEX "certificate_revocation_reason_idx" ON "certificate_revocation"("reason");

-- CreateIndex
CREATE INDEX "crypto_asset_organizationId_idx" ON "crypto_asset"("organizationId");

-- CreateIndex
CREATE INDEX "crypto_asset_assetType_idx" ON "crypto_asset"("assetType");

-- CreateIndex
CREATE INDEX "crypto_asset_algorithm_idx" ON "crypto_asset"("algorithm");

-- CreateIndex
CREATE INDEX "crypto_asset_quantumStatus_idx" ON "crypto_asset"("quantumStatus");

-- CreateIndex
CREATE INDEX "crypto_asset_status_idx" ON "crypto_asset"("status");

-- CreateIndex
CREATE UNIQUE INDEX "crypto_asset_organizationId_assetType_name_source_key" ON "crypto_asset"("organizationId", "assetType", "name", "source");

-- CreateIndex
CREATE INDEX "crypto_relationship_organizationId_idx" ON "crypto_relationship"("organizationId");

-- CreateIndex
CREATE INDEX "crypto_relationship_sourceAssetId_idx" ON "crypto_relationship"("sourceAssetId");

-- CreateIndex
CREATE INDEX "crypto_relationship_targetAssetId_idx" ON "crypto_relationship"("targetAssetId");

-- CreateIndex
CREATE INDEX "crypto_relationship_relationshipType_idx" ON "crypto_relationship"("relationshipType");

-- CreateIndex
CREATE UNIQUE INDEX "crypto_relationship_organizationId_sourceAssetId_targetAsse_key" ON "crypto_relationship"("organizationId", "sourceAssetId", "targetAssetId", "relationshipType");

-- CreateIndex
CREATE INDEX "crypto_finding_organizationId_idx" ON "crypto_finding"("organizationId");

-- CreateIndex
CREATE INDEX "crypto_finding_affectedAssetId_idx" ON "crypto_finding"("affectedAssetId");

-- CreateIndex
CREATE INDEX "crypto_finding_severity_idx" ON "crypto_finding"("severity");

-- CreateIndex
CREATE INDEX "crypto_finding_status_idx" ON "crypto_finding"("status");

-- CreateIndex
CREATE INDEX "crypto_finding_category_idx" ON "crypto_finding"("category");

-- CreateIndex
CREATE INDEX "crypto_inventory_snapshot_organizationId_idx" ON "crypto_inventory_snapshot"("organizationId");

-- CreateIndex
CREATE INDEX "crypto_inventory_snapshot_snapshotDate_idx" ON "crypto_inventory_snapshot"("snapshotDate");

-- CreateIndex
CREATE INDEX "crypto_migration_plan_organizationId_idx" ON "crypto_migration_plan"("organizationId");

-- CreateIndex
CREATE INDEX "crypto_migration_plan_status_idx" ON "crypto_migration_plan"("status");

-- CreateIndex
CREATE INDEX "zk_circuit_organizationId_idx" ON "zk_circuit"("organizationId");

-- CreateIndex
CREATE INDEX "zk_circuit_status_idx" ON "zk_circuit"("status");

-- CreateIndex
CREATE UNIQUE INDEX "zk_circuit_organizationId_name_version_key" ON "zk_circuit"("organizationId", "name", "version");

-- CreateIndex
CREATE INDEX "zk_proof_record_organizationId_idx" ON "zk_proof_record"("organizationId");

-- CreateIndex
CREATE INDEX "zk_proof_record_circuitId_idx" ON "zk_proof_record"("circuitId");

-- CreateIndex
CREATE INDEX "fhe_key_organizationId_idx" ON "fhe_key"("organizationId");

-- CreateIndex
CREATE INDEX "fhe_key_scheme_idx" ON "fhe_key"("scheme");

-- CreateIndex
CREATE INDEX "mpc_session_organizationId_idx" ON "mpc_session"("organizationId");

-- CreateIndex
CREATE INDEX "mpc_session_status_idx" ON "mpc_session"("status");

-- CreateIndex
CREATE INDEX "mpc_party_sessionId_idx" ON "mpc_party"("sessionId");

-- CreateIndex
CREATE UNIQUE INDEX "mpc_party_sessionId_partyId_key" ON "mpc_party"("sessionId", "partyId");

-- CreateIndex
CREATE INDEX "threshold_key_organizationId_idx" ON "threshold_key"("organizationId");

-- CreateIndex
CREATE INDEX "threshold_session_organizationId_idx" ON "threshold_session"("organizationId");

-- CreateIndex
CREATE INDEX "threshold_session_keyId_idx" ON "threshold_session"("keyId");

-- CreateIndex
CREATE INDEX "threshold_session_status_idx" ON "threshold_session"("status");

-- CreateIndex
CREATE INDEX "webhook_endpoint_organizationId_idx" ON "webhook_endpoint"("organizationId");

-- CreateIndex
CREATE INDEX "webhook_endpoint_status_idx" ON "webhook_endpoint"("status");

-- CreateIndex
CREATE INDEX "webhook_delivery_endpointId_idx" ON "webhook_delivery"("endpointId");

-- CreateIndex
CREATE INDEX "webhook_delivery_status_idx" ON "webhook_delivery"("status");

-- CreateIndex
CREATE INDEX "async_job_organizationId_idx" ON "async_job"("organizationId");

-- CreateIndex
CREATE INDEX "async_job_status_idx" ON "async_job"("status");

-- CreateIndex
CREATE INDEX "api_usage_record_organizationId_idx" ON "api_usage_record"("organizationId");

-- CreateIndex
CREATE INDEX "api_usage_record_credentialId_idx" ON "api_usage_record"("credentialId");

-- CreateIndex
CREATE INDEX "api_usage_record_timestamp_idx" ON "api_usage_record"("timestamp");

-- CreateIndex
CREATE INDEX "cryptographic_operation_organizationId_idx" ON "cryptographic_operation"("organizationId");

-- CreateIndex
CREATE INDEX "cryptographic_operation_requestId_idx" ON "cryptographic_operation"("requestId");

-- CreateIndex
CREATE INDEX "cryptographic_operation_idempotencyKey_idx" ON "cryptographic_operation"("idempotencyKey");

-- CreateIndex
CREATE INDEX "cryptographic_operation_status_idx" ON "cryptographic_operation"("status");

-- CreateIndex
CREATE INDEX "cryptographic_operation_operationType_idx" ON "cryptographic_operation"("operationType");

-- CreateIndex
CREATE UNIQUE INDEX "billing_customer_organizationId_key" ON "billing_customer"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "billing_customer_polarCustomerId_key" ON "billing_customer"("polarCustomerId");

-- CreateIndex
CREATE INDEX "billing_customer_organizationId_idx" ON "billing_customer"("organizationId");

-- CreateIndex
CREATE INDEX "billing_customer_polarCustomerId_idx" ON "billing_customer"("polarCustomerId");

-- CreateIndex
CREATE UNIQUE INDEX "billing_subscription_polarSubscriptionId_key" ON "billing_subscription"("polarSubscriptionId");

-- CreateIndex
CREATE INDEX "billing_subscription_organizationId_idx" ON "billing_subscription"("organizationId");

-- CreateIndex
CREATE INDEX "billing_subscription_polarSubscriptionId_idx" ON "billing_subscription"("polarSubscriptionId");

-- CreateIndex
CREATE INDEX "billing_subscription_status_idx" ON "billing_subscription"("status");

-- CreateIndex
CREATE INDEX "billing_usage_organizationId_idx" ON "billing_usage"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "billing_usage_organizationId_periodStart_periodEnd_key" ON "billing_usage"("organizationId", "periodStart", "periodEnd");

-- CreateIndex
CREATE UNIQUE INDEX "billing_usage_event_operationId_key" ON "billing_usage_event"("operationId");

-- CreateIndex
CREATE INDEX "billing_usage_event_organizationId_idx" ON "billing_usage_event"("organizationId");

-- CreateIndex
CREATE INDEX "billing_usage_event_operationId_idx" ON "billing_usage_event"("operationId");

-- CreateIndex
CREATE INDEX "billing_usage_event_timestamp_idx" ON "billing_usage_event"("timestamp");

-- CreateIndex
CREATE UNIQUE INDEX "billing_safety_state_organizationId_key" ON "billing_safety_state"("organizationId");

-- CreateIndex
CREATE INDEX "billing_safety_state_organizationId_idx" ON "billing_safety_state"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "billing_webhook_event_eventId_key" ON "billing_webhook_event"("eventId");

-- CreateIndex
CREATE INDEX "billing_webhook_event_eventId_idx" ON "billing_webhook_event"("eventId");

-- CreateIndex
CREATE INDEX "billing_webhook_event_eventType_idx" ON "billing_webhook_event"("eventType");

-- CreateIndex
CREATE INDEX "cryptographic_policy_organizationId_idx" ON "cryptographic_policy"("organizationId");

-- CreateIndex
CREATE INDEX "cryptographic_policy_organizationId_name_idx" ON "cryptographic_policy"("organizationId", "name");

-- CreateIndex
CREATE INDEX "cryptographic_policy_version_policyId_idx" ON "cryptographic_policy_version"("policyId");

-- CreateIndex
CREATE UNIQUE INDEX "cryptographic_policy_version_policyId_version_key" ON "cryptographic_policy_version"("policyId", "version");

-- CreateIndex
CREATE INDEX "cryptographic_policy_assignment_organizationId_idx" ON "cryptographic_policy_assignment"("organizationId");

-- CreateIndex
CREATE INDEX "cryptographic_policy_assignment_scopeType_scopeId_idx" ON "cryptographic_policy_assignment"("scopeType", "scopeId");

-- CreateIndex
CREATE UNIQUE INDEX "cryptographic_policy_assignment_organizationId_scopeType_sc_key" ON "cryptographic_policy_assignment"("organizationId", "scopeType", "scopeId");

-- CreateIndex
CREATE INDEX "team_organizationId_idx" ON "team"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "team_organizationId_name_key" ON "team"("organizationId", "name");

-- CreateIndex
CREATE INDEX "team_member_teamId_idx" ON "team_member"("teamId");

-- CreateIndex
CREATE INDEX "team_member_userId_idx" ON "team_member"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "team_member_teamId_userId_key" ON "team_member"("teamId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "service_identity_keyHash_key" ON "service_identity"("keyHash");

-- CreateIndex
CREATE INDEX "service_identity_organizationId_idx" ON "service_identity"("organizationId");

-- CreateIndex
CREATE INDEX "service_identity_projectId_idx" ON "service_identity"("projectId");

-- CreateIndex
CREATE INDEX "service_identity_environmentId_idx" ON "service_identity"("environmentId");

-- CreateIndex
CREATE INDEX "service_identity_status_idx" ON "service_identity"("status");

-- CreateIndex
CREATE INDEX "configuration_drift_organizationId_idx" ON "configuration_drift"("organizationId");

-- CreateIndex
CREATE INDEX "configuration_drift_resourceType_resourceId_idx" ON "configuration_drift"("resourceType", "resourceId");

-- CreateIndex
CREATE INDEX "configuration_drift_status_idx" ON "configuration_drift"("status");

-- CreateIndex
CREATE UNIQUE INDEX "organization_security_setting_organizationId_key" ON "organization_security_setting"("organizationId");

-- AddForeignKey
ALTER TABLE "session" ADD CONSTRAINT "session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account" ADD CONSTRAINT "account_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "member" ADD CONSTRAINT "member_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "member" ADD CONSTRAINT "member_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "invitation" ADD CONSTRAINT "invitation_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "invitation" ADD CONSTRAINT "invitation_inviterId_fkey" FOREIGN KEY ("inviterId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "project" ADD CONSTRAINT "project_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "environment" ADD CONSTRAINT "environment_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "api_credential" ADD CONSTRAINT "api_credential_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "api_credential" ADD CONSTRAINT "api_credential_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "environment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_event" ADD CONSTRAINT "audit_event_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cryptographic_key" ADD CONSTRAINT "cryptographic_key_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cryptographic_key" ADD CONSTRAINT "cryptographic_key_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cryptographic_key" ADD CONSTRAINT "cryptographic_key_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "environment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cryptographic_key_version" ADD CONSTRAINT "cryptographic_key_version_keyId_fkey" FOREIGN KEY ("keyId") REFERENCES "cryptographic_key"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "customer_key_provider" ADD CONSTRAINT "customer_key_provider_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "customer_key_provider" ADD CONSTRAINT "customer_key_provider_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "customer_key_provider" ADD CONSTRAINT "customer_key_provider_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "environment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "customer_registered_key" ADD CONSTRAINT "customer_registered_key_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "customer_key_provider"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "customer_registered_key" ADD CONSTRAINT "customer_registered_key_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "customer_registered_key" ADD CONSTRAINT "customer_registered_key_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "customer_registered_key" ADD CONSTRAINT "customer_registered_key_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "environment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "customer_key_version" ADD CONSTRAINT "customer_key_version_registeredKeyId_fkey" FOREIGN KEY ("registeredKeyId") REFERENCES "customer_registered_key"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "certificate_authority" ADD CONSTRAINT "certificate_authority_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "certificate_authority" ADD CONSTRAINT "certificate_authority_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "certificate_authority" ADD CONSTRAINT "certificate_authority_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "environment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "certificate_authority" ADD CONSTRAINT "certificate_authority_parentAuthorityId_fkey" FOREIGN KEY ("parentAuthorityId") REFERENCES "certificate_authority"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "environment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_authorityId_fkey" FOREIGN KEY ("authorityId") REFERENCES "certificate_authority"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "certificate_request" ADD CONSTRAINT "certificate_request_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "certificate_request" ADD CONSTRAINT "certificate_request_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "certificate_request" ADD CONSTRAINT "certificate_request_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "environment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "certificate_revocation" ADD CONSTRAINT "certificate_revocation_certificateId_fkey" FOREIGN KEY ("certificateId") REFERENCES "certificate"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "certificate_revocation" ADD CONSTRAINT "certificate_revocation_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "crypto_asset" ADD CONSTRAINT "crypto_asset_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "crypto_relationship" ADD CONSTRAINT "crypto_relationship_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "crypto_relationship" ADD CONSTRAINT "crypto_relationship_sourceAssetId_fkey" FOREIGN KEY ("sourceAssetId") REFERENCES "crypto_asset"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "crypto_relationship" ADD CONSTRAINT "crypto_relationship_targetAssetId_fkey" FOREIGN KEY ("targetAssetId") REFERENCES "crypto_asset"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "crypto_finding" ADD CONSTRAINT "crypto_finding_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "crypto_finding" ADD CONSTRAINT "crypto_finding_affectedAssetId_fkey" FOREIGN KEY ("affectedAssetId") REFERENCES "crypto_asset"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "crypto_inventory_snapshot" ADD CONSTRAINT "crypto_inventory_snapshot_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "crypto_migration_plan" ADD CONSTRAINT "crypto_migration_plan_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "zk_circuit" ADD CONSTRAINT "zk_circuit_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "zk_proof_record" ADD CONSTRAINT "zk_proof_record_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "zk_proof_record" ADD CONSTRAINT "zk_proof_record_circuitId_fkey" FOREIGN KEY ("circuitId") REFERENCES "zk_circuit"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "fhe_key" ADD CONSTRAINT "fhe_key_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mpc_session" ADD CONSTRAINT "mpc_session_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mpc_party" ADD CONSTRAINT "mpc_party_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "mpc_session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "threshold_key" ADD CONSTRAINT "threshold_key_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "threshold_session" ADD CONSTRAINT "threshold_session_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "threshold_session" ADD CONSTRAINT "threshold_session_keyId_fkey" FOREIGN KEY ("keyId") REFERENCES "threshold_key"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "webhook_endpoint" ADD CONSTRAINT "webhook_endpoint_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "webhook_delivery" ADD CONSTRAINT "webhook_delivery_endpointId_fkey" FOREIGN KEY ("endpointId") REFERENCES "webhook_endpoint"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "async_job" ADD CONSTRAINT "async_job_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "api_usage_record" ADD CONSTRAINT "api_usage_record_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cryptographic_operation" ADD CONSTRAINT "cryptographic_operation_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "billing_customer" ADD CONSTRAINT "billing_customer_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "billing_subscription" ADD CONSTRAINT "billing_subscription_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "billing_usage" ADD CONSTRAINT "billing_usage_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "billing_usage_event" ADD CONSTRAINT "billing_usage_event_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "billing_safety_state" ADD CONSTRAINT "billing_safety_state_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cryptographic_policy" ADD CONSTRAINT "cryptographic_policy_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cryptographic_policy_version" ADD CONSTRAINT "cryptographic_policy_version_policyId_fkey" FOREIGN KEY ("policyId") REFERENCES "cryptographic_policy"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cryptographic_policy_assignment" ADD CONSTRAINT "cryptographic_policy_assignment_policyId_fkey" FOREIGN KEY ("policyId") REFERENCES "cryptographic_policy"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "team" ADD CONSTRAINT "team_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "team_member" ADD CONSTRAINT "team_member_teamId_fkey" FOREIGN KEY ("teamId") REFERENCES "team"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "team_member" ADD CONSTRAINT "team_member_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "service_identity" ADD CONSTRAINT "service_identity_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "service_identity" ADD CONSTRAINT "service_identity_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "service_identity" ADD CONSTRAINT "service_identity_environmentId_fkey" FOREIGN KEY ("environmentId") REFERENCES "environment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "configuration_drift" ADD CONSTRAINT "configuration_drift_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_security_setting" ADD CONSTRAINT "organization_security_setting_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

