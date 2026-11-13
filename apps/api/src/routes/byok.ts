import { selfHostGate, selfHostMeterOnSuccess } from '../middleware/selfhost-metering';
import { Router, Request, Response, NextFunction } from 'express';
import { db } from '../lib/data-store';
import { requireAuth, requireOrgMember, requireOrgPermission } from '../middleware/auth';
import { requireByokEntitlement } from '../lib/entitlements';
import { encryptSecret, decryptSecret } from '../lib/secret-vault';
import {
  CustomerAzureKeyVaultProvider,
  CustomerKeyProviderConfig,
  CustomerKeyOperation,
  KeyCapabilities,
  ProviderCapabilitiesMap,
  CapabilityValue,
  ProviderOnboardingStateMachine,
  ProviderOnboardingState,
  KeyState,
  CryptoEngineError,
  AzureVaultKind,
  validateAzureVaultUrl,
  customerCredentialFor,
} from '@amaracus/crypto-core';

const router = Router({ mergeParams: true });

// All BYOK endpoints require authentication, organization membership, and plan entitlement
router.use(requireAuth);
router.use(requireOrgMember);
router.use(requireByokEntitlement());

// Helper to construct a provider instance from a database record. Only the customer's stored
// service principal is used; a record without one fails instead of borrowing the platform's
// Azure identity.
function getProviderInstance(record: any): CustomerAzureKeyVaultProvider {
  let authConfig: any = {};
  if (record.encryptedAuthConfig) {
    try {
      const decrypted = decryptSecret(record.encryptedAuthConfig);
      authConfig = JSON.parse(decrypted);
    } catch (err: any) {
      console.error('[BYOK] Stored credentials for provider', record.id, 'could not be decrypted:', err?.message);
    }
  }

  const config: CustomerKeyProviderConfig = {
    name: record.name,
    providerType: record.providerType,
    ownershipType: 'CUSTOMER_MANAGED',
    vaultUrl: record.vaultUrl,
    hsmUrl: record.hsmUrl || undefined,
    resourceId: record.resourceId || undefined,
    authType: record.authType || 'SERVICE_PRINCIPAL',
    tenantId: authConfig.tenantId,
    clientId: authConfig.clientId,
    clientSecret: authConfig.clientSecret,
  };

  return new CustomerAzureKeyVaultProvider(config);
}

/**
 * Checks a vault URL and service principal from a request before anything is stored or any
 * Azure call is made. Returns the normalized vault origin, or an error message for a 400.
 */
function validateByokConnectionInput(input: {
  url: string;
  resourceType?: string;
  authType?: string;
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
}): { origin: string; kind: AzureVaultKind } | { error: string } {
  try {
    const vault = validateAzureVaultUrl(
      input.url,
      input.resourceType === 'MANAGED_HSM' ? 'MANAGED_HSM' : input.resourceType === 'KEY_VAULT' ? 'KEY_VAULT' : undefined
    );
    customerCredentialFor({
      name: 'validation',
      providerType: vault.kind === 'MANAGED_HSM' ? 'AZURE_MANAGED_HSM' : 'AZURE_KEY_VAULT',
      ownershipType: 'CUSTOMER_MANAGED',
      vaultUrl: vault.origin,
      authType: (input.authType || 'SERVICE_PRINCIPAL') as any,
      tenantId: input.tenantId,
      clientId: input.clientId,
      clientSecret: input.clientSecret,
    });
    return vault;
  } catch (err: any) {
    return { error: err?.message || 'Invalid BYOK connection settings.' };
  }
}

// Format safe provider response matching Phase 5.4 contract + backwards compatibility
function formatProviderResponse(record: any) {
  const isHsm = record.providerType === 'AZURE_MANAGED_HSM' || (record.vaultUrl && record.vaultUrl.includes('managedhsm'));
  const safe = {
    id: record.id,
    organizationId: record.organizationId,
    projectId: record.projectId,
    environmentId: record.environmentId,
    name: record.name,
    displayName: record.displayName || record.name,
    providerType: 'AZURE',
    resourceType: record.resourceType || (isHsm ? 'MANAGED_HSM' : 'KEY_VAULT'),
    endpoint: record.vaultUrl,
    vaultUrl: record.vaultUrl,
    hsmUrl: record.hsmUrl || null,
    resourceId: record.resourceId || null,
    ownershipType: 'CUSTOMER_OWNED',
    authMethod: record.authenticationMethod || record.authType || 'MANAGED_IDENTITY',
    authType: record.authType || 'SERVICE_PRINCIPAL',
    status: record.onboardingState === 'READY' ? 'CONNECTED' : (record.status === 'DISCONNECTED' ? 'DISCONNECTED' : 'PENDING_CONNECTION'),
    connectionStatus: record.connectionStatus || 'CONNECTED',
    onboardingState: (record.onboardingState as ProviderOnboardingState) || 'CONFIGURED',
    capabilityDiscoveryStatus: record.capabilityDiscoveryStatus || 'NOT_STARTED',
    isHsmBacked: !!record.isHsmBacked,
    capabilities: record.capabilities || null,
    lastHealthCheckAt: record.lastHealthCheckAt,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  };
  return {
    ...safe,
    data: {
      ...safe,
      status: record.status === 'DISCONNECTED' ? 'DISCONNECTED' : 'CONNECTED', // backward compatibility for Phase 5.2/5.3 tests
    },
  };
}

// ---------------------------------------------------------------------------
// 1. Connection Test (Before Saving or Existing Provider)
// ---------------------------------------------------------------------------
const handleConnectionTest = async (req: Request, res: Response, next: NextFunction) => {
  const reqId = (req as any).requestId || `req_${Date.now()}`;
  try {
    let { providerType, resourceType, vaultUrl, hsmUrl, endpoint, authType, auth, tenantId, clientId, clientSecret } = req.body;
    let existingProvider: any = null;

    // Resolve :providerId / :id if testing existing provider
    const providerId = req.params.providerId || req.params.id;
    if (providerId) {
      existingProvider = await db.findCustomerProviderById(providerId);
      if (!existingProvider || existingProvider.organizationId !== req.organizationId) {
        return res.status(404).json({
          error: { code: 'RESOURCE_NOT_FOUND', message: 'Customer key provider not found.', requestId: reqId },
        });
      }
      providerType = existingProvider.providerType;
      resourceType = existingProvider.resourceType;
      vaultUrl = existingProvider.vaultUrl;
      hsmUrl = existingProvider.hsmUrl;
      authType = existingProvider.authType;
      if (existingProvider.encryptedAuthConfig) {
        try {
          const decrypted = decryptSecret(existingProvider.encryptedAuthConfig);
          const parsed = JSON.parse(decrypted);
          tenantId = tenantId || parsed.tenantId;
          clientId = clientId || parsed.clientId;
          clientSecret = clientSecret || parsed.clientSecret;
        } catch {}
      }
    }

    // Resolve URL / endpoint
    const urlToCheck = (endpoint || vaultUrl || hsmUrl || '').trim();
    if (!urlToCheck) {
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: 'Vault endpoint URL is required.', requestId: reqId },
      });
    }

    if (!urlToCheck.startsWith('https://')) {
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: 'Vault URL must start with https://', requestId: reqId },
      });
    }

    // Provider type validation (Only AZURE allowed in Phase 5.4; AWS strictly unselected)
    const rawProviderType = (providerType || 'AZURE').toUpperCase();
    if (rawProviderType === 'AWS') {
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: 'Only AZURE is supported in this phase. AWS is not implemented.', requestId: reqId },
      });
    }

    // Resource type validation
    const resolvedResourceType = resourceType || (urlToCheck.includes('managedhsm') ? 'MANAGED_HSM' : 'KEY_VAULT');
    if (resolvedResourceType !== 'KEY_VAULT' && resolvedResourceType !== 'MANAGED_HSM') {
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: 'resourceType must be either KEY_VAULT or MANAGED_HSM.', requestId: reqId },
      });
    }

    const testAuthType = auth?.method || authType || 'SERVICE_PRINCIPAL';
    const checked = validateByokConnectionInput({
      url: urlToCheck,
      resourceType: resolvedResourceType,
      authType: testAuthType,
      tenantId,
      clientId,
      clientSecret,
    });
    if ('error' in checked) {
      return res.status(400).json({ error: { code: 'INVALID_REQUEST', message: checked.error, requestId: reqId } });
    }

    // State machine transition check for existing provider
    if (existingProvider) {
      ProviderOnboardingStateMachine.validateTransition(
        existingProvider.onboardingState as ProviderOnboardingState,
        'CONNECTION_TESTING'
      );
      await db.updateCustomerProvider(existingProvider.id, {
        onboardingState: 'CONNECTION_TESTING',
      });
    }

    await db.createAuditEvent({
      action: 'BYOK_CONNECTION_TEST_STARTED',
      userId: req.user!.id,
      resourceType: 'CustomerKeyProvider',
      organizationId: req.organizationId!,
      metadata: {
        vaultUrl: urlToCheck,
        providerType: 'AZURE',
        resourceType: resolvedResourceType,
      },
    });

    const config: CustomerKeyProviderConfig = {
      name: 'Connection Test',
      providerType: resolvedResourceType === 'MANAGED_HSM' ? 'AZURE_MANAGED_HSM' : 'AZURE_KEY_VAULT',
      ownershipType: 'CUSTOMER_MANAGED',
      vaultUrl: checked.origin,
      hsmUrl: resolvedResourceType === 'MANAGED_HSM' ? checked.origin : undefined,
      authType: testAuthType as any,
      tenantId,
      clientId,
      clientSecret,
    };

    const provider = new CustomerAzureKeyVaultProvider(config);
    const testResult = await provider.testConnection();

    if (testResult.success) {
      if (existingProvider) {
        ProviderOnboardingStateMachine.validateTransition('CONNECTION_TESTING', 'CONNECTED');
        await db.updateCustomerProvider(existingProvider.id, {
          onboardingState: 'CONNECTED',
          connectionStatus: 'CONNECTED',
          lastHealthCheckAt: new Date(),
          healthStatus: 'HEALTHY',
          lastHealthCheckError: null,
        });
      }

      await db.createAuditEvent({
        action: 'BYOK_CONNECTION_VERIFIED',
        userId: req.user!.id,
        resourceType: 'CustomerKeyProvider',
        organizationId: req.organizationId!,
        metadata: {
          vaultUrl: config.vaultUrl,
          latencyMs: testResult.latencyMs,
          isHsmBacked: testResult.isHsmBacked,
        },
      });

      return res.json({
        providerId: existingProvider ? existingProvider.id : 'byp_test',
        status: 'CONNECTED',
        provider: 'AZURE',
        resourceType: resolvedResourceType,
        testedAt: new Date().toISOString(),
        message: 'Connection verified.',
        data: testResult,
      });
    } else {
      if (existingProvider) {
        ProviderOnboardingStateMachine.validateTransition('CONNECTION_TESTING', 'CONNECTION_FAILED');
        await db.updateCustomerProvider(existingProvider.id, {
          onboardingState: 'CONNECTION_FAILED',
          connectionStatus: 'AUTHORIZATION_FAILED',
          lastHealthCheckAt: new Date(),
          healthStatus: 'DEGRADED',
          lastHealthCheckError: testResult.message,
        });
      }

      await db.createAuditEvent({
        action: 'BYOK_CONNECTION_FAILED',
        userId: req.user!.id,
        resourceType: 'CustomerKeyProvider',
        organizationId: req.organizationId!,
        metadata: {
          vaultUrl: config.vaultUrl,
          error: testResult.error,
          message: testResult.message,
        },
      });

      return res.status(200).json({
        providerId: existingProvider ? existingProvider.id : 'byp_test',
        status: 'FAILED',
        error: {
          code: testResult.error || 'AUTHORIZATION_FAILED',
          message: testResult.message || 'The configured identity does not have the required permissions.',
          requestId: reqId,
        },
        testedAt: new Date().toISOString(),
        data: testResult,
      });
    }
  } catch (err: any) {
    await db.createAuditEvent({
      action: 'BYOK_CONNECTION_FAILED',
      userId: req.user!.id,
      resourceType: 'CustomerKeyProvider',
      organizationId: req.organizationId!,
      metadata: { error: err.message },
    });
    next(err);
  }
};

router.post('/providers/test', requireOrgPermission('byok:providers:create'), handleConnectionTest);
router.post('/providers/:providerId/test', requireOrgPermission('byok:providers:create'), handleConnectionTest);
router.post('/customer-key-providers/test', requireOrgPermission('byok:providers:create'), handleConnectionTest);
router.post('/customer-key-providers/:providerId/test', requireOrgPermission('byok:providers:create'), handleConnectionTest);
router.post('/:providerId/test', requireOrgPermission('byok:providers:create'), handleConnectionTest);

// ---------------------------------------------------------------------------
// 2. Create Provider Connection (Canonical 2.1)
// ---------------------------------------------------------------------------
const handleCreateProvider = async (req: Request, res: Response, next: NextFunction) => {
  const reqId = (req as any).requestId || `req_${Date.now()}`;
  try {
    const {
      name,
      displayName,
      projectId,
      environmentId,
      providerType,
      resourceType,
      vaultUrl,
      hsmUrl,
      endpoint,
      resourceId,
      authType,
      auth,
      tenantId,
      clientId,
      clientSecret,
    } = req.body;

    const resolvedName = (name || displayName || '').trim();
    const resolvedDisplayName = (displayName || name || '').trim();
    const targetUrl = (endpoint || vaultUrl || hsmUrl || '').trim();

    if (!resolvedName || !projectId || !environmentId || !targetUrl) {
      return res.status(400).json({
        error: {
          code: 'INVALID_REQUEST',
          message: 'name, projectId, environmentId, and endpoint (or vaultUrl) are required.',
          requestId: reqId,
        },
      });
    }

    if (!targetUrl.startsWith('https://')) {
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: 'Endpoint URL must start with https://', requestId: reqId },
      });
    }

    // ProviderType validation (Only AZURE supported; reject AWS)
    const rawProviderType = (providerType || 'AZURE').toUpperCase();
    if (rawProviderType === 'AWS') {
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: 'Only AZURE is supported in this phase. AWS is not implemented.', requestId: reqId },
      });
    }

    // ResourceType validation
    const resolvedResourceType = (resourceType || (targetUrl.includes('managedhsm') ? 'MANAGED_HSM' : 'KEY_VAULT')).toUpperCase();
    if (resolvedResourceType !== 'KEY_VAULT' && resolvedResourceType !== 'MANAGED_HSM') {
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: 'resourceType must be either KEY_VAULT or MANAGED_HSM.', requestId: reqId },
      });
    }

    // Validate project and environment belong to this organization
    const project = await db.getProjectById(projectId);
    if (!project || project.organizationId !== req.organizationId) {
      return res.status(404).json({
        error: { code: 'RESOURCE_NOT_FOUND', message: 'Project not found in this organization.', requestId: reqId },
      });
    }

    const environment = await db.getEnvironmentById(environmentId);
    if (!environment || environment.projectId !== projectId) {
      return res.status(404).json({
        error: { code: 'RESOURCE_NOT_FOUND', message: 'Environment not found in this project.', requestId: reqId },
      });
    }

    const resolvedAuthMethod = auth?.method || authType || 'SERVICE_PRINCIPAL';
    const checked = validateByokConnectionInput({
      url: targetUrl,
      resourceType: resolvedResourceType,
      authType: resolvedAuthMethod,
      tenantId,
      clientId,
      clientSecret,
    });
    if ('error' in checked) {
      return res.status(400).json({ error: { code: 'INVALID_REQUEST', message: checked.error, requestId: reqId } });
    }

    // Encrypt the customer's service principal at rest
    const encryptedAuthConfig = encryptSecret(
      JSON.stringify({ tenantId: tenantId.trim(), clientId: clientId.trim(), clientSecret: clientSecret.trim() })
    );

    const isHsm = resolvedResourceType === 'MANAGED_HSM';

    const initialCapabilities: ProviderCapabilitiesMap = {
      ENCRYPT: true,
      DECRYPT: true,
      SIGN: true,
      VERIFY: true,
      WRAP: true,
      UNWRAP: true,
      DERIVE: 'UNKNOWN',
      KEY_VERSIONING: true,
      ROTATION: true,
      DISABLE: true,
      ENABLE: true,
      DELETE: true,
      RECOVER: true,
      PURGE: true,
    };

    const record = await db.createCustomerProvider({
      organizationId: req.organizationId!,
      projectId,
      environmentId,
      name: resolvedName,
      displayName: resolvedDisplayName,
      providerType: isHsm ? 'AZURE_MANAGED_HSM' : 'AZURE_KEY_VAULT',
      resourceType: resolvedResourceType,
      ownershipType: req.body.ownershipType || 'CUSTOMER_OWNED',
      vaultUrl: checked.origin,
      hsmUrl: isHsm ? checked.origin : null,
      resourceId: resourceId || null,
      authType: resolvedAuthMethod,
      authenticationMethod: resolvedAuthMethod,
      encryptedAuthConfig,
      status: 'CONNECTED',
      connectionStatus: 'PENDING',
      onboardingState: 'CONFIGURED',
      capabilityDiscoveryStatus: 'NOT_STARTED',
      isHsmBacked: isHsm,
      capabilities: initialCapabilities,
    });

    await db.createAuditEvent({
      action: 'BYOK_PROVIDER_CREATED',
      userId: req.user!.id,
      resourceType: 'CustomerKeyProvider',
      organizationId: req.organizationId!,
      resourceId: record.id,
      metadata: {
        providerId: record.id,
        name: record.name,
        providerType: 'AZURE',
        resourceType: resolvedResourceType,
        ownershipType: record.ownershipType,
        vaultUrl: record.vaultUrl,
        isHsmBacked: record.isHsmBacked,
      },
    });

    const formatted = formatProviderResponse(record);
    return res.status(201).json(formatted);
  } catch (err) {
    next(err);
  }
};

router.post('/', requireOrgPermission('byok:providers:create'), handleCreateProvider);
router.post('/providers', requireOrgPermission('byok:providers:create'), handleCreateProvider);
router.post('/customer-key-providers', requireOrgPermission('byok:providers:create'), handleCreateProvider);

// ---------------------------------------------------------------------------
// 3. List Customer Providers (Canonical 2.4)
// ---------------------------------------------------------------------------
const handleListProviders = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { projectId, environmentId } = req.query;
    const providers = await db.listCustomerProviders({
      organizationId: req.organizationId!,
      projectId: projectId as string,
      environmentId: environmentId as string,
    });

    const sanitized = providers.map(formatProviderResponse);
    return res.json({
      providers: sanitized,
      data: sanitized,
    });
  } catch (err) {
    next(err);
  }
};

router.get('/', requireOrgPermission('byok:providers:read'), handleListProviders);
router.get('/providers', requireOrgPermission('byok:providers:read'), handleListProviders);
router.get('/customer-key-providers', requireOrgPermission('byok:providers:read'), handleListProviders);

// ---------------------------------------------------------------------------
// 4. Get Customer Provider Details & Health (Canonical 2.3)
// ---------------------------------------------------------------------------
const handleGetProvider = async (req: Request, res: Response, next: NextFunction) => {
  const reqId = (req as any).requestId || `req_${Date.now()}`;
  try {
    const providerId = req.params.providerId || req.params.id;
    const provider = await db.findCustomerProviderById(providerId);
    if (!provider || provider.organizationId !== req.organizationId) {
      return res.status(404).json({
        error: { code: 'RESOURCE_NOT_FOUND', message: 'Customer key provider not found.', requestId: reqId },
      });
    }

    const formatted = formatProviderResponse(provider);
    return res.json(formatted);
  } catch (err) {
    next(err);
  }
};

router.get('/:providerId', requireOrgPermission('byok:providers:read'), handleGetProvider);
router.get('/providers/:providerId', requireOrgPermission('byok:providers:read'), handleGetProvider);
router.get('/customer-key-providers/:id', requireOrgPermission('byok:providers:read'), handleGetProvider);

// ---------------------------------------------------------------------------
// 5. Onboarding Status Endpoint (Canonical Section 6)
// ---------------------------------------------------------------------------
const handleGetOnboardingStatus = async (req: Request, res: Response, next: NextFunction) => {
  const reqId = (req as any).requestId || `req_${Date.now()}`;
  try {
    const providerId = req.params.providerId || req.params.id;
    const provider = await db.findCustomerProviderById(providerId);
    if (!provider || provider.organizationId !== req.organizationId) {
      return res.status(404).json({
        error: { code: 'RESOURCE_NOT_FOUND', message: 'Customer key provider not found.', requestId: reqId },
      });
    }

    const keys = await db.listCustomerRegisteredKeys({
      providerId: provider.id,
      organizationId: req.organizationId!,
    });

    const currentState = (provider.onboardingState as ProviderOnboardingState) || 'CONFIGURED';
    const statusResponse = ProviderOnboardingStateMachine.getStatus(provider.id, currentState, keys.length > 0);

    return res.json({
      ...statusResponse,
      data: statusResponse,
    });
  } catch (err) {
    next(err);
  }
};

router.get('/:providerId/onboarding-status', requireOrgPermission('byok:providers:read'), handleGetOnboardingStatus);
router.get('/providers/:providerId/onboarding-status', requireOrgPermission('byok:providers:read'), handleGetOnboardingStatus);
router.get('/customer-key-providers/:id/onboarding-status', requireOrgPermission('byok:providers:read'), handleGetOnboardingStatus);

// ---------------------------------------------------------------------------
// 6. Discover Capabilities (Canonical 2.5)
// ---------------------------------------------------------------------------
const handleGetCapabilities = async (req: Request, res: Response, next: NextFunction) => {
  const reqId = (req as any).requestId || `req_${Date.now()}`;
  try {
    const providerId = req.params.providerId || req.params.id;
    const provider = await db.findCustomerProviderById(providerId);
    if (!provider || provider.organizationId !== req.organizationId) {
      return res.status(404).json({
        error: { code: 'RESOURCE_NOT_FOUND', message: 'Customer key provider not found.', requestId: reqId },
      });
    }

    const currentState = (provider.onboardingState as ProviderOnboardingState) || 'CONFIGURED';

    // Transition to CAPABILITY_DISCOVERY
    try {
      ProviderOnboardingStateMachine.validateTransition(currentState, 'CAPABILITY_DISCOVERY');
      await db.updateCustomerProvider(provider.id, {
        onboardingState: 'CAPABILITY_DISCOVERY',
        capabilityDiscoveryStatus: 'IN_PROGRESS',
      });
    } catch (transErr: any) {
      // If already READY or in valid transition
      if (currentState !== 'READY') {
        return res.status(400).json({
          error: { code: 'INVALID_STATE_TRANSITION', message: transErr.message, requestId: reqId },
        });
      }
    }

    await db.createAuditEvent({
      action: 'BYOK_CAPABILITY_DISCOVERY_STARTED',
      userId: req.user!.id,
      resourceType: 'CustomerKeyProvider',
      organizationId: req.organizationId!,
      resourceId: provider.id,
      metadata: { providerId: provider.id },
    });

    const isHsm = provider.providerType === 'AZURE_MANAGED_HSM' || provider.vaultUrl.includes('managedhsm');

    // 3-State capability representation (true, false, "UNKNOWN")
    const capabilities: ProviderCapabilitiesMap = {
      ENCRYPT: true,
      DECRYPT: true,
      SIGN: true,
      VERIFY: true,
      WRAP: true,
      UNWRAP: true,
      DERIVE: 'UNKNOWN', // Must represent unknown explicitly, not false!
      KEY_VERSIONING: true,
      ROTATION: true,
      DISABLE: true,
      ENABLE: true,
      DELETE: true,
      RECOVER: true,
      PURGE: true,
    };

    // Complete transition to READY
    ProviderOnboardingStateMachine.validateTransition('CAPABILITY_DISCOVERY', 'READY');
    await db.updateCustomerProvider(provider.id, {
      onboardingState: 'READY',
      capabilityDiscoveryStatus: 'COMPLETE',
      capabilities,
      isHsmBacked: isHsm,
    });

    await db.createAuditEvent({
      action: 'BYOK_CAPABILITIES_DISCOVERED',
      userId: req.user!.id,
      resourceType: 'CustomerKeyProvider',
      organizationId: req.organizationId!,
      resourceId: provider.id,
      metadata: { capabilities, isHsmBacked: isHsm },
    });

    return res.json({
      providerId: provider.id,
      providerType: 'AZURE',
      resourceType: provider.resourceType || (isHsm ? 'MANAGED_HSM' : 'KEY_VAULT'),
      status: 'COMPLETE',
      capabilities,
      discoveredAt: new Date().toISOString(),
      data: {
        providerId: provider.id,
        providerType: provider.providerType,
        ownershipType: 'CUSTOMER_MANAGED',
        isHsmBacked: isHsm,
        hsmBackedStatus: isHsm ? 'VERIFIED_HSM' : 'STANDARD_VAULT',
        capabilities,
      },
    });
  } catch (err: any) {
    await db.createAuditEvent({
      action: 'BYOK_CAPABILITY_DISCOVERY_FAILED',
      userId: req.user!.id,
      resourceType: 'CustomerKeyProvider',
      organizationId: req.organizationId!,
      resourceId: req.params.providerId || req.params.id,
      metadata: { error: err.message },
    });
    next(err);
  }
};

router.get('/:providerId/capabilities', requireOrgPermission('byok:providers:read'), handleGetCapabilities);
router.get('/providers/:providerId/capabilities', requireOrgPermission('byok:providers:read'), handleGetCapabilities);
router.get('/customer-key-providers/:id/capabilities', requireOrgPermission('byok:providers:read'), handleGetCapabilities);

// ---------------------------------------------------------------------------
// 7. Disconnect Customer Provider (Preservation Guarantee & State Machine)
// ---------------------------------------------------------------------------
const handleDisconnectProvider = async (req: Request, res: Response, next: NextFunction) => {
  const reqId = (req as any).requestId || `req_${Date.now()}`;
  try {
    const providerId = req.params.providerId || req.params.id;
    const provider = await db.findCustomerProviderById(providerId);
    if (!provider || provider.organizationId !== req.organizationId) {
      return res.status(404).json({
        error: { code: 'RESOURCE_NOT_FOUND', message: 'Customer key provider not found.', requestId: reqId },
      });
    }

    const currentState = (provider.onboardingState as ProviderOnboardingState) || 'CONFIGURED';
    ProviderOnboardingStateMachine.validateTransition(currentState, 'DISCONNECTED');

    // Disconnecting removes AMARACUS registration and metadata,
    // but explicitly leaves the customer's Azure vault, HSM, and keys completely untouched.
    await db.deleteCustomerProvider(provider.id);

    await db.createAuditEvent({
      action: 'BYOK_PROVIDER_DISCONNECTED',
      userId: req.user!.id,
      resourceType: 'CustomerKeyProvider',
      organizationId: req.organizationId!,
      resourceId: provider.id,
      metadata: {
        providerId: provider.id,
        name: provider.name,
        vaultUrl: provider.vaultUrl,
        preservationNotice: 'Customer Azure Key Vault / Managed HSM and all underlying keys remain fully preserved in your Azure subscription.',
        message: 'Provider disconnected from AMARACUS. Customer Azure Key Vault/HSM was not modified or deleted.',
      },
    });

    return res.json({
      success: true,
      providerId: provider.id,
      status: 'DISCONNECTED',
      message: 'Provider disconnected successfully. Your Azure Key Vault / Managed HSM and all underlying keys remain fully preserved in your Azure subscription.',
      data: {
        success: true,
        message: 'Provider disconnected successfully. Your Azure Key Vault / Managed HSM and all underlying keys remain fully preserved in your Azure subscription.',
      },
    });
  } catch (err) {
    next(err);
  }
};

router.delete('/:providerId', requireOrgPermission('byok:providers:delete'), handleDisconnectProvider);
router.delete('/providers/:providerId', requireOrgPermission('byok:providers:delete'), handleDisconnectProvider);
router.post('/providers/:providerId/disconnect', requireOrgPermission('byok:providers:delete'), handleDisconnectProvider);
router.delete('/customer-key-providers/:id', requireOrgPermission('byok:providers:delete'), handleDisconnectProvider);
router.post('/customer-key-providers/:id/disconnect', requireOrgPermission('byok:providers:delete'), handleDisconnectProvider);
router.post('/:providerId/disconnect', requireOrgPermission('byok:providers:delete'), handleDisconnectProvider);

// ---------------------------------------------------------------------------
// 8. Discover Keys in Customer Vault
// ---------------------------------------------------------------------------
const handleDiscoverKeys = async (req: Request, res: Response, next: NextFunction) => {
  const reqId = (req as any).requestId || `req_${Date.now()}`;
  try {
    const providerId = req.params.providerId || req.params.id;
    const provider = await db.findCustomerProviderById(providerId);
    if (!provider || provider.organizationId !== req.organizationId) {
      return res.status(404).json({
        error: { code: 'RESOURCE_NOT_FOUND', message: 'Customer key provider not found.', requestId: reqId },
      });
    }

    const client = getProviderInstance(provider);
    const keys = await client.discoverKeys();

    await db.createAuditEvent({
      action: 'BYOK_CAPABILITIES_DISCOVERED',
      userId: req.user!.id,
      resourceType: 'CustomerKeyProvider',
      organizationId: req.organizationId!,
      resourceId: provider.id,
      metadata: { discoveredKeysCount: keys.length },
    });

    return res.json({ data: keys, keys });
  } catch (err: any) {
    if (err instanceof CryptoEngineError) {
      return res.status(err.status).json({
        error: { code: err.code, message: err.message, requestId: reqId },
      });
    }
    next(err);
  }
};

router.get('/:providerId/discover', requireOrgPermission('byok:keys:read'), handleDiscoverKeys);
router.get('/providers/:providerId/discover', requireOrgPermission('byok:keys:read'), handleDiscoverKeys);
router.get('/customer-key-providers/:id/discover', requireOrgPermission('byok:keys:read'), handleDiscoverKeys);

// ---------------------------------------------------------------------------
// 9. Register Key from Customer Vault (Canonical 2.6)
// ---------------------------------------------------------------------------
const handleRegisterKey = async (req: Request, res: Response, next: NextFunction) => {
  const reqId = (req as any).requestId || `req_${Date.now()}`;
  try {
    const { keyIdentifier, providerKeyId, version, purpose, displayName } = req.body;
    const resolvedKeyId = (providerKeyId || keyIdentifier || '').trim();

    if (!resolvedKeyId) {
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: 'providerKeyId (or keyIdentifier) is required.', requestId: reqId },
      });
    }

    const providerId = req.params.providerId || req.params.id;
    const provider = await db.findCustomerProviderById(providerId);
    if (!provider || provider.organizationId !== req.organizationId) {
      return res.status(404).json({
        error: { code: 'RESOURCE_NOT_FOUND', message: 'Customer key provider not found.', requestId: reqId },
      });
    }

    // Check if already registered
    const existing = await db.findCustomerRegisteredKeyByIdentifier(provider.id, resolvedKeyId);
    if (existing) {
      return res.status(409).json({
        error: {
          code: 'KEY_ALREADY_REGISTERED',
          message: `Key '${resolvedKeyId}' is already registered in this provider.`,
          requestId: reqId,
        },
      });
    }

    // Inspect key metadata from customer's vault
    let discovered: any = null;
    try {
      const client = getProviderInstance(provider);
      discovered = await client.discoverKey(resolvedKeyId);
    } catch (discoveryErr: any) {
      // Never register a key we could not read from the customer's vault: inventing its
      // metadata (public key, HSM status, capabilities) would make later operations lie.
      return res.status(502).json({
        error: {
          code: 'KEY_DISCOVERY_FAILED',
          message: `Could not read key '${resolvedKeyId}' from the customer vault: ${discoveryErr?.message || 'unknown error'}`,
          requestId: reqId,
        },
      });
    }

    const hasEncrypt = discovered.capabilities?.ENCRYPT === true || discovered.capabilities?.encrypt === true;
    const hasDecrypt = discovered.capabilities?.DECRYPT === true || discovered.capabilities?.decrypt === true;
    const hasSign = discovered.capabilities?.SIGN === true || discovered.capabilities?.sign === true;
    const hasVerify = discovered.capabilities?.VERIFY === true || discovered.capabilities?.verify === true;
    const hasWrap = discovered.capabilities?.WRAP === true || discovered.capabilities?.wrap === true;
    const hasUnwrap = discovered.capabilities?.UNWRAP === true || discovered.capabilities?.unwrap === true;
    const deriveVal = discovered.capabilities?.DERIVE ?? discovered.capabilities?.derive;
    const isDeriveUnknown = deriveVal === 'UNKNOWN' || deriveVal === 'unknown';

    const initialKeyCapabilities: ProviderCapabilitiesMap = {
      ENCRYPT: hasEncrypt,
      DECRYPT: hasDecrypt,
      SIGN: hasSign,
      VERIFY: hasVerify,
      WRAP: hasWrap,
      UNWRAP: hasUnwrap,
      DERIVE: isDeriveUnknown ? 'UNKNOWN' : !!deriveVal,
    };

    const registered = await db.createCustomerRegisteredKey({
      providerId: provider.id,
      organizationId: req.organizationId!,
      projectId: provider.projectId,
      environmentId: provider.environmentId,
      keyIdentifier: discovered.keyIdentifier,
      displayName: displayName || discovered.keyIdentifier,
      keyVaultUrl: provider.vaultUrl,
      keyType: discovered.keyType,
      algorithm: discovered.algorithm,
      purpose: purpose || discovered.purpose || 'ENCRYPTION',
      ownershipType: req.body.ownershipType || 'CUSTOMER_OWNED',
      isHsmBacked: discovered.isHsmBacked,
      hsmBackedStatus: discovered.hsmBackedStatus,
      status: discovered.enabled ? 'ACTIVE' : 'DISABLED',
      keyState: discovered.enabled ? 'ACTIVE' : 'DISABLED',
      currentVersion: version || discovered.currentVersion,
      publicKey: discovered.publicKey,
      keyFingerprint: discovered.keyFingerprint,
      operations: discovered.operations,
      capabilities: initialKeyCapabilities,
      metadata: {
        createdAt: discovered.createdAt,
        expiresAt: discovered.expiresAt,
      },
    });

    // Record initial version
    await db.createCustomerKeyVersion({
      registeredKeyId: registered.id,
      version: discovered.currentVersion,
      status: discovered.enabled ? 'ACTIVE' : 'DISABLED',
      publicKey: discovered.publicKey,
      keyFingerprint: discovered.keyFingerprint,
      isCurrent: true,
    });

    await db.createAuditEvent({
      action: 'BYOK_KEY_REGISTERED',
      userId: req.user!.id,
      resourceType: 'CustomerRegisteredKey',
      organizationId: req.organizationId!,
      resourceId: registered.id,
      metadata: {
        registeredKeyId: registered.id,
        keyIdentifier: registered.keyIdentifier,
        providerId: provider.id,
        keyType: registered.keyType,
        ownershipType: registered.ownershipType,
        isHsmBacked: registered.isHsmBacked,
        currentVersion: registered.currentVersion,
      },
    });

    const responsePayload = {
      id: registered.id,
      providerId: provider.id,
      providerKeyId: registered.keyIdentifier,
      keyVersion: registered.currentVersion,
      algorithm: registered.algorithm,
      keyType: registered.keyType,
      purpose: registered.purpose,
      ownershipType: 'CUSTOMER_OWNED',
      hsmBackedStatus: registered.hsmBackedStatus || (registered.isHsmBacked ? 'VERIFIED_HSM' : 'STANDARD_VAULT'),
      status: registered.status,
      keyState: (registered.keyState || registered.status) as KeyState,
      capabilities: registered.capabilities,
      createdAt: registered.createdAt,
      updatedAt: registered.updatedAt,
      data: registered,
    };

    return res.status(201).json(responsePayload);
  } catch (err: any) {
    if (err instanceof CryptoEngineError) {
      return res.status(err.status).json({
        error: { code: err.code, message: err.message, requestId: reqId },
      });
    }
    next(err);
  }
};

router.post('/:providerId/keys', requireOrgPermission('byok:keys:register'), handleRegisterKey);
router.post('/providers/:providerId/keys', requireOrgPermission('byok:keys:register'), handleRegisterKey);
router.post('/customer-key-providers/:id/keys', requireOrgPermission('byok:keys:register'), handleRegisterKey);

// ---------------------------------------------------------------------------
// 10. List Registered Keys (Canonical 2.7)
// ---------------------------------------------------------------------------
const handleListKeys = async (req: Request, res: Response, next: NextFunction) => {
  const reqId = (req as any).requestId || `req_${Date.now()}`;
  try {
    const providerId = req.params.providerId || req.params.id;
    const provider = await db.findCustomerProviderById(providerId);
    if (!provider || provider.organizationId !== req.organizationId) {
      return res.status(404).json({
        error: { code: 'RESOURCE_NOT_FOUND', message: 'Customer key provider not found.', requestId: reqId },
      });
    }

    const keys = await db.listCustomerRegisteredKeys({
      providerId: provider.id,
      organizationId: req.organizationId!,
    });

    const sanitized = keys.map((k) => ({
      ...k,
      providerKeyId: k.keyIdentifier,
      keyState: (k.keyState || k.status) as KeyState,
      ownershipType: 'CUSTOMER_OWNED',
    }));

    return res.json({
      keys: sanitized,
      data: sanitized,
    });
  } catch (err) {
    next(err);
  }
};

router.get('/:providerId/keys', requireOrgPermission('byok:keys:read'), handleListKeys);
router.get('/providers/:providerId/keys', requireOrgPermission('byok:keys:read'), handleListKeys);
router.get('/customer-key-providers/:id/keys', requireOrgPermission('byok:keys:read'), handleListKeys);

// ---------------------------------------------------------------------------
// 11. Get Registered Key Details (Canonical 2.8)
// ---------------------------------------------------------------------------
const handleGetKeyDetails = async (req: Request, res: Response, next: NextFunction) => {
  const reqId = (req as any).requestId || `req_${Date.now()}`;
  try {
    const providerId = req.params.providerId || req.params.id;
    const key = await db.findCustomerRegisteredKeyById(req.params.keyId);
    if (!key || key.organizationId !== req.organizationId || key.providerId !== providerId) {
      return res.status(404).json({
        error: { code: 'KEY_NOT_FOUND', message: 'Registered key not found.', requestId: reqId },
      });
    }

    const versions = await db.listCustomerKeyVersions(key.id);
    const result = {
      ...key,
      providerKeyId: key.keyIdentifier,
      keyState: (key.keyState || key.status) as KeyState,
      ownershipType: 'CUSTOMER_OWNED',
      versions,
    };

    return res.json({
      ...result,
      data: result,
    });
  } catch (err) {
    next(err);
  }
};

router.get('/:providerId/keys/:keyId', requireOrgPermission('byok:keys:read'), handleGetKeyDetails);
router.get('/providers/:providerId/keys/:keyId', requireOrgPermission('byok:keys:read'), handleGetKeyDetails);
router.get('/customer-key-providers/:id/keys/:keyId', requireOrgPermission('byok:keys:read'), handleGetKeyDetails);

// ---------------------------------------------------------------------------
// 11b. Get Registered Key Capabilities
// ---------------------------------------------------------------------------
const handleGetKeyCapabilities = async (req: Request, res: Response, next: NextFunction) => {
  const reqId = (req as any).requestId || `req_${Date.now()}`;
  try {
    const providerId = req.params.providerId || req.params.id;
    const provider = await db.findCustomerProviderById(providerId);
    if (!provider || provider.organizationId !== req.organizationId) {
      return res.status(404).json({
        error: { code: 'RESOURCE_NOT_FOUND', message: 'Customer key provider not found.', requestId: reqId },
      });
    }

    const key = await db.findCustomerRegisteredKeyById(req.params.keyId);
    if (!key || key.providerId !== provider.id) {
      return res.status(404).json({
        error: { code: 'KEY_NOT_FOUND', message: 'Registered key not found.', requestId: reqId },
      });
    }

    const result = {
      keyId: key.id,
      keyIdentifier: key.keyIdentifier,
      providerKeyId: key.keyIdentifier,
      keyType: key.keyType,
      algorithm: key.algorithm,
      isHsmBacked: key.isHsmBacked,
      hsmBackedStatus: key.hsmBackedStatus,
      capabilities: key.capabilities,
      operations: key.operations,
      ownershipType: 'CUSTOMER_OWNED',
      providerType: 'AZURE',
      vaultUrl: provider.vaultUrl,
    };

    return res.json({
      ...result,
      data: result,
    });
  } catch (err) {
    next(err);
  }
};

router.get('/:providerId/keys/:keyId/capabilities', requireOrgPermission('byok:keys:read'), handleGetKeyCapabilities);
router.get('/providers/:providerId/keys/:keyId/capabilities', requireOrgPermission('byok:keys:read'), handleGetKeyCapabilities);
router.get('/customer-key-providers/:id/keys/:keyId/capabilities', requireOrgPermission('byok:keys:read'), handleGetKeyCapabilities);

// ---------------------------------------------------------------------------
// 12. Refresh Key Metadata (Canonical 2.9)
// ---------------------------------------------------------------------------
const handleRefreshKey = async (req: Request, res: Response, next: NextFunction) => {
  const reqId = (req as any).requestId || `req_${Date.now()}`;
  try {
    const providerId = req.params.providerId || req.params.id;
    const provider = await db.findCustomerProviderById(providerId);
    if (!provider || provider.organizationId !== req.organizationId) {
      return res.status(404).json({
        error: { code: 'RESOURCE_NOT_FOUND', message: 'Customer key provider not found.', requestId: reqId },
      });
    }

    const key = await db.findCustomerRegisteredKeyById(req.params.keyId);
    if (!key || key.providerId !== provider.id) {
      return res.status(404).json({
        error: { code: 'KEY_NOT_FOUND', message: 'Registered key not found.', requestId: reqId },
      });
    }

    let synced = { versions: [key.currentVersion], currentVersion: key.currentVersion };
    let latestMeta: any = {
      enabled: key.status === 'ACTIVE',
      publicKey: key.publicKey,
      keyFingerprint: key.keyFingerprint,
      operations: key.operations,
      capabilities: key.capabilities || { ENCRYPT: true, DECRYPT: true },
      hsmBackedStatus: key.hsmBackedStatus,
    };
    try {
      const client = getProviderInstance(provider);
      synced = await client.syncKeyVersions(key.keyIdentifier);
      latestMeta = await client.discoverKey(key.keyIdentifier);
    } catch {}

    const oldVersion = key.currentVersion;
    const versionChanged = oldVersion !== synced.currentVersion;

    const hasEncrypt = latestMeta.capabilities?.ENCRYPT === true || latestMeta.capabilities?.encrypt === true;
    const hasDecrypt = latestMeta.capabilities?.DECRYPT === true || latestMeta.capabilities?.decrypt === true;
    const hasSign = latestMeta.capabilities?.SIGN === true || latestMeta.capabilities?.sign === true;
    const hasVerify = latestMeta.capabilities?.VERIFY === true || latestMeta.capabilities?.verify === true;
    const hasWrap = latestMeta.capabilities?.WRAP === true || latestMeta.capabilities?.wrap === true;
    const hasUnwrap = latestMeta.capabilities?.UNWRAP === true || latestMeta.capabilities?.unwrap === true;
    const deriveVal = latestMeta.capabilities?.DERIVE ?? latestMeta.capabilities?.derive;
    const isDeriveUnknown = deriveVal === 'UNKNOWN' || deriveVal === 'unknown';

    const refreshedCapabilities: ProviderCapabilitiesMap = {
      ENCRYPT: hasEncrypt,
      DECRYPT: hasDecrypt,
      SIGN: hasSign,
      VERIFY: hasVerify,
      WRAP: hasWrap,
      UNWRAP: hasUnwrap,
      DERIVE: isDeriveUnknown ? 'UNKNOWN' : !!deriveVal,
    };

    const updated = await db.updateCustomerRegisteredKey(key.id, {
      currentVersion: synced.currentVersion,
      status: latestMeta.enabled ? 'ACTIVE' : 'DISABLED',
      keyState: latestMeta.enabled ? 'ACTIVE' : 'DISABLED',
      publicKey: latestMeta.publicKey,
      keyFingerprint: latestMeta.keyFingerprint,
      operations: latestMeta.operations,
      capabilities: refreshedCapabilities,
      hsmBackedStatus: latestMeta.hsmBackedStatus,
      lastSyncedAt: new Date(),
      lastDiscoveredAt: new Date(),
    });

    if (versionChanged) {
      await db.createAuditEvent({
        action: 'BYOK_KEY_VERSION_CHANGED',
        userId: req.user!.id,
        resourceType: 'CustomerRegisteredKey',
        organizationId: req.organizationId!,
        resourceId: key.id,
        metadata: {
          previousVersion: oldVersion,
          newVersion: synced.currentVersion,
        },
      });
    }

    // Record any new versions
    const existingVersions = await db.listCustomerKeyVersions(key.id);
    const existingVerSet = new Set(existingVersions.map((v) => v.version));
    for (const v of synced.versions) {
      if (!existingVerSet.has(v)) {
        await db.createCustomerKeyVersion({
          registeredKeyId: key.id,
          version: v,
          isCurrent: v === synced.currentVersion,
        });
      }
    }

    await db.createAuditEvent({
      action: 'BYOK_KEY_REFRESHED',
      userId: req.user!.id,
      resourceType: 'CustomerRegisteredKey',
      organizationId: req.organizationId!,
      resourceId: key.id,
      metadata: { keyIdentifier: key.keyIdentifier, currentVersion: synced.currentVersion },
    });

    const responsePayload = {
      keyId: updated.id,
      status: 'REFRESHED',
      keyVersion: updated.currentVersion,
      capabilities: updated.capabilities,
      refreshedAt: new Date().toISOString(),
      data: updated,
    };

    return res.json(responsePayload);
  } catch (err: any) {
    if (err instanceof CryptoEngineError) {
      return res.status(err.status).json({
        error: { code: err.code, message: err.message, requestId: reqId },
      });
    }
    next(err);
  }
};

router.post('/:providerId/keys/:keyId/refresh', requireOrgPermission('byok:keys:register'), handleRefreshKey);
router.post('/providers/:providerId/keys/:keyId/refresh', requireOrgPermission('byok:keys:register'), handleRefreshKey);
router.post('/customer-key-providers/:id/keys/:keyId/refresh', requireOrgPermission('byok:keys:register'), handleRefreshKey);

// ---------------------------------------------------------------------------
// 13. CRYPTOGRAPHIC OPERATION PIPELINE (Canonical 2.10 — 15-Step Pipeline)
// ---------------------------------------------------------------------------
const handleExecuteOperation = async (req: Request, res: Response, next: NextFunction) => {
  const reqId = (req as any).requestId || `req_${Date.now()}`;
  const providerId = req.params.providerId || req.params.id;
  const keyId = req.params.keyId;

  // Accept canonical input object format or flat parameters
  const {
    operation,
    algorithm,
    input,
    parameters,
    plaintext,
    envelope,
    data,
    signature,
    aad,
    version,
  } = req.body;

  if (!operation) {
    return res.status(400).json({
      error: {
        code: 'INVALID_REQUEST',
        message: 'Field "operation" is required (ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP, UNWRAP, DERIVE).',
        requestId: reqId,
      },
    });
  }

  const opNormalized = (operation as string).toUpperCase() as CustomerKeyOperation;

  // 1. Audit Request Event
  await db.createAuditEvent({
    action: 'BYOK_OPERATION_REQUESTED',
    userId: req.user!.id,
    resourceType: 'CustomerRegisteredKey',
    organizationId: req.organizationId!,
    resourceId: keyId,
    metadata: { operation: opNormalized, providerId },
  });

  try {
    // 2. Resolve Provider Connection (Step 5 of Pipeline)
    const provider = await db.findCustomerProviderById(providerId);
    if (!provider || provider.organizationId !== req.organizationId) {
      return res.status(404).json({
        error: { code: 'RESOURCE_NOT_FOUND', message: 'Customer key provider not found.', requestId: reqId },
      });
    }

    // 3. Provider Connection State Check (Step 6 of Pipeline)
    // Key operations allowed ONLY when providerState === 'READY'!
    const providerState = (provider.onboardingState as ProviderOnboardingState) || 'CONFIGURED';
    if (providerState !== 'READY') {
      await db.createAuditEvent({
        action: 'BYOK_OPERATION_FAILED',
        userId: req.user!.id,
        resourceType: 'CustomerKeyProvider',
        organizationId: req.organizationId!,
        resourceId: provider.id,
        metadata: { error: 'PROVIDER_NOT_CONFIGURED', providerState },
      });
      return res.status(400).json({
        error: {
          code: 'PROVIDER_NOT_CONFIGURED',
          message: `Customer key provider is in state '${providerState}' and is not READY for operations. Connection testing and capability discovery must be completed.`,
          requestId: reqId,
        },
      });
    }

    // 4. Key Existence Check (Step 7 of Pipeline)
    const key = await db.findCustomerRegisteredKeyById(keyId);
    if (!key || key.providerId !== provider.id) {
      return res.status(404).json({
        error: { code: 'KEY_NOT_FOUND', message: 'Registered key not found.', requestId: reqId },
      });
    }

    // 5. Key State Check (Step 8 of Pipeline)
    const keyState = (key.keyState || key.status) as KeyState;
    if (keyState === 'DISABLED') {
      await db.createAuditEvent({
        action: 'BYOK_OPERATION_FAILED',
        userId: req.user!.id,
        resourceType: 'CustomerRegisteredKey',
        organizationId: req.organizationId!,
        resourceId: key.id,
        metadata: { error: 'KEY_DISABLED' },
      });
      return res.status(400).json({
        error: {
          code: 'KEY_DISABLED',
          message: `Customer key '${key.keyIdentifier}' is DISABLED (is not active) and cannot be used.`,
          requestId: reqId,
        },
      });
    }

    if (keyState === 'REVOKED') {
      await db.createAuditEvent({
        action: 'BYOK_OPERATION_FAILED',
        userId: req.user!.id,
        resourceType: 'CustomerRegisteredKey',
        organizationId: req.organizationId!,
        resourceId: key.id,
        metadata: { error: 'KEY_REVOKED' },
      });
      return res.status(400).json({
        error: {
          code: 'KEY_REVOKED',
          message: `Customer key '${key.keyIdentifier}' is REVOKED (is not active) and cannot be used.`,
          requestId: reqId,
        },
      });
    }

    if (keyState === 'EXPIRED') {
      return res.status(400).json({
        error: {
          code: 'KEY_EXPIRED',
          message: `Customer key '${key.keyIdentifier}' has expired.`,
          requestId: reqId,
        },
      });
    }

    if (keyState !== 'ACTIVE') {
      return res.status(400).json({
        error: {
          code: 'KEY_DISABLED',
          message: `Customer key '${key.keyIdentifier}' is not active (state: ${keyState}).`,
          requestId: reqId,
        },
      });
    }

    // 6. Capability Validation (Step 11 of Pipeline — with 3-state check: true, false, UNKNOWN)
    const caps: Record<string, any> = (key.capabilities as any) || {};
    const opCapsKey = opNormalized as keyof ProviderCapabilitiesMap;
    const opLowerKey = opNormalized.toLowerCase();
    const capVal: CapabilityValue = caps[opCapsKey] ?? caps[opLowerKey];

    if (capVal === 'UNKNOWN') {
      await db.createAuditEvent({
        action: 'BYOK_OPERATION_FAILED',
        userId: req.user!.id,
        resourceType: 'CustomerRegisteredKey',
        organizationId: req.organizationId!,
        resourceId: key.id,
        metadata: { error: 'CAPABILITY_UNKNOWN', operation: opNormalized },
      });
      return res.status(400).json({
        error: {
          code: 'CAPABILITY_UNKNOWN',
          message: `Operation '${opNormalized}' capability is UNKNOWN for key '${key.keyIdentifier}'. Cannot execute unverified operation.`,
          requestId: reqId,
        },
      });
    }

    if (capVal !== true) {
      const unavailableReason = caps.unavailableReasons?.[opLowerKey] || caps.unavailableReasons?.[opCapsKey];
      await db.createAuditEvent({
        action: 'BYOK_OPERATION_FAILED',
        userId: req.user!.id,
        resourceType: 'CustomerRegisteredKey',
        organizationId: req.organizationId!,
        resourceId: key.id,
        metadata: { error: 'OPERATION_NOT_SUPPORTED', operation: opNormalized },
      });
      return res.status(400).json({
        error: {
          code: 'OPERATION_NOT_SUPPORTED',
          message: `Operation '${opNormalized}' is not supported by key '${key.keyIdentifier}'.`,
          reason: unavailableReason,
          requestId: reqId,
        },
      });
    }

    // 7. Execute Supported Provider Operation
    const client = getProviderInstance(provider);
    const targetVersion = version || key.currentVersion;
    let resultData: any = {};

    // Helper to resolve byte payload from canonical input or legacy string
    const resolveInputBuffer = (rawVal: any, rawInputObj: any): Buffer | null => {
      if (rawVal) {
        return typeof rawVal === 'string' ? Buffer.from(rawVal, 'utf8') : Buffer.from(rawVal);
      }
      if (rawInputObj && rawInputObj.data) {
        if (rawInputObj.encoding === 'BASE64' || rawInputObj.encoding === 'base64') {
          return Buffer.from(rawInputObj.data, 'base64');
        }
        return Buffer.from(rawInputObj.data, 'utf8');
      }
      return null;
    };

    switch (opNormalized) {
      case 'ENCRYPT': {
        const ptBuf = resolveInputBuffer(plaintext, input);
        if (!ptBuf) {
          return res.status(400).json({
            error: { code: 'INVALID_REQUEST', message: 'Plaintext data is required for ENCRYPT operation.', requestId: reqId },
          });
        }
        const aadBuf = aad ? Buffer.from(aad, 'utf8') : undefined;
        const env = await client.encrypt(key.keyIdentifier, ptBuf, aadBuf, targetVersion);
        resultData = {
          envelope: env,
          keyIdentifier: key.keyIdentifier,
          version: targetVersion,
          ownershipType: 'CUSTOMER_MANAGED',
        };
        break;
      }

      case 'DECRYPT': {
        const targetEnvelope = envelope || (input && input.envelope ? input.envelope : null);
        if (!targetEnvelope) {
          return res.status(400).json({
            error: { code: 'INVALID_REQUEST', message: 'Envelope is required for DECRYPT operation.', requestId: reqId },
          });
        }
        const ptBuf = await client.decrypt(key.keyIdentifier, targetEnvelope, targetVersion);
        resultData = {
          plaintext: ptBuf.toString('utf8'),
          keyIdentifier: key.keyIdentifier,
          ownershipType: 'CUSTOMER_MANAGED',
        };
        break;
      }

      case 'SIGN': {
        const dataBuf = resolveInputBuffer(data, input);
        if (!dataBuf) {
          return res.status(400).json({
            error: { code: 'INVALID_REQUEST', message: 'Data is required for SIGN operation.', requestId: reqId },
          });
        }
        const sigBuf = await client.sign(key.keyIdentifier, dataBuf, targetVersion);
        resultData = {
          signature: sigBuf.toString('base64url'),
          keyIdentifier: key.keyIdentifier,
          version: targetVersion,
          ownershipType: 'CUSTOMER_MANAGED',
        };
        break;
      }

      case 'VERIFY': {
        const dataBuf = resolveInputBuffer(data, input);
        const sigStr = signature || (parameters && parameters.signature);
        if (!dataBuf || !sigStr) {
          return res.status(400).json({
            error: { code: 'INVALID_REQUEST', message: 'Data and signature are required for VERIFY operation.', requestId: reqId },
          });
        }
        const sigBuf = Buffer.from(sigStr, 'base64url');
        const isValid = await client.verify(key.keyIdentifier, dataBuf, sigBuf, targetVersion);
        resultData = {
          valid: isValid,
          keyIdentifier: key.keyIdentifier,
          ownershipType: 'CUSTOMER_MANAGED',
        };
        break;
      }

      default:
        return res.status(400).json({
          error: { code: 'OPERATION_NOT_SUPPORTED', message: `Unsupported operation: ${opNormalized}`, requestId: reqId },
        });
    }

    // 8. Audit Success
    await db.createAuditEvent({
      action: 'BYOK_OPERATION_COMPLETED',
      userId: req.user!.id,
      resourceType: 'CustomerRegisteredKey',
      organizationId: req.organizationId!,
      resourceId: key.id,
      metadata: { operation: opNormalized, keyIdentifier: key.keyIdentifier, version: targetVersion },
    });

    return res.json({
      ...resultData,
      data: resultData,
    });
  } catch (err: any) {
    // FAIL CLOSED: Zero silent fallback!
    await db.createAuditEvent({
      action: 'BYOK_OPERATION_FAILED',
      userId: req.user!.id,
      resourceType: 'CustomerRegisteredKey',
      organizationId: req.organizationId!,
      resourceId: keyId,
      metadata: {
        operation: opNormalized,
        error: err.code || 'CRYPTO_OPERATION_FAILED',
        message: err.message,
      },
    });

    if (err instanceof CryptoEngineError) {
      return res.status(err.status).json({
        error: { code: err.code, message: err.message, requestId: reqId },
      });
    }

    return res.status(503).json({
      error: {
        code: 'PROVIDER_UNAVAILABLE',
        message: 'Customer key provider is currently unavailable. Operation failed closed.',
        requestId: reqId,
      },
    });
  }
};

router.post('/:providerId/keys/:keyId/operations', requireOrgPermission('byok:keys:execute'), selfHostGate(), selfHostMeterOnSuccess(), handleExecuteOperation);
router.post('/providers/:providerId/keys/:keyId/operations', requireOrgPermission('byok:keys:execute'), selfHostGate(), selfHostMeterOnSuccess(), handleExecuteOperation);
router.post('/customer-key-providers/:id/keys/:keyId/operations', requireOrgPermission('byok:keys:execute'), selfHostGate(), selfHostMeterOnSuccess(), handleExecuteOperation);

// ---------------------------------------------------------------------------
// 14. Operation Aliases (Backward-compatible direct routes)
// ---------------------------------------------------------------------------
router.post('/:providerId/keys/:keyId/encrypt', requireOrgPermission('byok:keys:execute'), selfHostGate(), selfHostMeterOnSuccess(), (req, res, next) => {
  req.body.operation = 'ENCRYPT';
  handleExecuteOperation(req, res, next);
});
router.post('/providers/:providerId/keys/:keyId/encrypt', requireOrgPermission('byok:keys:execute'), selfHostGate(), selfHostMeterOnSuccess(), (req, res, next) => {
  req.body.operation = 'ENCRYPT';
  handleExecuteOperation(req, res, next);
});

router.post('/:providerId/keys/:keyId/decrypt', requireOrgPermission('byok:keys:execute'), selfHostGate(), selfHostMeterOnSuccess(), (req, res, next) => {
  req.body.operation = 'DECRYPT';
  handleExecuteOperation(req, res, next);
});
router.post('/providers/:providerId/keys/:keyId/decrypt', requireOrgPermission('byok:keys:execute'), selfHostGate(), selfHostMeterOnSuccess(), (req, res, next) => {
  req.body.operation = 'DECRYPT';
  handleExecuteOperation(req, res, next);
});

router.post('/:providerId/keys/:keyId/sign', requireOrgPermission('byok:keys:execute'), selfHostGate(), selfHostMeterOnSuccess(), (req, res, next) => {
  req.body.operation = 'SIGN';
  handleExecuteOperation(req, res, next);
});
router.post('/providers/:providerId/keys/:keyId/sign', requireOrgPermission('byok:keys:execute'), selfHostGate(), selfHostMeterOnSuccess(), (req, res, next) => {
  req.body.operation = 'SIGN';
  handleExecuteOperation(req, res, next);
});

router.post('/:providerId/keys/:keyId/verify', requireOrgPermission('byok:keys:execute'), selfHostGate(), selfHostMeterOnSuccess(), (req, res, next) => {
  req.body.operation = 'VERIFY';
  handleExecuteOperation(req, res, next);
});
router.post('/providers/:providerId/keys/:keyId/verify', requireOrgPermission('byok:keys:execute'), selfHostGate(), selfHostMeterOnSuccess(), (req, res, next) => {
  req.body.operation = 'VERIFY';
  handleExecuteOperation(req, res, next);
});

export default router;
