import {
  cryptographicRuntime,
  KeyResolver,
  KeyReference,
  AuditSink,
  IdempotencyStore,
  OperationStateObserver,
  OperationStatus,
  CryptographicOperationResult,
  TenantContext,
  CryptographicOperationRequest,
  OperationType,
} from '@amaracus/crypto-core';
import { db } from './data-store';
import { currentRequestContext } from './request-context';
import { noteDecrypt } from './decrypt-alerts';
import { usageMeter } from './usage-meter';

export class DataStoreKeyResolver implements KeyResolver {
  async resolveKey(
    keyIdOrName: string,
    organizationId: string,
    projectId?: string | null,
    environmentId?: string | null
  ): Promise<KeyReference | null> {
    let key = await db.findKeyById(keyIdOrName, organizationId);
    if (!key && projectId && environmentId) {
      key = await db.findKeyByName(organizationId, projectId, environmentId, keyIdOrName);
    }
    if (!key) return null;

    const currentVer = await db.findKeyVersionByNumber(key.id, key.currentVersion);
    const providerKeyId = currentVer?.providerKeyId || key.id;
    const allVersions = await db.listKeyVersions(key.id);

    return {
      id: key.id,
      name: key.name,
      organizationId: key.organizationId,
      projectId: key.projectId,
      environmentId: key.environmentId,
      algorithm: key.algorithm,
      purpose: key.purpose,
      provider: key.provider,
      providerKeyId,
      currentVersion: key.currentVersion,
      status: key.status,
      isHsmBacked: key.provider === 'AZURE_MANAGED_HSM',
      isCustomerManaged: key.provider?.startsWith('CUSTOMER_') || false,
      publicKey: currentVer?.publicKey,
      encryptedKeyMaterial: currentVer?.encryptedKeyMaterial,
      metadata: key.metadata,
      versions: allVersions.map((v) => ({
        version: v.version,
        providerKeyId: v.providerKeyId || key.id,
        status: v.status,
        publicKey: v.publicKey,
        encryptedKeyMaterial: v.encryptedKeyMaterial,
      })),
    };
  }
}

export class DbAuditSink implements AuditSink {
  async logOperation(event: {
    operationId: string;
    requestId: string;
    action: string;
    organizationId: string;
    projectId?: string | null;
    environmentId?: string | null;
    actorId?: string | null;
    providerId: string;
    algorithm?: string | null;
    keyId?: string | null;
    status: 'SUCCESS' | 'FAILED';
    durationMs: number;
    error?: string;
  }): Promise<void> {
    const { ipAddress, userAgent, apiKeyId } = currentRequestContext();
    try {
      if (event.action === 'crypto.decrypt' && event.status === 'SUCCESS') {
        noteDecrypt({
          organizationId: event.organizationId,
          actorId: event.actorId,
          ipAddress,
          isApiKey: Boolean(apiKeyId) && apiKeyId === event.actorId,
        }).catch((err) =>
          console.error('[DecryptAlerts] Could not record decrypt:', err?.message || err)
        );
      }
      await db.createAuditEvent({
        organizationId: event.organizationId || null,
        userId: event.actorId || null,
        ipAddress,
        userAgent,
        action: event.action,
        resourceType: 'CryptographicOperation',
        resourceId: event.keyId || event.algorithm || event.operationId,
        metadata: {
          operationId: event.operationId,
          requestId: event.requestId,
          providerId: event.providerId,
          algorithm: event.algorithm,
          status: event.status,
          durationMs: event.durationMs,
          error: event.error,
        },
      });

      if (event.status === 'SUCCESS' && event.organizationId) {
        await usageMeter.recordOperation({
          organizationId: event.organizationId,
          operationType: event.action.replace(/^crypto\./, '').toUpperCase(),
          quantity: 1,
          operationId: event.operationId,
        });
      }
    } catch (err) {
      console.warn('[Audit Sink Warning] Failed to log operation audit or record usage:', err);
    }
  }
}

export class DbIdempotencyStore implements IdempotencyStore {
  private cache = new Map<string, CryptographicOperationResult>();

  async get(key: string): Promise<CryptographicOperationResult | null> {
    const memoryCached = this.cache.get(key);
    if (memoryCached) return memoryCached;

    return null;
  }

  async set(key: string, result: CryptographicOperationResult): Promise<void> {
    this.cache.set(key, result);
  }
}

export class DbOperationStateObserver implements OperationStateObserver {
  private opRecordIds = new Map<string, string>();

  async onTransition(
    operationId: string,
    status: OperationStatus,
    metadata?: Record<string, any>
  ): Promise<void> {
    try {
      let recordId = this.opRecordIds.get(operationId);
      if (!recordId) {
        const existing = await db.getCryptographicOperation(operationId);
        if (existing) {
          recordId = existing.id;
          this.opRecordIds.set(operationId, recordId);
        }
      }

      if (!recordId) {
        // Initial creation or first status report
        const created = await db.createCryptographicOperation({
          id: operationId,
          operationType: metadata?.type || 'UNKNOWN',
          status,
          organizationId: metadata?.organizationId || 'default',
          projectId: metadata?.projectId || null,
          environmentId: metadata?.environmentId || null,
          algorithm: metadata?.algorithm || null,
          keyId: metadata?.keyId || null,
          providerId: metadata?.providerId || null,
          durationMs: metadata?.durationMs || null,
          metadata,
          error: metadata?.error ? { message: metadata.error } : null,
        });
        this.opRecordIds.set(operationId, created.id);
      } else {
        await db.updateCryptographicOperation(recordId, {
          status,
          durationMs: metadata?.durationMs !== undefined ? metadata.durationMs : undefined,
          providerId: metadata?.providerId !== undefined ? metadata.providerId : undefined,
          metadata: metadata ? { ...metadata } : undefined,
          error: metadata?.error ? { message: metadata.error } : undefined,
        });
      }
    } catch (err) {
      // Non-blocking observer failure
    }
  }
}

// Wire dependencies to the unified runtime singleton
const keyResolver = new DataStoreKeyResolver();
const auditSink = new DbAuditSink();
const idempotencyStore = new DbIdempotencyStore();
const stateObserver = new DbOperationStateObserver();

cryptographicRuntime.setKeyResolver(keyResolver);
cryptographicRuntime.setAuditSink(auditSink);
cryptographicRuntime.setIdempotencyStore(idempotencyStore);
cryptographicRuntime.setStateObserver(stateObserver);

export {
  cryptographicRuntime,
  keyResolver,
  auditSink,
  idempotencyStore,
  stateObserver,
};
