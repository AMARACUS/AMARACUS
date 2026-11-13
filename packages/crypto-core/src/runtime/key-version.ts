/**
 * Key-version selection for managed keys.
 *
 * Only the current, ACTIVE version may encrypt or sign. Decrypt and verify use the
 * version the caller names (or the current one) and accept ACTIVE or DEPRECATED
 * versions. Anything else fails closed: the runtime never tries other versions.
 */

import { KeyReference } from './key-reference';
import { KeyLifecycleValidator } from '../keys/state-machine';
import { KeyLifecycleStatus } from '../keys/types';
import { CryptoEngineError } from '../errors';

type KeyUse = 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'rotate';

const USE_BY_OPERATION: Record<string, KeyUse> = {
  ENCRYPT: 'encrypt',
  DECRYPT: 'decrypt',
  SIGN: 'sign',
  PQC_SIGN: 'sign',
  VERIFY: 'verify',
  PQC_VERIFY: 'verify',
  KEY_ROTATION: 'rotate',
};

const READ_ONLY_VERSION_STATES = new Set(['ACTIVE', 'DEPRECATED']);

/**
 * Validates the key and version state for an operation and returns a reference
 * pinned to the selected version (providerKeyId and key material of that version).
 */
export function selectKeyVersion(
  keyRef: KeyReference,
  operationType: string,
  requestedVersion?: number | string | null
): KeyReference {
  const use = USE_BY_OPERATION[operationType];
  if (!use) return keyRef;

  KeyLifecycleValidator.validateOperationAllowed(String(keyRef.status).toUpperCase() as KeyLifecycleStatus, use);

  const current = Number(keyRef.currentVersion) || 1;
  const hasRequested = requestedVersion !== undefined && requestedVersion !== null && requestedVersion !== '';
  const requested = hasRequested ? Number(requestedVersion) : current;
  if (!Number.isInteger(requested) || requested < 1) {
    throw new CryptoEngineError('INVALID_REQUEST', `Invalid key version '${requestedVersion}'.`, 400);
  }

  const producesOutput = use === 'encrypt' || use === 'sign';
  if (producesOutput && requested !== current) {
    throw new CryptoEngineError(
      'KEY_DISABLED',
      `Only the current version (${current}) of key '${keyRef.id}' can ${use}; version ${requested} is not active.`,
      400,
      { keyId: keyRef.id, version: requested, currentVersion: current }
    );
  }

  // References built without a version list (e.g. tests, raw providers) pin to the current version
  if (!keyRef.versions || keyRef.versions.length === 0) {
    if (requested !== current) {
      throw new CryptoEngineError('KEY_NOT_FOUND', `Key '${keyRef.id}' has no version ${requested}.`, 404);
    }
    return keyRef;
  }

  const version = keyRef.versions.find((v) => Number(v.version) === requested);
  if (!version) {
    throw new CryptoEngineError('KEY_NOT_FOUND', `Key '${keyRef.id}' has no version ${requested}.`, 404, {
      keyId: keyRef.id,
      version: requested,
    });
  }

  const status = String(version.status || 'ACTIVE').toUpperCase();
  const allowed = producesOutput || use === 'rotate' ? status === 'ACTIVE' : READ_ONLY_VERSION_STATES.has(status);
  if (!allowed) {
    throw new CryptoEngineError(
      'KEY_DISABLED',
      `Version ${requested} of key '${keyRef.id}' is ${status} and cannot be used to ${use}.`,
      400,
      { keyId: keyRef.id, version: requested, status }
    );
  }

  return {
    ...keyRef,
    currentVersion: requested,
    providerKeyId: version.providerKeyId || keyRef.providerKeyId,
    publicKey: version.publicKey ?? keyRef.publicKey,
    encryptedKeyMaterial: version.encryptedKeyMaterial ?? keyRef.encryptedKeyMaterial,
  };
}
