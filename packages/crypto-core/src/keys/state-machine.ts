import { KeyLifecycleStatus, KeyPurpose } from './types';
import { CryptoEngineError } from '../errors';

const LEGAL_TRANSITIONS: Record<KeyLifecycleStatus, Set<KeyLifecycleStatus>> = {
  PENDING: new Set<KeyLifecycleStatus>(['ACTIVE', 'DISABLED', 'DESTROYED']),
  ACTIVE: new Set<KeyLifecycleStatus>(['DISABLED', 'ROTATING', 'REVOKED', 'SCHEDULED_FOR_DELETION', 'DESTROYED']),
  DISABLED: new Set<KeyLifecycleStatus>(['ACTIVE', 'REVOKED', 'SCHEDULED_FOR_DELETION', 'DESTROYED']),
  ROTATING: new Set<KeyLifecycleStatus>(['ACTIVE', 'DISABLED', 'REVOKED', 'DESTROYED']),
  REVOKED: new Set<KeyLifecycleStatus>(['SCHEDULED_FOR_DELETION', 'DESTROYED']),
  SCHEDULED_FOR_DELETION: new Set<KeyLifecycleStatus>(['ACTIVE', 'DESTROYED']),
  DESTROYED: new Set<KeyLifecycleStatus>([]), // Terminal state: NEVER allows transition out
};

export class KeyLifecycleValidator {
  static validateTransition(current: KeyLifecycleStatus, target: KeyLifecycleStatus): void {
    if (current === target) return;

    if (current === 'DESTROYED') {
      throw new CryptoEngineError(
        'INVALID_STATE_TRANSITION',
        'Key has been permanently destroyed and cannot be modified or reactivated.'
      );
    }

    const legal = LEGAL_TRANSITIONS[current];
    if (!legal || !legal.has(target)) {
      throw new CryptoEngineError(
        'INVALID_STATE_TRANSITION',
        `Illegal lifecycle transition from ${current} to ${target}.`
      );
    }
  }

  static validateOperationAllowed(
    status: KeyLifecycleStatus,
    operation: 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'rotate'
  ): void {
    if (status === 'DESTROYED') {
      throw new CryptoEngineError('KEY_DESTROYED', 'Cryptographic key has been permanently destroyed.');
    }

    if (status === 'SCHEDULED_FOR_DELETION') {
      throw new CryptoEngineError(
        'KEY_DISABLED',
        'Cryptographic key is scheduled for deletion and cannot be used.'
      );
    }

    if (status === 'REVOKED') {
      if (operation !== 'verify') {
        throw new CryptoEngineError(
          'KEY_REVOKED',
          `Cryptographic key is revoked and cannot be used for ${operation}.`
        );
      }
    }

    if (status === 'DISABLED') {
      if (operation === 'encrypt' || operation === 'sign' || operation === 'rotate') {
        throw new CryptoEngineError(
          'KEY_DISABLED',
          `Cryptographic key is disabled and cannot be used for ${operation}.`
        );
      }
    }
  }

  static validatePurpose(declaredPurpose: KeyPurpose, operation: 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'derive' | 'wrap'): void {
    switch (operation) {
      case 'encrypt':
      case 'decrypt':
        if (declaredPurpose !== 'ENCRYPTION' && declaredPurpose !== 'KEY_WRAPPING') {
          throw new CryptoEngineError(
            'INVALID_PURPOSE',
            `Key purpose is '${declaredPurpose}', which does not permit '${operation}'. Encryption requires ENCRYPTION or KEY_WRAPPING purpose.`
          );
        }
        break;
      case 'sign':
      case 'verify':
        if (declaredPurpose !== 'SIGNING') {
          throw new CryptoEngineError(
            'INVALID_PURPOSE',
            `Key purpose is '${declaredPurpose}', which does not permit '${operation}'. Digital signing requires SIGNING purpose.`
          );
        }
        break;
      case 'derive':
        if (declaredPurpose !== 'KEY_AGREEMENT') {
          throw new CryptoEngineError(
            'INVALID_PURPOSE',
            `Key purpose is '${declaredPurpose}', which does not permit key agreement.`
          );
        }
        break;
      case 'wrap':
        if (declaredPurpose !== 'KEY_WRAPPING') {
          throw new CryptoEngineError(
            'INVALID_PURPOSE',
            `Key purpose is '${declaredPurpose}', which does not permit key wrapping.`
          );
        }
        break;
    }
  }
}
