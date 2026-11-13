import {
  KeyLifecycleValidator,
  CryptoEngineError,
  KeyLifecycleStatus,
} from '@amaracus/crypto-core';

describe('Phase 5 — Key Lifecycle State Machine & Purpose Enforcement', () => {
  describe('State Machine Transitions', () => {
    test('allows valid lifecycle transitions from PENDING', () => {
      expect(() => KeyLifecycleValidator.validateTransition('PENDING', 'ACTIVE')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateTransition('PENDING', 'DISABLED')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateTransition('PENDING', 'DESTROYED')).not.toThrow();
    });

    test('allows valid lifecycle transitions from ACTIVE', () => {
      expect(() => KeyLifecycleValidator.validateTransition('ACTIVE', 'DISABLED')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateTransition('ACTIVE', 'ROTATING')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateTransition('ACTIVE', 'REVOKED')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateTransition('ACTIVE', 'SCHEDULED_FOR_DELETION')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateTransition('ACTIVE', 'DESTROYED')).not.toThrow();
    });

    test('allows valid lifecycle transitions from DISABLED', () => {
      expect(() => KeyLifecycleValidator.validateTransition('DISABLED', 'ACTIVE')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateTransition('DISABLED', 'REVOKED')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateTransition('DISABLED', 'SCHEDULED_FOR_DELETION')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateTransition('DISABLED', 'DESTROYED')).not.toThrow();
    });

    test('allows recovery from SCHEDULED_FOR_DELETION back to ACTIVE', () => {
      expect(() => KeyLifecycleValidator.validateTransition('SCHEDULED_FOR_DELETION', 'ACTIVE')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateTransition('SCHEDULED_FOR_DELETION', 'DESTROYED')).not.toThrow();
    });

    test('terminal state: DESTROYED can NEVER transition out', () => {
      const targets: KeyLifecycleStatus[] = [
        'PENDING',
        'ACTIVE',
        'DISABLED',
        'ROTATING',
        'REVOKED',
        'SCHEDULED_FOR_DELETION',
      ];

      for (const target of targets) {
        expect(() => KeyLifecycleValidator.validateTransition('DESTROYED', target)).toThrow(
          CryptoEngineError
        );
        try {
          KeyLifecycleValidator.validateTransition('DESTROYED', target);
        } catch (err: any) {
          expect(err.code).toBe('INVALID_STATE_TRANSITION');
          expect(err.message).toMatch(/permanently destroyed/i);
        }
      }
    });

    test('rejects illegal transition: REVOKED cannot return to ACTIVE', () => {
      expect(() => KeyLifecycleValidator.validateTransition('REVOKED', 'ACTIVE')).toThrow(
        CryptoEngineError
      );
      try {
        KeyLifecycleValidator.validateTransition('REVOKED', 'ACTIVE');
      } catch (err: any) {
        expect(err.code).toBe('INVALID_STATE_TRANSITION');
      }
    });

    test('idempotent transition: same-state transition is a no-op', () => {
      expect(() => KeyLifecycleValidator.validateTransition('ACTIVE', 'ACTIVE')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateTransition('DISABLED', 'DISABLED')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateTransition('REVOKED', 'REVOKED')).not.toThrow();
    });
  });

  describe('Operation Permission by State', () => {
    test('permits standard operations on ACTIVE key', () => {
      expect(() => KeyLifecycleValidator.validateOperationAllowed('ACTIVE', 'encrypt')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateOperationAllowed('ACTIVE', 'decrypt')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateOperationAllowed('ACTIVE', 'sign')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateOperationAllowed('ACTIVE', 'verify')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateOperationAllowed('ACTIVE', 'rotate')).not.toThrow();
    });

    test('blocks encryption, signing, and rotation on DISABLED key, but permits decrypt/verify for existing data', () => {
      expect(() => KeyLifecycleValidator.validateOperationAllowed('DISABLED', 'encrypt')).toThrow();
      expect(() => KeyLifecycleValidator.validateOperationAllowed('DISABLED', 'sign')).toThrow();
      expect(() => KeyLifecycleValidator.validateOperationAllowed('DISABLED', 'rotate')).toThrow();
      // Decrypt and verify remain allowed for verification of previously encrypted data
      expect(() => KeyLifecycleValidator.validateOperationAllowed('DISABLED', 'decrypt')).not.toThrow();
      expect(() => KeyLifecycleValidator.validateOperationAllowed('DISABLED', 'verify')).not.toThrow();
    });

    test('blocks all cryptographic use on SCHEDULED_FOR_DELETION key', () => {
      expect(() => KeyLifecycleValidator.validateOperationAllowed('SCHEDULED_FOR_DELETION', 'encrypt')).toThrow();
      expect(() => KeyLifecycleValidator.validateOperationAllowed('SCHEDULED_FOR_DELETION', 'sign')).toThrow();
    });

    test('blocks all operations except historical verify on REVOKED key', () => {
      expect(() => KeyLifecycleValidator.validateOperationAllowed('REVOKED', 'encrypt')).toThrow();
      expect(() => KeyLifecycleValidator.validateOperationAllowed('REVOKED', 'sign')).toThrow();
      expect(() => KeyLifecycleValidator.validateOperationAllowed('REVOKED', 'decrypt')).toThrow();
      expect(() => KeyLifecycleValidator.validateOperationAllowed('REVOKED', 'rotate')).toThrow();
      // Verify is permitted for forensic audit of signatures created before revocation
      expect(() => KeyLifecycleValidator.validateOperationAllowed('REVOKED', 'verify')).not.toThrow();
    });

    test('blocks ALL operations on DESTROYED key', () => {
      const ops = ['encrypt', 'decrypt', 'sign', 'verify', 'rotate'] as const;
      for (const op of ops) {
        expect(() => KeyLifecycleValidator.validateOperationAllowed('DESTROYED', op)).toThrow(
          CryptoEngineError
        );
      }
    });
  });

  describe('Cryptographic Purpose Enforcement', () => {
    test('enforces ENCRYPTION purpose for encrypt/decrypt', () => {
      expect(() => KeyLifecycleValidator.validatePurpose('ENCRYPTION', 'encrypt')).not.toThrow();
      expect(() => KeyLifecycleValidator.validatePurpose('KEY_WRAPPING', 'encrypt')).not.toThrow();
      expect(() => KeyLifecycleValidator.validatePurpose('SIGNING', 'encrypt')).toThrow(CryptoEngineError);
      expect(() => KeyLifecycleValidator.validatePurpose('KEY_AGREEMENT', 'encrypt')).toThrow(CryptoEngineError);
    });

    test('enforces SIGNING purpose for sign/verify', () => {
      expect(() => KeyLifecycleValidator.validatePurpose('SIGNING', 'sign')).not.toThrow();
      expect(() => KeyLifecycleValidator.validatePurpose('SIGNING', 'verify')).not.toThrow();
      expect(() => KeyLifecycleValidator.validatePurpose('ENCRYPTION', 'sign')).toThrow(CryptoEngineError);
      expect(() => KeyLifecycleValidator.validatePurpose('KEY_WRAPPING', 'sign')).toThrow(CryptoEngineError);
    });

    test('enforces KEY_AGREEMENT purpose for derive', () => {
      expect(() => KeyLifecycleValidator.validatePurpose('KEY_AGREEMENT', 'derive')).not.toThrow();
      expect(() => KeyLifecycleValidator.validatePurpose('ENCRYPTION', 'derive')).toThrow(CryptoEngineError);
      expect(() => KeyLifecycleValidator.validatePurpose('SIGNING', 'derive')).toThrow(CryptoEngineError);
    });

    test('enforces KEY_WRAPPING purpose for wrap', () => {
      expect(() => KeyLifecycleValidator.validatePurpose('KEY_WRAPPING', 'wrap')).not.toThrow();
      expect(() => KeyLifecycleValidator.validatePurpose('SIGNING', 'wrap')).toThrow(CryptoEngineError);
    });
  });
});
