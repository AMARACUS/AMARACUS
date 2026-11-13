import {
  ProviderOnboardingStateMachine,
  ProviderOnboardingState,
  CryptoEngineError,
} from '@amaracus/crypto-core';

describe('Phase 5.4 — Provider Onboarding State Machine', () => {
  describe('1. Valid State Transitions', () => {
    test('allows sequential happy path from NOT_STARTED to READY', () => {
      // NOT_STARTED -> CONFIGURED
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('NOT_STARTED', 'CONFIGURED');
      }).not.toThrow();

      // CONFIGURED -> CONNECTION_TESTING
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CONFIGURED', 'CONNECTION_TESTING');
      }).not.toThrow();

      // CONNECTION_TESTING -> CONNECTED
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CONNECTION_TESTING', 'CONNECTED');
      }).not.toThrow();

      // CONNECTED -> CAPABILITY_DISCOVERY
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CONNECTED', 'CAPABILITY_DISCOVERY');
      }).not.toThrow();

      // CAPABILITY_DISCOVERY -> READY
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CAPABILITY_DISCOVERY', 'READY');
      }).not.toThrow();
    });

    test('allows transition through CONFIGURATION_REQUIRED', () => {
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('NOT_STARTED', 'CONFIGURATION_REQUIRED');
      }).not.toThrow();

      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CONFIGURATION_REQUIRED', 'CONFIGURED');
      }).not.toThrow();
    });

    test('allows identity self-transitions (no-op)', () => {
      const states: ProviderOnboardingState[] = [
        'NOT_STARTED',
        'CONFIGURATION_REQUIRED',
        'CONFIGURED',
        'CONNECTION_TESTING',
        'CONNECTION_FAILED',
        'CONNECTED',
        'CAPABILITY_DISCOVERY',
        'CAPABILITY_DISCOVERY_FAILED',
        'READY',
        'DISCONNECTED',
      ];
      for (const s of states) {
        expect(() => ProviderOnboardingStateMachine.validateTransition(s, s)).not.toThrow();
      }
    });

    test('allows retry transition after connection failure', () => {
      // CONNECTION_TESTING -> CONNECTION_FAILED
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CONNECTION_TESTING', 'CONNECTION_FAILED');
      }).not.toThrow();

      // CONNECTION_FAILED -> CONNECTION_TESTING (Retry)
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CONNECTION_FAILED', 'CONNECTION_TESTING');
      }).not.toThrow();

      // Retry succeeds -> CONNECTED
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CONNECTION_TESTING', 'CONNECTED');
      }).not.toThrow();
    });

    test('allows retry transition after capability discovery failure', () => {
      // CAPABILITY_DISCOVERY -> CAPABILITY_DISCOVERY_FAILED
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CAPABILITY_DISCOVERY', 'CAPABILITY_DISCOVERY_FAILED');
      }).not.toThrow();

      // CAPABILITY_DISCOVERY_FAILED -> CAPABILITY_DISCOVERY (Retry)
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CAPABILITY_DISCOVERY_FAILED', 'CAPABILITY_DISCOVERY');
      }).not.toThrow();

      // Retry succeeds -> READY
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CAPABILITY_DISCOVERY', 'READY');
      }).not.toThrow();
    });

    test('allows disconnect from READY, CONNECTED, and FAILED states', () => {
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('READY', 'DISCONNECTED');
      }).not.toThrow();

      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CONNECTED', 'DISCONNECTED');
      }).not.toThrow();

      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CAPABILITY_DISCOVERY_FAILED', 'DISCONNECTED');
      }).not.toThrow();

      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CONNECTION_FAILED', 'DISCONNECTED');
      }).not.toThrow();
    });

    test('allows re-onboarding after DISCONNECTED', () => {
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('DISCONNECTED', 'CONFIGURATION_REQUIRED');
      }).not.toThrow();

      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('DISCONNECTED', 'CONFIGURED');
      }).not.toThrow();
    });
  });

  describe('2. Rejection of Invalid State Transitions', () => {
    test('strictly rejects NOT_STARTED -> READY', () => {
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('NOT_STARTED', 'READY');
      }).toThrow(/Cannot transition directly from NOT_STARTED to READY/);
    });

    test('strictly rejects CONFIGURATION_REQUIRED -> READY', () => {
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CONFIGURATION_REQUIRED', 'READY');
      }).toThrow(/Cannot transition from CONFIGURATION_REQUIRED to READY/);
    });

    test('strictly rejects CONFIGURED -> READY (skipping testing and discovery)', () => {
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CONFIGURED', 'READY');
      }).toThrow(/Cannot transition from CONFIGURED directly to READY/);
    });

    test('strictly rejects CONNECTED -> READY (skipping capability discovery)', () => {
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CONNECTED', 'READY');
      }).toThrow(/Cannot transition from CONNECTED to READY without completing capability discovery/);
    });

    test('strictly rejects CAPABILITY_DISCOVERY_FAILED -> READY', () => {
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CAPABILITY_DISCOVERY_FAILED', 'READY');
      }).toThrow(/Cannot transition from CAPABILITY_DISCOVERY_FAILED to READY/);
    });

    test('strictly rejects DISCONNECTED -> READY', () => {
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('DISCONNECTED', 'READY');
      }).toThrow(/Cannot transition from DISCONNECTED to READY without completing onboarding again/);
    });

    test('strictly rejects illegal backward or cross jumps', () => {
      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('NOT_STARTED', 'CONNECTED');
      }).toThrow(CryptoEngineError);

      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('READY', 'CONFIGURED');
      }).toThrow(CryptoEngineError);

      expect(() => {
        ProviderOnboardingStateMachine.validateTransition('CONNECTED', 'CONFIGURATION_REQUIRED');
      }).toThrow(CryptoEngineError);
    });
  });

  describe('3. Canonical Progress and NextAction Derivation', () => {
    test('calculates progress for CONFIGURED state', () => {
      const progress = ProviderOnboardingStateMachine.computeProgress('CONFIGURED', false);
      expect(progress.configuration).toBe('COMPLETE');
      expect(progress.connection).toBe('NOT_STARTED');
      expect(progress.capabilities).toBe('NOT_STARTED');
      expect(progress.keyRegistration).toBe('NOT_STARTED');

      const nextAction = ProviderOnboardingStateMachine.determineNextAction('CONFIGURED', false);
      expect(nextAction).toBe('TEST_CONNECTION');
      expect(ProviderOnboardingStateMachine.canProceed('CONFIGURED')).toBe(false);
    });

    test('calculates progress for CONNECTION_FAILED state', () => {
      const progress = ProviderOnboardingStateMachine.computeProgress('CONNECTION_FAILED', false);
      expect(progress.configuration).toBe('COMPLETE');
      expect(progress.connection).toBe('FAILED');
      expect(progress.capabilities).toBe('NOT_STARTED');

      const nextAction = ProviderOnboardingStateMachine.determineNextAction('CONNECTION_FAILED', false);
      expect(nextAction).toBe('RETRY_CONNECTION');
      expect(ProviderOnboardingStateMachine.canProceed('CONNECTION_FAILED')).toBe(false);
    });

    test('calculates progress for CONNECTED state', () => {
      const progress = ProviderOnboardingStateMachine.computeProgress('CONNECTED', false);
      expect(progress.configuration).toBe('COMPLETE');
      expect(progress.connection).toBe('COMPLETE');
      expect(progress.capabilities).toBe('NOT_STARTED');

      const nextAction = ProviderOnboardingStateMachine.determineNextAction('CONNECTED', false);
      expect(nextAction).toBe('DISCOVER_CAPABILITIES');
      expect(ProviderOnboardingStateMachine.canProceed('CONNECTED')).toBe(false);
    });

    test('calculates progress for CAPABILITY_DISCOVERY_FAILED state', () => {
      const progress = ProviderOnboardingStateMachine.computeProgress('CAPABILITY_DISCOVERY_FAILED', false);
      expect(progress.configuration).toBe('COMPLETE');
      expect(progress.connection).toBe('COMPLETE');
      expect(progress.capabilities).toBe('FAILED');

      const nextAction = ProviderOnboardingStateMachine.determineNextAction('CAPABILITY_DISCOVERY_FAILED', false);
      expect(nextAction).toBe('RETRY_CAPABILITY_DISCOVERY');
      expect(ProviderOnboardingStateMachine.canProceed('CAPABILITY_DISCOVERY_FAILED')).toBe(false);
    });

    test('calculates progress for READY state without keys', () => {
      const progress = ProviderOnboardingStateMachine.computeProgress('READY', false);
      expect(progress.configuration).toBe('COMPLETE');
      expect(progress.connection).toBe('COMPLETE');
      expect(progress.capabilities).toBe('COMPLETE');
      expect(progress.keyRegistration).toBe('NOT_STARTED');

      const nextAction = ProviderOnboardingStateMachine.determineNextAction('READY', false);
      expect(nextAction).toBe('REGISTER_KEY');
      expect(ProviderOnboardingStateMachine.canProceed('READY')).toBe(true);
    });

    test('calculates progress for READY state with registered keys', () => {
      const progress = ProviderOnboardingStateMachine.computeProgress('READY', true);
      expect(progress.keyRegistration).toBe('COMPLETE');

      const nextAction = ProviderOnboardingStateMachine.determineNextAction('READY', true);
      expect(nextAction).toBe('READY');
      expect(ProviderOnboardingStateMachine.canProceed('READY')).toBe(true);
    });

    test('generates canonical OnboardingStatusResponse', () => {
      const status = ProviderOnboardingStateMachine.getStatus('byp_test_123', 'READY', true);
      expect(status.providerId).toBe('byp_test_123');
      expect(status.state).toBe('READY');
      expect(status.progress.capabilities).toBe('COMPLETE');
      expect(status.nextAction).toBe('READY');
      expect(status.canProceed).toBe(true);
    });
  });
});
