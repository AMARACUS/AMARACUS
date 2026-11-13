import { CryptoEngineError } from '../errors';

export type ProviderOnboardingState =
  | 'NOT_STARTED'
  | 'CONFIGURATION_REQUIRED'
  | 'CONFIGURED'
  | 'CONNECTION_TESTING'
  | 'CONNECTION_FAILED'
  | 'CONNECTED'
  | 'CAPABILITY_DISCOVERY'
  | 'CAPABILITY_DISCOVERY_FAILED'
  | 'READY'
  | 'DISCONNECTED';

export type OnboardingNextAction =
  | 'CONFIGURE_PROVIDER'
  | 'TEST_CONNECTION'
  | 'RETRY_CONNECTION'
  | 'DISCOVER_CAPABILITIES'
  | 'WAIT_FOR_CAPABILITY_DISCOVERY'
  | 'RETRY_CAPABILITY_DISCOVERY'
  | 'REGISTER_KEY'
  | 'READY'
  | 'DISCONNECT'
  | 'REVIEW_ERROR';

export interface OnboardingProgress {
  configuration: 'NOT_STARTED' | 'IN_PROGRESS' | 'COMPLETE';
  connection: 'NOT_STARTED' | 'IN_PROGRESS' | 'FAILED' | 'COMPLETE';
  capabilities: 'NOT_STARTED' | 'IN_PROGRESS' | 'FAILED' | 'COMPLETE';
  keyRegistration: 'NOT_STARTED' | 'IN_PROGRESS' | 'COMPLETE';
}

export interface OnboardingStatusResponse {
  providerId: string;
  state: ProviderOnboardingState;
  progress: OnboardingProgress;
  nextAction: OnboardingNextAction;
  canProceed: boolean;
}

const LEGAL_ONBOARDING_TRANSITIONS: Record<ProviderOnboardingState, Set<ProviderOnboardingState>> = {
  NOT_STARTED: new Set<ProviderOnboardingState>(['CONFIGURATION_REQUIRED', 'CONFIGURED', 'DISCONNECTED']),
  CONFIGURATION_REQUIRED: new Set<ProviderOnboardingState>(['CONFIGURED', 'DISCONNECTED']),
  CONFIGURED: new Set<ProviderOnboardingState>(['CONNECTION_TESTING', 'CONFIGURATION_REQUIRED', 'DISCONNECTED']),
  CONNECTION_TESTING: new Set<ProviderOnboardingState>(['CONNECTED', 'CONNECTION_FAILED', 'DISCONNECTED']),
  CONNECTION_FAILED: new Set<ProviderOnboardingState>(['CONNECTION_TESTING', 'CONFIGURATION_REQUIRED', 'DISCONNECTED']),
  CONNECTED: new Set<ProviderOnboardingState>(['CAPABILITY_DISCOVERY', 'READY', 'DISCONNECTED']),
  CAPABILITY_DISCOVERY: new Set<ProviderOnboardingState>(['READY', 'CAPABILITY_DISCOVERY_FAILED', 'DISCONNECTED']),
  CAPABILITY_DISCOVERY_FAILED: new Set<ProviderOnboardingState>(['CAPABILITY_DISCOVERY', 'DISCONNECTED', 'CONFIGURATION_REQUIRED']),
  READY: new Set<ProviderOnboardingState>(['DISCONNECTED', 'CAPABILITY_DISCOVERY', 'CONNECTION_TESTING']),
  DISCONNECTED: new Set<ProviderOnboardingState>(['CONFIGURATION_REQUIRED', 'CONFIGURED']),
};

export class ProviderOnboardingStateMachine {
  /**
   * Validates whether a transition from current state to target state is permissible.
   * Throws CryptoEngineError('INVALID_STATE_TRANSITION', ...) on illegal transitions.
   */
  static validateTransition(current: ProviderOnboardingState, target: ProviderOnboardingState): void {
    if (current === target) return;

    // Explicit check for impossible leaps to READY as mandated by Phase 5.4 specifications
    if (target === 'READY') {
      if (current === 'NOT_STARTED') {
        throw new CryptoEngineError(
          'INVALID_STATE_TRANSITION',
          'Cannot transition directly from NOT_STARTED to READY. Provider must be configured, connected, and have capabilities discovered.'
        );
      }
      if (current === 'CONFIGURATION_REQUIRED') {
        throw new CryptoEngineError(
          'INVALID_STATE_TRANSITION',
          'Cannot transition from CONFIGURATION_REQUIRED to READY. Provider configuration must be completed and verified.'
        );
      }
      if (current === 'CONFIGURED') {
        throw new CryptoEngineError(
          'INVALID_STATE_TRANSITION',
          'Cannot transition from CONFIGURED directly to READY without completing connection test and capability discovery.'
        );
      }
      if (current === 'CONNECTED') {
        throw new CryptoEngineError(
          'INVALID_STATE_TRANSITION',
          'Cannot transition from CONNECTED to READY without completing capability discovery.'
        );
      }
      if (current === 'CAPABILITY_DISCOVERY_FAILED') {
        throw new CryptoEngineError(
          'INVALID_STATE_TRANSITION',
          'Cannot transition from CAPABILITY_DISCOVERY_FAILED to READY until capability discovery succeeds.'
        );
      }
      if (current === 'DISCONNECTED') {
        throw new CryptoEngineError(
          'INVALID_STATE_TRANSITION',
          'Cannot transition from DISCONNECTED to READY without completing onboarding again.'
        );
      }
    }

    const legalTargets = LEGAL_ONBOARDING_TRANSITIONS[current];
    if (!legalTargets || !legalTargets.has(target)) {
      throw new CryptoEngineError(
        'INVALID_STATE_TRANSITION',
        `Illegal provider onboarding state transition from ${current} to ${target}.`
      );
    }
  }

  /**
   * Derives standardized 4-phase progress from current state and key registration status.
   */
  static computeProgress(state: ProviderOnboardingState, hasRegisteredKeys: boolean = false): OnboardingProgress {
    switch (state) {
      case 'NOT_STARTED':
        return {
          configuration: 'NOT_STARTED',
          connection: 'NOT_STARTED',
          capabilities: 'NOT_STARTED',
          keyRegistration: 'NOT_STARTED',
        };
      case 'CONFIGURATION_REQUIRED':
        return {
          configuration: 'IN_PROGRESS',
          connection: 'NOT_STARTED',
          capabilities: 'NOT_STARTED',
          keyRegistration: 'NOT_STARTED',
        };
      case 'CONFIGURED':
        return {
          configuration: 'COMPLETE',
          connection: 'NOT_STARTED',
          capabilities: 'NOT_STARTED',
          keyRegistration: 'NOT_STARTED',
        };
      case 'CONNECTION_TESTING':
        return {
          configuration: 'COMPLETE',
          connection: 'IN_PROGRESS',
          capabilities: 'NOT_STARTED',
          keyRegistration: 'NOT_STARTED',
        };
      case 'CONNECTION_FAILED':
        return {
          configuration: 'COMPLETE',
          connection: 'FAILED',
          capabilities: 'NOT_STARTED',
          keyRegistration: 'NOT_STARTED',
        };
      case 'CONNECTED':
        return {
          configuration: 'COMPLETE',
          connection: 'COMPLETE',
          capabilities: 'NOT_STARTED',
          keyRegistration: 'NOT_STARTED',
        };
      case 'CAPABILITY_DISCOVERY':
        return {
          configuration: 'COMPLETE',
          connection: 'COMPLETE',
          capabilities: 'IN_PROGRESS',
          keyRegistration: 'NOT_STARTED',
        };
      case 'CAPABILITY_DISCOVERY_FAILED':
        return {
          configuration: 'COMPLETE',
          connection: 'COMPLETE',
          capabilities: 'FAILED',
          keyRegistration: 'NOT_STARTED',
        };
      case 'READY':
        return {
          configuration: 'COMPLETE',
          connection: 'COMPLETE',
          capabilities: 'COMPLETE',
          keyRegistration: hasRegisteredKeys ? 'COMPLETE' : 'NOT_STARTED',
        };
      case 'DISCONNECTED':
        return {
          configuration: 'NOT_STARTED',
          connection: 'NOT_STARTED',
          capabilities: 'NOT_STARTED',
          keyRegistration: 'NOT_STARTED',
        };
      default:
        return {
          configuration: 'NOT_STARTED',
          connection: 'NOT_STARTED',
          capabilities: 'NOT_STARTED',
          keyRegistration: 'NOT_STARTED',
        };
    }
  }

  /**
   * Determines the canonical nextAction for the current state.
   */
  static determineNextAction(state: ProviderOnboardingState, hasRegisteredKeys: boolean = false): OnboardingNextAction {
    switch (state) {
      case 'NOT_STARTED':
      case 'CONFIGURATION_REQUIRED':
      case 'DISCONNECTED':
        return 'CONFIGURE_PROVIDER';
      case 'CONFIGURED':
        return 'TEST_CONNECTION';
      case 'CONNECTION_TESTING':
        return 'REVIEW_ERROR';
      case 'CONNECTION_FAILED':
        return 'RETRY_CONNECTION';
      case 'CONNECTED':
        return 'DISCOVER_CAPABILITIES';
      case 'CAPABILITY_DISCOVERY':
        return 'WAIT_FOR_CAPABILITY_DISCOVERY';
      case 'CAPABILITY_DISCOVERY_FAILED':
        return 'RETRY_CAPABILITY_DISCOVERY';
      case 'READY':
        return hasRegisteredKeys ? 'READY' : 'REGISTER_KEY';
      default:
        return 'CONFIGURE_PROVIDER';
    }
  }

  /**
   * Determines whether the onboarding state allows proceeding to cryptographic operations or next phase.
   */
  static canProceed(state: ProviderOnboardingState): boolean {
    return state === 'READY';
  }

  /**
   * Generates the canonical OnboardingStatusResponse for an organization/provider.
   */
  static getStatus(
    providerId: string,
    state: ProviderOnboardingState,
    hasRegisteredKeys: boolean = false
  ): OnboardingStatusResponse {
    return {
      providerId,
      state,
      progress: this.computeProgress(state, hasRegisteredKeys),
      nextAction: this.determineNextAction(state, hasRegisteredKeys),
      canProceed: this.canProceed(state),
    };
  }
}
