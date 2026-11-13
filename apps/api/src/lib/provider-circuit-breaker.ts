export type CircuitBreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerConfig {
  failureThreshold: number; // Number of consecutive failures to trip breaker (default: 5)
  cooldownPeriodMs: number; // Time before transitioning from OPEN to HALF_OPEN (default: 30000ms)
  halfOpenSuccessThreshold: number; // Consecutive successes needed to close breaker (default: 2)
}

export interface ProviderCircuitStatus {
  providerId: string;
  state: CircuitBreakerState;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  lastFailureTime: Date | null;
  lastStateChange: Date;
  totalTrips: number;
}

export class ProviderCircuitBreaker {
  private circuits = new Map<string, ProviderCircuitStatus>();
  private config: CircuitBreakerConfig;

  constructor(config?: Partial<CircuitBreakerConfig>) {
    this.config = {
      failureThreshold: config?.failureThreshold ?? 5,
      cooldownPeriodMs: config?.cooldownPeriodMs ?? 30000,
      halfOpenSuccessThreshold: config?.halfOpenSuccessThreshold ?? 2,
    };
  }

  private getOrCreateCircuit(providerId: string): ProviderCircuitStatus {
    let circuit = this.circuits.get(providerId);
    if (!circuit) {
      circuit = {
        providerId,
        state: 'CLOSED',
        consecutiveFailures: 0,
        consecutiveSuccesses: 0,
        lastFailureTime: null,
        lastStateChange: new Date(),
        totalTrips: 0,
      };
      this.circuits.set(providerId, circuit);
    }
    return circuit;
  }

  getState(providerId: string): CircuitBreakerState {
    const circuit = this.getOrCreateCircuit(providerId);
    const now = Date.now();

    // Check if cooldown has expired for an OPEN breaker
    if (circuit.state === 'OPEN' && circuit.lastFailureTime) {
      if (now - circuit.lastFailureTime.getTime() >= this.config.cooldownPeriodMs) {
        circuit.state = 'HALF_OPEN';
        circuit.consecutiveSuccesses = 0;
        circuit.lastStateChange = new Date();
      }
    }

    return circuit.state;
  }

  isOpen(providerId: string): boolean {
    return this.getState(providerId) === 'OPEN';
  }

  recordSuccess(providerId: string): void {
    const circuit = this.getOrCreateCircuit(providerId);
    circuit.consecutiveFailures = 0;

    if (circuit.state === 'HALF_OPEN') {
      circuit.consecutiveSuccesses += 1;
      if (circuit.consecutiveSuccesses >= this.config.halfOpenSuccessThreshold) {
        circuit.state = 'CLOSED';
        circuit.consecutiveSuccesses = 0;
        circuit.lastStateChange = new Date();
      }
    }
  }

  recordFailure(providerId: string, err?: any): void {
    const circuit = this.getOrCreateCircuit(providerId);
    const now = new Date();
    circuit.lastFailureTime = now;
    circuit.consecutiveFailures += 1;

    // Check if error is a rate-limit / throttle (e.g., Azure 429) or upstream outage (503/504)
    const isThrottled = err?.statusCode === 429 || err?.code === 'TOO_MANY_REQUESTS' || err?.message?.includes('429');
    
    // Throttling trips immediately or after reduced threshold
    const effectiveThreshold = isThrottled ? Math.min(2, this.config.failureThreshold) : this.config.failureThreshold;

    if (circuit.state === 'CLOSED' && circuit.consecutiveFailures >= effectiveThreshold) {
      circuit.state = 'OPEN';
      circuit.totalTrips += 1;
      circuit.lastStateChange = now;
    } else if (circuit.state === 'HALF_OPEN') {
      // Re-trip immediately if probe failed
      circuit.state = 'OPEN';
      circuit.totalTrips += 1;
      circuit.lastStateChange = now;
    }
  }

  async execute<T>(
    providerId: string,
    operation: () => Promise<T>,
    fallback?: () => Promise<T>
  ): Promise<T> {
    if (this.isOpen(providerId)) {
      if (fallback) {
        return fallback();
      }
      const err: any = new Error(
        `Cryptographic provider '${providerId}' circuit breaker is OPEN due to upstream throttling or failures.`
      );
      err.code = 'PROVIDER_CIRCUIT_OPEN';
      err.statusCode = 503;
      err.retryable = true;
      throw err;
    }

    try {
      const result = await operation();
      this.recordSuccess(providerId);
      return result;
    } catch (err: any) {
      this.recordFailure(providerId, err);
      if (fallback && this.isOpen(providerId)) {
        return fallback();
      }
      throw err;
    }
  }

  getAllStatuses(): ProviderCircuitStatus[] {
    return Array.from(this.circuits.values()).map((c) => ({
      ...c,
      state: this.getState(c.providerId),
    }));
  }

  reset(): void {
    this.circuits.clear();
  }
}

export const providerCircuitBreaker = new ProviderCircuitBreaker();
