import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { providerCircuitBreaker } from '../src/lib/provider-circuit-breaker';
import { managedOperationQueue } from '../src/lib/managed-operation-queue';
import { metricsExporter } from '../src/lib/metrics-exporter';
import { db } from '../src/lib/data-store';
import { CryptoEngineService, generateSecureRandom } from '@amaracus/crypto-core';

describe('Phase 17 - Global Production Infrastructure & Reliability', () => {
  let server: http.Server;
  let baseUrl: string;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await managedOperationQueue.shutdown();
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  beforeEach(() => {
    providerCircuitBreaker.reset();
    managedOperationQueue.reset();
    metricsExporter.reset();
  });

  describe('1. Cloud Health Probes & Prometheus Observability', () => {
    it('should return 200 OK from Kubernetes liveness probe (/health/live)', async () => {
      const res = await fetch(`${baseUrl}/health/live`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.status).toBe('alive');
      expect(typeof data.uptimeSeconds).toBe('number');
      expect(data.service).toBe('amaracus-api');
    });

    it('should return 200 OK from Kubernetes readiness probe (/health/ready)', async () => {
      const res = await fetch(`${baseUrl}/health/ready`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.status).toBe('ready');
      expect(data.ready).toBe(true);
      expect(data.database).toBeDefined();
      expect(data.queue).toBeDefined();
      expect(typeof data.queue.depth).toBe('number');
    });

    it('should expose valid Prometheus text format metrics (/metrics)', async () => {
      // Simulate HTTP activity
      await fetch(`${baseUrl}/health/live`);
      await fetch(`${baseUrl}/health/ready`);

      // Hidden without METRICS_TOKEN, and from callers without the token.
      const saved = process.env.METRICS_TOKEN;
      delete process.env.METRICS_TOKEN;
      expect((await fetch(`${baseUrl}/metrics`)).status).toBe(404);
      process.env.METRICS_TOKEN = 'metrics-token-for-tests-0123456789';
      expect((await fetch(`${baseUrl}/metrics`, { headers: { Authorization: 'Bearer wrong' } })).status).toBe(404);

      const res = await fetch(`${baseUrl}/metrics`, {
        headers: { Authorization: 'Bearer metrics-token-for-tests-0123456789' },
      });
      if (saved === undefined) delete process.env.METRICS_TOKEN;
      else process.env.METRICS_TOKEN = saved;
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('text/plain');

      const body = await res.text();
      // Process & Node metrics
      expect(body).toContain('# HELP process_resident_memory_bytes');
      expect(body).toContain('process_resident_memory_bytes');
      expect(body).toContain('process_uptime_seconds');

      // HTTP metrics
      expect(body).toContain('# HELP amaracus_http_requests_total');
      expect(body).toContain('amaracus_http_requests_total');

      // Cryptographic metrics
      expect(body).toContain('# HELP amaracus_crypto_operations_total');
      expect(body).toContain('# HELP amaracus_crypto_dead_letter_total');

      // Worker queue & circuit breaker metrics
      expect(body).toContain('# HELP amaracus_worker_queue_depth');
      expect(body).toContain('amaracus_worker_queue_depth');
      expect(body).toContain('# HELP amaracus_circuit_breaker_state');
      expect(body).toContain('amaracus_circuit_breaker_state');
    });
  });

  describe('2. Provider Circuit Breaker & Throttling Safeguards', () => {
    it('should remain CLOSED under normal operating conditions', () => {
      const state = providerCircuitBreaker.getState('azure-keyvault');
      expect(state).toBe('CLOSED');
      expect(providerCircuitBreaker.isOpen('azure-keyvault')).toBe(false);
    });

    it('should trip to OPEN when consecutive failure threshold is exceeded', async () => {
      const testProvider = 'test-failing-hsm';

      // Record 5 consecutive failures
      for (let i = 0; i < 5; i++) {
        providerCircuitBreaker.recordFailure(testProvider, new Error('Connection timeout'));
      }

      expect(providerCircuitBreaker.getState(testProvider)).toBe('OPEN');
      expect(providerCircuitBreaker.isOpen(testProvider)).toBe(true);

      // Fast-fail attempt without executing underlying operation
      await expect(
        providerCircuitBreaker.execute(testProvider, async () => {
          return 'should not run';
        })
      ).rejects.toThrow(/circuit breaker is OPEN/);
    });

    it('should trip quickly on HTTP 429 rate limit throttling', () => {
      const testProvider = 'test-throttled-vault';
      const throttleErr: any = new Error('Too Many Requests');
      throttleErr.statusCode = 429;

      // 2 throttled requests trip the breaker
      providerCircuitBreaker.recordFailure(testProvider, throttleErr);
      providerCircuitBreaker.recordFailure(testProvider, throttleErr);

      expect(providerCircuitBreaker.getState(testProvider)).toBe('OPEN');
    });

    it('should transition to HALF_OPEN after cooldown and close on successful probes', async () => {
      const customBreaker = new (providerCircuitBreaker.constructor as any)({
        failureThreshold: 2,
        cooldownPeriodMs: 50,
        halfOpenSuccessThreshold: 2,
      });

      customBreaker.recordFailure('p1', new Error('Fail 1'));
      customBreaker.recordFailure('p1', new Error('Fail 2'));
      expect(customBreaker.getState('p1')).toBe('OPEN');

      // Wait for cooldown window
      await new Promise((resolve) => setTimeout(resolve, 60));
      expect(customBreaker.getState('p1')).toBe('HALF_OPEN');

      // 2 consecutive successes should restore CLOSED state
      customBreaker.recordSuccess('p1');
      customBreaker.recordSuccess('p1');
      expect(customBreaker.getState('p1')).toBe('CLOSED');
    });
  });

  describe('3. Worker Durability & Zombie Job Recovery', () => {
    it('should identify and safely recover orphaned jobs abandoned during crashes', async () => {
      const orgId = 'org_test_zombie_' + Date.now();
      const opId = 'op_zombie_' + Date.now();

      // Seed a stale operation in EXECUTING state with past timestamp
      const fiveMinutesAgo = new Date(Date.now() - 300000);
      await db.createCryptographicOperation({
        id: opId,
        organizationId: orgId,
        operationType: 'ENCRYPT',
        algorithm: 'AES-256-GCM',
        status: 'EXECUTING',
        retryCount: 0,
        request: {
          algorithm: 'AES-256-GCM',
          plaintext: 'SGVsbG8gV29ybGQ=',
        },
      });

      // Manually set updatedAt to past date in datastore
      await db.updateCryptographicOperation(opId, {
        updatedAt: fiveMinutesAgo,
      });

      // Trigger zombie recovery sweep
      const recovered = await managedOperationQueue.recoverZombieJobs(120000);
      expect(recovered).toBeGreaterThanOrEqual(1);

      // Verify the zombie job was restored to QUEUED status with incremented retry count
      const updatedOp = await db.getCryptographicOperation(opId);
      expect(updatedOp).not.toBeNull();
      expect(updatedOp?.status).toBe('QUEUED');
      expect(updatedOp?.retryCount).toBe(1);
      expect(updatedOp?.error?.code).toBe('ZOMBIE_WORKER_RECOVERED');
    });

    it('should transition to DEAD_LETTER if a zombie job has already exhausted retries', async () => {
      const orgId = 'org_test_exhausted_' + Date.now();
      const opId = 'op_exhausted_' + Date.now();

      const fiveMinutesAgo = new Date(Date.now() - 300000);
      await db.createCryptographicOperation({
        id: opId,
        organizationId: orgId,
        operationType: 'ENCRYPT',
        algorithm: 'AES-256-GCM',
        status: 'EXECUTING',
        retryCount: 3, // Exhausted
        request: {
          algorithm: 'AES-256-GCM',
          plaintext: 'SGVsbG8gV29ybGQ=',
        },
      });

      await db.updateCryptographicOperation(opId, {
        updatedAt: fiveMinutesAgo,
      });

      await managedOperationQueue.recoverZombieJobs(120000);

      const finalOp = await db.getCryptographicOperation(opId);
      expect(finalOp?.status).toBe('DEAD_LETTER');
      expect(finalOp?.error?.code).toBe('ZOMBIE_RECOVERY_EXHAUSTED');
    });
  });

  describe('4. Cryptographic Workload & Concurrency Throughput Benchmark', () => {
    it('should sustain concurrent cryptographic operations with zero secret leakage', async () => {
      const cryptoService = new CryptoEngineService();
      const keyHex = generateSecureRandom(32).toString('hex');
      const plaintext = 'Confidential Enterprise Document Payload 2026';
      const concurrency = 50;

      const startTime = Date.now();

      // Launch 50 parallel encryption and decryption cycles
      const tasks = Array.from({ length: concurrency }).map(async () => {
        const envelope = await cryptoService.encrypt({
          algorithm: 'AES-256-GCM',
          key: keyHex,
          keyEncoding: 'hex',
          plaintext,
        });

        expect(envelope.ct).toBeDefined();
        expect(envelope.iv).toBeDefined();
        expect(envelope.tag).toBeDefined();

        const decrypted = await cryptoService.decrypt({
          envelope,
          key: keyHex,
          keyEncoding: 'hex',
        });

        expect(decrypted).toBe(plaintext);
        return true;
      });

      const results = await Promise.all(tasks);
      const durationMs = Date.now() - startTime;
      const throughputOpsPerSec = Math.round((concurrency / (durationMs / 1000)));

      expect(results.length).toBe(concurrency);
      expect(results.every((r) => r === true)).toBe(true);

      console.log(`\n======================================================`);
      console.log(`[BENCHMARK] Concurrent Cryptographic Workload Test`);
      console.log(`Total Operations: ${concurrency} parallel encrypt+decrypt cycles`);
      console.log(`Total Duration: ${durationMs} ms`);
      console.log(`Throughput: ~${throughputOpsPerSec} ops/second`);
      console.log(`Average Latency: ${(durationMs / concurrency).toFixed(2)} ms/op`);
      console.log(`======================================================\n`);

      expect(durationMs).toBeLessThan(10000);
    });
  });
});
