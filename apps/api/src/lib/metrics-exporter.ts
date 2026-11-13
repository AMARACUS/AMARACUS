import { operationObservability } from './operation-observability';
import { managedOperationQueue } from './managed-operation-queue';
import { providerCircuitBreaker } from './provider-circuit-breaker';

export interface HttpRequestMetric {
  method: string;
  statusCode: number;
  durationMs: number;
}

export class MetricsExporter {
  private httpRequests: Map<string, number> = new Map();
  private totalHttpRequests = 0;
  private totalHttpDurationMs = 0;

  recordHttpRequest(method: string, statusCode: number, durationMs: number): void {
    const key = `${method.toUpperCase()}_${statusCode}`;
    this.httpRequests.set(key, (this.httpRequests.get(key) || 0) + 1);
    this.totalHttpRequests += 1;
    this.totalHttpDurationMs += durationMs;
  }

  generatePrometheusMetrics(): string {
    const lines: string[] = [];
    const mem = process.memoryUsage();
    const uptime = process.uptime();
    const cpu = process.cpuUsage();
    const cpuSeconds = (cpu.user + cpu.system) / 1000000;

    // Process & Runtime Metrics
    lines.push('# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.');
    lines.push('# TYPE process_cpu_seconds_total counter');
    lines.push(`process_cpu_seconds_total ${cpuSeconds.toFixed(4)}`);

    lines.push('# HELP process_resident_memory_bytes Resident memory size in bytes.');
    lines.push('# TYPE process_resident_memory_bytes gauge');
    lines.push(`process_resident_memory_bytes ${mem.rss}`);

    lines.push('# HELP nodejs_heap_size_total_bytes Total allocated heap memory in bytes.');
    lines.push('# TYPE nodejs_heap_size_total_bytes gauge');
    lines.push(`nodejs_heap_size_total_bytes ${mem.heapTotal}`);

    lines.push('# HELP nodejs_heap_size_used_bytes Used heap memory in bytes.');
    lines.push('# TYPE nodejs_heap_size_used_bytes gauge');
    lines.push(`nodejs_heap_size_used_bytes ${mem.heapUsed}`);

    lines.push('# HELP process_uptime_seconds Process uptime in seconds.');
    lines.push('# TYPE process_uptime_seconds gauge');
    lines.push(`process_uptime_seconds ${uptime.toFixed(1)}`);

    // HTTP Metrics
    lines.push('# HELP amaracus_http_requests_total Total number of HTTP requests processed.');
    lines.push('# TYPE amaracus_http_requests_total counter');
    if (this.httpRequests.size === 0) {
      lines.push('amaracus_http_requests_total{method="GET",status="200"} 0');
    } else {
      for (const [key, count] of this.httpRequests.entries()) {
        const [method, status] = key.split('_');
        lines.push(`amaracus_http_requests_total{method="${method}",status="${status}"} ${count}`);
      }
    }

    lines.push('# HELP amaracus_http_request_duration_seconds_sum Total duration of HTTP requests in seconds.');
    lines.push('# TYPE amaracus_http_request_duration_seconds_sum counter');
    lines.push(`amaracus_http_request_duration_seconds_sum ${(this.totalHttpDurationMs / 1000).toFixed(4)}`);

    lines.push('# HELP amaracus_http_request_duration_seconds_count Total count of measured HTTP requests.');
    lines.push('# TYPE amaracus_http_request_duration_seconds_count counter');
    lines.push(`amaracus_http_request_duration_seconds_count ${this.totalHttpRequests}`);

    // Cryptographic Operations Metrics
    const cryptoMetrics = operationObservability.getMetricsSummary();

    lines.push('# HELP amaracus_crypto_operations_total Total cryptographic operations by status.');
    lines.push('# TYPE amaracus_crypto_operations_total counter');
    for (const [status, count] of Object.entries(cryptoMetrics.countsByStatus)) {
      lines.push(`amaracus_crypto_operations_total{status="${status}"} ${count}`);
    }

    lines.push('# HELP amaracus_crypto_operations_by_type Total cryptographic operations by operation type.');
    lines.push('# TYPE amaracus_crypto_operations_by_type counter');
    for (const [type, count] of Object.entries(cryptoMetrics.countsByType)) {
      lines.push(`amaracus_crypto_operations_by_type{type="${type}"} ${count}`);
    }

    lines.push('# HELP amaracus_crypto_dead_letter_total Total operations exhausted retries and moved to dead-letter queue.');
    lines.push('# TYPE amaracus_crypto_dead_letter_total counter');
    lines.push(`amaracus_crypto_dead_letter_total ${cryptoMetrics.deadLetterCount}`);

    lines.push('# HELP amaracus_crypto_provider_failovers_total Total provider failover events triggered.');
    lines.push('# TYPE amaracus_crypto_provider_failovers_total counter');
    lines.push(`amaracus_crypto_provider_failovers_total ${cryptoMetrics.providerFailovers}`);

    // Cryptographic Latency Summaries (Converted to seconds)
    const lat = cryptoMetrics.latencies.overall;
    lines.push('# HELP amaracus_crypto_operation_duration_seconds Cryptographic execution latency quantiles in seconds.');
    lines.push('# TYPE amaracus_crypto_operation_duration_seconds summary');
    lines.push(`amaracus_crypto_operation_duration_seconds{quantile="0.5"} ${(lat.p50Ms / 1000).toFixed(4)}`);
    lines.push(`amaracus_crypto_operation_duration_seconds{quantile="0.95"} ${(lat.p95Ms / 1000).toFixed(4)}`);
    lines.push(`amaracus_crypto_operation_duration_seconds{quantile="0.99"} ${(lat.p99Ms / 1000).toFixed(4)}`);
    lines.push(`amaracus_crypto_operation_duration_seconds_sum ${(lat.sumMs / 1000).toFixed(4)}`);
    lines.push(`amaracus_crypto_operation_duration_seconds_count ${lat.count}`);

    // Worker Queue Metrics
    const queueMetrics = managedOperationQueue.getQueueMetrics();
    lines.push('# HELP amaracus_worker_queue_depth Current depth of managed operation background queue.');
    lines.push('# TYPE amaracus_worker_queue_depth gauge');
    lines.push(`amaracus_worker_queue_depth ${queueMetrics.depth}`);

    lines.push('# HELP amaracus_worker_active_workers Number of active background worker tasks currently executing.');
    lines.push('# TYPE amaracus_worker_active_workers gauge');
    lines.push(`amaracus_worker_active_workers ${queueMetrics.activeWorkers}`);

    lines.push('# HELP amaracus_worker_max_workers Configured worker concurrency limit.');
    lines.push('# TYPE amaracus_worker_max_workers gauge');
    lines.push(`amaracus_worker_max_workers ${queueMetrics.maxWorkers}`);

    // Circuit Breaker Metrics
    lines.push('# HELP amaracus_circuit_breaker_state Current state of cryptographic provider circuit breakers (0=CLOSED, 1=HALF_OPEN, 2=OPEN).');
    lines.push('# TYPE amaracus_circuit_breaker_state gauge');
    const circuitStatuses = providerCircuitBreaker.getAllStatuses();
    const stateValueMap = { CLOSED: 0, HALF_OPEN: 1, OPEN: 2 };

    if (circuitStatuses.length === 0) {
      lines.push('amaracus_circuit_breaker_state{provider="azure-keyvault"} 0');
    } else {
      for (const c of circuitStatuses) {
        lines.push(`amaracus_circuit_breaker_state{provider="${c.providerId}"} ${stateValueMap[c.state]}`);
      }
    }

    return lines.join('\n') + '\n';
  }

  reset(): void {
    this.httpRequests.clear();
    this.totalHttpRequests = 0;
    this.totalHttpDurationMs = 0;
  }
}

export const metricsExporter = new MetricsExporter();
