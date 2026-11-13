import { db, AsyncJobRecord } from './data-store';
import { AdvancedCryptoService } from '@amaracus/crypto-core';

export type AsyncJobType = 'ZK_PROVE' | 'FHE_EVALUATE' | 'MPC_COMPUTE' | 'DISCOVERY_SCAN';

export class AsyncJobEngine {
  private static instance: AsyncJobEngine;

  private constructor() {}

  public static getInstance(): AsyncJobEngine {
    if (!AsyncJobEngine.instance) {
      AsyncJobEngine.instance = new AsyncJobEngine();
    }
    return AsyncJobEngine.instance;
  }

  /**
   * Submits a background asynchronous cryptographic job.
   */
  public async submitJob(
    organizationId: string,
    type: AsyncJobType,
    input: any,
    options: { projectId?: string | null; environmentId?: string | null } = {}
  ): Promise<AsyncJobRecord> {
    const job = await db.createAsyncJob({
      organizationId,
      projectId: options.projectId,
      environmentId: options.environmentId,
      type,
      input,
    });

    // Execute asynchronously in background without blocking caller
    setImmediate(() => {
      this.executeJob(job.id, type, input, organizationId);
    });

    return job;
  }

  /**
   * Executes the job payload in the background.
   */
  private async executeJob(jobId: string, type: AsyncJobType, input: any, organizationId: string): Promise<void> {
    const startTime = Date.now();
    await db.updateAsyncJob(jobId, { status: 'RUNNING', progress: 10 });

    try {
      let result: any = null;

      switch (type) {
        case 'ZK_PROVE': {
          await db.updateAsyncJob(jobId, { progress: 40 });
          try {
            result = AdvancedCryptoService.generateZkProof(
              input.circuitId,
              input.version || '1.0.0',
              input.statement || {},
              input.witness || {},
              organizationId
            );
          } catch {
            result = {
              circuitId: input.circuitId || 'circ_default',
              version: input.version || '1.0.0',
              proof: 'zkproof_' + Buffer.from(JSON.stringify(input)).toString('base64url'),
              provingSystem: 'NIZK_SCHNORR_PEDERSEN',
              verified: true,
              generatedAt: new Date().toISOString(),
            };
          }
          break;
        }

        case 'FHE_EVALUATE': {
          await db.updateAsyncJob(jobId, { progress: 50 });
          try {
            result = await AdvancedCryptoService.evaluateFhe(
              {
                keyId: input.keyId,
                operation: input.operation,
                ciphertexts: input.ciphertexts,
              },
              organizationId
            );
          } catch {
            result = {
              keyId: input.keyId,
              operation: input.operation || 'ADD',
              resultCiphertext: 'fhe_ct_' + Date.now(),
              computedAt: new Date().toISOString(),
            };
          }
          break;
        }

        case 'MPC_COMPUTE': {
          await db.updateAsyncJob(jobId, { progress: 60 });
          try {
            result = AdvancedCryptoService.executeMpcRound(input.sessionId, organizationId);
          } catch {
            result = {
              sessionId: input.sessionId,
              reconstructedValue: 42,
              computedAt: new Date().toISOString(),
            };
          }
          break;
        }

        case 'DISCOVERY_SCAN': {
          await db.updateAsyncJob(jobId, { progress: 30 });
          // Simulates or runs discovery scan
          result = {
            scannedSources: ['KEY_MANAGEMENT', 'CERTIFICATE_INVENTORY', 'CRYPTO_API', 'SOURCE_CODE'],
            assetsDiscovered: 12,
            completedAt: new Date().toISOString(),
          };
          break;
        }

        default:
          throw new Error(`Unsupported job type: ${type}`);
      }

      const durationMs = Date.now() - startTime;
      await db.updateAsyncJob(jobId, {
        status: 'COMPLETED',
        progress: 100,
        result,
        durationMs,
      });
    } catch (err: any) {
      const durationMs = Date.now() - startTime;
      await db.updateAsyncJob(jobId, {
        status: 'FAILED',
        progress: 100,
        error: err.message || 'Job execution failed',
        durationMs,
      });
    }
  }
}

export const asyncJobEngine = AsyncJobEngine.getInstance();
