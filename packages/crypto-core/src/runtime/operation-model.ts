/**
 * AMARACUS Cryptographic Infrastructure — Unified Operation Model & Lifecycle
 *
 * Represents cryptographic operations independently of underlying providers.
 * Enforces predictable execution lifecycles and standardized result/error formats.
 */

import { AlgorithmId } from '../types';
import { KeyReference } from './key-reference';
import { TenantContext } from './context';

export type OperationType =
  | 'ENCRYPT'
  | 'DECRYPT'
  | 'SIGN'
  | 'VERIFY'
  | 'HASH'
  | 'HMAC'
  | 'HMAC_VERIFY'
  | 'KEY_GEN'
  | 'KEY_ROTATION'
  | 'KEY_AGREEMENT'
  | 'WRAP_KEY'
  | 'UNWRAP_KEY'
  | 'KEM_KEYGEN'
  | 'KEM_ENCAPSULATE'
  | 'KEM_DECAPSULATE'
  | 'PQC_SIGN'
  | 'PQC_VERIFY'
  | 'ADVANCED_ZK_PROVE'
  | 'ADVANCED_ZK_VERIFY'
  | 'CERT_GENERATE'
  | 'CERT_VERIFY';

export type OperationStatus =
  | 'REQUESTED'
  | 'VALIDATING'
  | 'AUTHORIZING'
  | 'AUTHORIZED'
  | 'RESOLVING'
  | 'QUEUED'
  | 'EXECUTING'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELED'
  | 'TIMED_OUT'
  | 'DEAD_LETTER'
  | 'EXPIRED';

export interface CryptographicOperationRequest<TParams = any> {
  operationId: string;
  requestId: string;
  idempotencyKey?: string | null;
  type: OperationType;
  algorithm?: AlgorithmId | string | null;
  keyId?: string | null;
  keyReference?: KeyReference | null;
  params: TParams;
  policy?: string | null;
  metadata?: Record<string, any> | null;
  mode?: 'sync' | 'async';
  timeoutMs?: number;
}

export interface CryptographicOperationMetadata {
  durationMs: number;
  providerId: string;
  providerName: string;
  algorithm?: string | null;
  keyId?: string | null;
  keyVersion?: number | string | null;
  isHardwareBacked?: boolean;
  isCustomerManaged?: boolean;
  isPqc?: boolean;
  timestamp: string;
  failoverOccurred?: boolean;
  originalProviderId?: string;
  retryCount?: number;
  [key: string]: any;
}

export interface CryptographicOperationError {
  code: string;
  message: string;
  retryable: boolean;
  statusCode?: number;
  details?: any;
}

export interface CryptographicOperationResult<TData = any> {
  success: boolean;
  operationId: string;
  requestId: string;
  status: OperationStatus;
  type: OperationType;
  data?: TData;
  metadata: CryptographicOperationMetadata;
  error?: CryptographicOperationError;
}

export interface CryptographicOperationRecord {
  id: string;
  requestId?: string | null;
  idempotencyKey?: string | null;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  operationType: OperationType | string;
  algorithm?: string | null;
  keyId?: string | null;
  providerId?: string | null;
  status: OperationStatus | string;
  retryCount?: number;
  durationMs?: number | null;
  metadata?: Record<string, any> | null;
  result?: any | null;
  error?: CryptographicOperationError | null;
  expiresAt?: Date | null;
  createdAt: Date;
  updatedAt: Date;
}
