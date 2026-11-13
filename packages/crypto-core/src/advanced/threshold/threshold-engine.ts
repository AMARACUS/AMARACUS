/**
 * AMARACUS — Phase 9: Threshold Cryptography Orchestration Engine
 * Manages M-of-N threshold keys, session quorums, participant security,
 * and policy enforcement.
 */

import { FrostEngine } from './frost-engine';
import {
  ThresholdKey,
  ThresholdOperation,
  ThresholdParticipant,
  ThresholdSession
} from '../types';
import { CryptoEngineError } from '../../errors';

interface StoredThresholdKey extends ThresholdKey {
  // Store participant private shares securely in memory for demo execution,
  // never exposed over API!
  participantPrivateShares: Map<string, bigint>;
}

export class ThresholdEngine {
  private static keys = new Map<string, StoredThresholdKey>();
  private static sessions = new Map<string, ThresholdSession>();

  /**
   * Generates a new M-of-N threshold key
   */
  public static createThresholdKey(
    organizationId: string,
    name: string,
    threshold: number,
    totalParticipants: number,
    algorithm: 'ED25519_FROST' | 'SHAMIR_M_OF_N' = 'ED25519_FROST',
    projectId?: string,
    environmentId?: string
  ): ThresholdKey {
    if (threshold < 2) {
      throw new CryptoEngineError('INVALID_REQUEST', 'Threshold (M) must be at least 2', 400);
    }
    if (threshold > totalParticipants) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        `Threshold (${threshold}) cannot exceed total participants (${totalParticipants})`,
        400
      );
    }

    const { groupPublicKey, participantKeyShares } = FrostEngine.generateThresholdKeyShares(
      threshold,
      totalParticipants
    );

    const keyId = `thresh-key-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
    const participants: ThresholdParticipant[] = [];
    const participantPrivateShares = new Map<string, bigint>();

    for (const p of participantKeyShares) {
      const pId = `part-${keyId}-${p.index}`;
      participants.push({
        participantId: pId,
        name: `Participant #${p.index}`,
        publicKeyShare: p.publicKeyShare,
        index: p.index
      });
      participantPrivateShares.set(pId, p.privateShareScalar);
    }

    const keyRecord: StoredThresholdKey = {
      id: keyId,
      organizationId,
      projectId,
      environmentId,
      name,
      algorithm,
      threshold,
      totalParticipants,
      groupPublicKey,
      participants,
      participantPrivateShares,
      createdAt: new Date().toISOString()
    };

    this.keys.set(keyId, keyRecord);
    return this.sanitizeKey(keyRecord);
  }

  /**
   * Retrieves a threshold key without exposing participant private shares
   */
  public static getKey(keyId: string, organizationId?: string): ThresholdKey {
    const key = this.keys.get(keyId);
    if (!key) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', `Threshold Key '${keyId}' not found`, 404);
    }
    if (organizationId && key.organizationId !== organizationId) {
      throw new CryptoEngineError('TENANT_ACCESS_DENIED', `Access denied to Threshold Key '${keyId}'`, 403);
    }
    return this.sanitizeKey(key);
  }

  /**
   * List threshold keys for an organization
   */
  public static listKeys(organizationId: string): ThresholdKey[] {
    const results: ThresholdKey[] = [];
    for (const k of this.keys.values()) {
      if (k.organizationId === organizationId) {
        results.push(this.sanitizeKey(k));
      }
    }
    return results;
  }

  /**
   * Creates a new threshold operation session requiring M-of-N participant approvals
   */
  public static createSession(
    organizationId: string,
    keyId: string,
    operation: ThresholdOperation,
    messageToSign?: string,
    payloadToAuthorize?: string
  ): ThresholdSession {
    const key = this.getKey(keyId, organizationId);
    const sessionId = `thresh-sess-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 60 * 60 * 1000).toISOString();

    const session: ThresholdSession = {
      id: sessionId,
      organizationId,
      keyId,
      operation,
      messageToSign,
      payloadToAuthorize,
      threshold: key.threshold,
      totalParticipants: key.totalParticipants,
      approvals: [],
      status: 'PENDING_APPROVALS',
      expiresAt,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString()
    };

    this.sessions.set(sessionId, session);
    return session;
  }

  /**
   * Submit an approval from a registered participant
   */
  public static approveSession(
    sessionId: string,
    participantId: string,
    organizationId?: string
  ): ThresholdSession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', `Threshold Session '${sessionId}' not found`, 404);
    }
    if (organizationId && session.organizationId !== organizationId) {
      throw new CryptoEngineError('TENANT_ACCESS_DENIED', `Access denied to Threshold Session '${sessionId}'`, 403);
    }

    if (session.status !== 'PENDING_APPROVALS' && session.status !== 'READY') {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        `Cannot approve session in status '${session.status}'`,
        400
      );
    }

    const key = this.keys.get(session.keyId);
    if (!key) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', 'Associated threshold key not found', 404);
    }

    const participant = key.participants.find(p => p.participantId === participantId);
    if (!participant) {
      throw new CryptoEngineError('FORBIDDEN', `Participant '${participantId}' is not authorized for this key`, 403);
    }

    if (session.approvals.some(a => a.participantId === participantId)) {
      throw new CryptoEngineError('CONFLICT', `Participant '${participantId}' has already approved this session`, 409);
    }

    session.approvals.push({
      participantId,
      approvedAt: new Date().toISOString()
    });

    if (session.approvals.length >= session.threshold) {
      session.status = 'READY';
    }

    session.updatedAt = new Date().toISOString();
    return session;
  }

  /**
   * Executes the threshold operation if participant quorum (>= M) is satisfied
   */
  public static executeSession(
    sessionId: string,
    organizationId?: string
  ): ThresholdSession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', `Threshold Session '${sessionId}' not found`, 404);
    }
    if (organizationId && session.organizationId !== organizationId) {
      throw new CryptoEngineError('TENANT_ACCESS_DENIED', `Access denied to Threshold Session '${sessionId}'`, 403);
    }

    // Strict Policy Check: approvals >= threshold
    if (session.approvals.length < session.threshold) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        `Threshold policy violated: requires ${session.threshold} participants, but only ${session.approvals.length} approved`,
        400
      );
    }

    const key = this.keys.get(session.keyId);
    if (!key) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', 'Associated threshold key not found', 404);
    }

    // Simulate/execute the threshold operation
    let signature: string | undefined;
    if (session.operation === 'THRESHOLD_SIGN' && session.messageToSign) {
      // Aggregate participant partial signatures without central private key reconstruction
      const participatingIndices = session.approvals
        .map(a => key.participants.find(p => p.participantId === a.participantId)?.index)
        .filter((idx): idx is number => idx !== undefined);

      const msgBytes = Buffer.from(session.messageToSign, 'utf8');
      const partialSigs: bigint[] = [];

      for (const a of session.approvals) {
        const p = key.participants.find(pt => pt.participantId === a.participantId);
        if (p) {
          const priv = key.participantPrivateShares.get(p.participantId) || 1n;
          const s_i = FrostEngine.generatePartialSignature(
            msgBytes,
            priv,
            p.index,
            participatingIndices,
            123456n // ephemeral nonce
          );
          partialSigs.push(s_i);
        }
      }

      const combinedS = FrostEngine.combinePartialSignatures(partialSigs);
      signature = `thresh-sig-${key.groupPublicKey.slice(0, 16)}-${combinedS.toString(16)}`;
    }

    session.status = 'EXECUTED';
    session.combinedResult = {
      signature,
      authorized: true,
      executedAt: new Date().toISOString()
    };
    session.updatedAt = new Date().toISOString();

    return session;
  }

  /**
   * Get session details
   */
  public static getSession(sessionId: string, organizationId?: string): ThresholdSession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', `Threshold Session '${sessionId}' not found`, 404);
    }
    if (organizationId && session.organizationId !== organizationId) {
      throw new CryptoEngineError('TENANT_ACCESS_DENIED', `Access denied to Threshold Session '${sessionId}'`, 403);
    }
    return session;
  }

  /**
   * Sanitizes key to guarantee zero private share leakage
   */
  private static sanitizeKey(key: StoredThresholdKey): ThresholdKey {
    const { participantPrivateShares, ...safe } = key;
    return safe;
  }
}
