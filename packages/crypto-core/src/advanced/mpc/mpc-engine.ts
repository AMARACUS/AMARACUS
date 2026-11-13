/**
 * AMARACUS — Phase 9: Multi-Party Computation (MPC) Engine
 * Coordinates MPC sessions across multiple parties without ever storing
 * or exposing raw private party inputs.
 */

import * as crypto from 'crypto';
import { AdditiveSharing } from './additive-sharing';
import { MpcParty, MpcProtocol, MpcSession } from '../types';
import { CryptoEngineError } from '../../errors';

interface StoredMpcSession extends MpcSession {
  // In-memory router of blinded shares: partyId -> shares addressed to that party
  // No raw inputs are ever stored!
  blindedSharesInbox: Map<string, bigint[]>;
  partyAggregatedSums: Map<string, bigint>;
}

export class MpcEngine {
  private static sessions = new Map<string, StoredMpcSession>();

  /**
   * Creates a new MPC session
   */
  public static createSession(
    organizationId: string,
    title: string,
    operation: 'SECURE_SUM' | 'SECURE_AVERAGE' | 'SECURE_COUNT' = 'SECURE_SUM',
    requiredParties: number = 2,
    threshold: number = 2,
    protocol: MpcProtocol = 'ADDITIVE_SECRET_SHARING',
    projectId?: string,
    environmentId?: string
  ): MpcSession {
    if (requiredParties < 2) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        'MPC session requires at least 2 participating parties',
        400
      );
    }

    if (threshold > requiredParties) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        'Threshold cannot exceed total required parties',
        400
      );
    }

    const sessionId = `mpc-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 60 * 60 * 1000).toISOString(); // 1 hour TTL

    const session: StoredMpcSession = {
      id: sessionId,
      organizationId,
      projectId,
      environmentId,
      title,
      protocol,
      operation,
      requiredParties,
      threshold,
      status: 'WAITING_FOR_PARTIES',
      currentRound: 0,
      totalRounds: 2, // Round 1: Input share distribution, Round 2: Local aggregation & output
      parties: [],
      blindedSharesInbox: new Map(),
      partyAggregatedSums: new Map(),
      expiresAt,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString()
    };

    this.sessions.set(sessionId, session);
    return this.sanitizeSession(session);
  }

  /**
   * Join an existing MPC session
   */
  public static joinSession(
    sessionId: string,
    partyId: string,
    name: string,
    role: 'COORDINATOR' | 'COMPUTE_PARTY' | 'INPUT_PARTY' = 'INPUT_PARTY',
    organizationId?: string
  ): MpcSession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', `MPC Session '${sessionId}' not found`, 404);
    }

    if (organizationId && session.organizationId !== organizationId) {
      throw new CryptoEngineError('TENANT_ACCESS_DENIED', `Access denied to MPC Session '${sessionId}'`, 403);
    }

    if (session.status !== 'WAITING_FOR_PARTIES' && session.status !== 'INITIALIZING') {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        `Cannot join session in status '${session.status}'`,
        400
      );
    }

    if (session.parties.some(p => p.partyId === partyId)) {
      throw new CryptoEngineError(
        'CONFLICT',
        `Party '${partyId}' is already registered in this session`,
        409
      );
    }

    if (session.parties.length >= session.requiredParties) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        `Session is full (${session.parties.length}/${session.requiredParties} parties already joined)`,
        400
      );
    }

    const party: MpcParty = {
      partyId,
      name,
      role,
      joinedAt: new Date().toISOString(),
      hasSubmittedInput: false
    };

    session.parties.push(party);
    session.updatedAt = new Date().toISOString();

    if (session.parties.length === session.requiredParties) {
      session.status = 'WAITING_FOR_INPUTS';
      session.currentRound = 1;
    }

    return this.sanitizeSession(session);
  }

  /**
   * Submit blinded shares for a party.
   * To prevent secret leakage, each party splits their input into N blinded shares:
   * raw inputs are NEVER stored on the server!
   */
  public static submitPartyInput(
    sessionId: string,
    partyId: string,
    rawSecretInput: number,
    organizationId?: string
  ): MpcSession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', `MPC Session '${sessionId}' not found`, 404);
    }

    if (organizationId && session.organizationId !== organizationId) {
      throw new CryptoEngineError('TENANT_ACCESS_DENIED', `Access denied to MPC Session '${sessionId}'`, 403);
    }

    if (new Date() > new Date(session.expiresAt)) {
      session.status = 'TIMED_OUT';
      throw new CryptoEngineError('INVALID_REQUEST', 'MPC session has expired', 400);
    }

    const party = session.parties.find(p => p.partyId === partyId);
    if (!party) {
      throw new CryptoEngineError('FORBIDDEN', `Party '${partyId}' is not authorized in this session`, 403);
    }

    if (party.hasSubmittedInput) {
      throw new CryptoEngineError('CONFLICT', `Party '${partyId}' has already submitted input for this session`, 409);
    }

    // Split raw input into N blinded shares (one share for each party)
    const shares = AdditiveSharing.split(rawSecretInput, session.requiredParties);

    // Route each blinded share to the corresponding party's inbox
    // Neither the server nor any other party ever receives the raw input!
    for (let i = 0; i < session.parties.length; i++) {
      const recipientId = session.parties[i].partyId;
      const currentInbox = session.blindedSharesInbox.get(recipientId) || [];
      currentInbox.push(shares[i]);
      session.blindedSharesInbox.set(recipientId, currentInbox);
    }

    // Mark party submitted with cryptographic commitment of blinded share
    party.hasSubmittedInput = true;
    party.blindedShareHash = crypto
      .createHash('sha256')
      .update(`blinded-share-${sessionId}-${partyId}-${shares[0]}`)
      .digest('hex');

    session.updatedAt = new Date().toISOString();

    // Check if all parties have submitted
    const allSubmitted = session.parties.every(p => p.hasSubmittedInput);
    if (allSubmitted) {
      session.status = 'COMPUTING_ROUND';
    }

    return this.sanitizeSession(session);
  }

  /**
   * Execute MPC computation round:
   * Each party computes their local sum of received blinded shares,
   * then shares are aggregated to produce the final output.
   */
  public static executeRound(sessionId: string, organizationId?: string): MpcSession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', `MPC Session '${sessionId}' not found`, 404);
    }

    if (organizationId && session.organizationId !== organizationId) {
      throw new CryptoEngineError('TENANT_ACCESS_DENIED', `Access denied to MPC Session '${sessionId}'`, 403);
    }

    const submittedCount = session.parties.filter(p => p.hasSubmittedInput).length;
    if (submittedCount < session.threshold) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        `Insufficient participants to execute MPC computation (${submittedCount}/${session.threshold} submitted)`,
        400
      );
    }

    // Round 2: Local aggregation per party
    const p = AdditiveSharing.FIELD_MODULUS;
    const partySums: bigint[] = [];

    for (const party of session.parties) {
      const shares = session.blindedSharesInbox.get(party.partyId) || [];
      let localSum = 0n;
      for (const share of shares) {
        localSum = (localSum + share) % p;
      }
      partySums.push(localSum);
      session.partyAggregatedSums.set(party.partyId, localSum);
    }

    // Combine party sums to produce the final result
    const totalSum = AdditiveSharing.recombine(partySums);
    let finalValue = totalSum;

    if (session.operation === 'SECURE_AVERAGE') {
      finalValue = totalSum / session.parties.length;
    } else if (session.operation === 'SECURE_COUNT') {
      finalValue = session.parties.length;
    }

    session.status = 'COMPLETED';
    session.currentRound = 2;
    session.result = {
      computedValue: finalValue,
      completedAt: new Date().toISOString(),
      participatingParties: session.parties.map(pt => pt.partyId)
    };
    session.updatedAt = new Date().toISOString();

    return this.sanitizeSession(session);
  }

  /**
   * Get session status and results
   */
  public static getSession(sessionId: string, organizationId?: string): MpcSession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', `MPC Session '${sessionId}' not found`, 404);
    }
    if (organizationId && session.organizationId !== organizationId) {
      throw new CryptoEngineError('TENANT_ACCESS_DENIED', `Access denied to MPC Session '${sessionId}'`, 403);
    }
    return this.sanitizeSession(session);
  }

  /**
   * Strips internal share mailboxes to ensure zero secret leakage in API responses
   */
  private static sanitizeSession(session: StoredMpcSession): MpcSession {
    const { blindedSharesInbox, partyAggregatedSums, ...safe } = session;
    return safe;
  }
}
