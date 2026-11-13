/**
 * AMARACUS — Phase 9: Advanced Crypto Orchestration Service
 * Central service layer managing ZK, FHE, MPC, and Threshold subsystems.
 */

import { ZkCircuitEngine } from './zk/circuit';
import { ZkNizkProver } from './zk/nizk-prover';
import { ZkNizkVerifier } from './zk/nizk-verifier';
import { FheEngine } from './fhe/fhe-engine';
import { MpcEngine } from './mpc/mpc-engine';
import { ThresholdEngine } from './threshold/threshold-engine';
import { AdvancedCryptoPolicyEngine } from './policy';
import { AdvancedCryptoProviderRegistry } from './provider-registry';
import {
  FheEvaluationRequest,
  FheEvaluationResult,
  FheKeyMetadata,
  MpcSession,
  ThresholdKey,
  ThresholdOperation,
  ThresholdSession,
  ZkCircuitDefinition,
  ZkProof,
  ZkStatement,
  ZkVerifyResult,
  ZkWitness
} from './types';

export class AdvancedCryptoService {
  // ==========================================
  // 1. ZK Operations
  // ==========================================

  public static createZkCircuit(
    organizationId: string,
    def: Omit<ZkCircuitDefinition, 'createdAt' | 'updatedAt'>
  ): ZkCircuitDefinition {
    AdvancedCryptoPolicyEngine.validateZkSystem(def.provingSystem);
    return ZkCircuitEngine.registerCircuit(def);
  }

  public static getZkCircuit(id: string, version?: string, orgId?: string): ZkCircuitDefinition {
    return ZkCircuitEngine.getCircuit(id, version, orgId);
  }

  public static listZkCircuits(orgId: string): ZkCircuitDefinition[] {
    return ZkCircuitEngine.listCircuits(orgId);
  }

  public static generateZkProof(
    circuitId: string,
    version: string,
    statement: ZkStatement,
    witness: ZkWitness,
    orgId?: string
  ): ZkProof {
    const circuit = ZkCircuitEngine.getCircuit(circuitId, version, orgId);
    AdvancedCryptoPolicyEngine.validateZkSystem(circuit.provingSystem);
    return ZkNizkProver.prove(circuit, statement, witness);
  }

  public static verifyZkProof(
    circuitId: string,
    version: string,
    statement: ZkStatement,
    proof: ZkProof,
    orgId?: string
  ): ZkVerifyResult {
    const circuit = ZkCircuitEngine.getCircuit(circuitId, version, orgId);
    return ZkNizkVerifier.verify(circuit, statement, proof);
  }

  // ==========================================
  // 2. FHE Operations
  // ==========================================

  public static async generateFheKey(
    organizationId: string,
    scheme: 'BFV' | 'BGV' | 'CKKS' = 'BFV',
    polyModulusDegree: 4096 | 8192 = 4096,
    projectId?: string,
    environmentId?: string
  ): Promise<FheKeyMetadata> {
    AdvancedCryptoPolicyEngine.validateFheScheme(scheme, polyModulusDegree);
    return FheEngine.generateKeypair(organizationId, scheme, polyModulusDegree, projectId, environmentId);
  }

  public static getFheKey(keyId: string, organizationId?: string): FheKeyMetadata {
    return FheEngine.getKey(keyId, organizationId);
  }

  public static async encryptFhe(keyId: string, value: number, organizationId?: string) {
    return FheEngine.encrypt(keyId, value, organizationId);
  }

  public static async decryptFhe(keyId: string, ciphertextBase64: string, organizationId?: string) {
    return FheEngine.decrypt(keyId, ciphertextBase64, organizationId);
  }

  public static async evaluateFhe(
    request: FheEvaluationRequest,
    organizationId?: string
  ): Promise<FheEvaluationResult> {
    return FheEngine.evaluate(request, organizationId);
  }

  public static getFheLimits() {
    return FheEngine.getLimits();
  }

  // ==========================================
  // 3. MPC Operations
  // ==========================================

  public static createMpcSession(
    organizationId: string,
    title: string,
    operation: 'SECURE_SUM' | 'SECURE_AVERAGE' | 'SECURE_COUNT' = 'SECURE_SUM',
    requiredParties: number = 2,
    threshold: number = 2,
    projectId?: string,
    environmentId?: string
  ): MpcSession {
    AdvancedCryptoPolicyEngine.validateMpcProtocol('ADDITIVE_SECRET_SHARING');
    return MpcEngine.createSession(
      organizationId,
      title,
      operation,
      requiredParties,
      threshold,
      'ADDITIVE_SECRET_SHARING',
      projectId,
      environmentId
    );
  }

  public static joinMpcSession(
    sessionId: string,
    partyId: string,
    name: string,
    role: 'COORDINATOR' | 'COMPUTE_PARTY' | 'INPUT_PARTY' = 'INPUT_PARTY',
    organizationId?: string
  ): MpcSession {
    return MpcEngine.joinSession(sessionId, partyId, name, role, organizationId);
  }

  public static submitMpcPartyInput(
    sessionId: string,
    partyId: string,
    rawSecretInput: number,
    organizationId?: string
  ): MpcSession {
    return MpcEngine.submitPartyInput(sessionId, partyId, rawSecretInput, organizationId);
  }

  public static executeMpcRound(sessionId: string, organizationId?: string): MpcSession {
    return MpcEngine.executeRound(sessionId, organizationId);
  }

  public static getMpcSession(sessionId: string, organizationId?: string): MpcSession {
    return MpcEngine.getSession(sessionId, organizationId);
  }

  // ==========================================
  // 4. Threshold Operations
  // ==========================================

  public static createThresholdKey(
    organizationId: string,
    name: string,
    threshold: number,
    totalParticipants: number,
    projectId?: string,
    environmentId?: string
  ): ThresholdKey {
    AdvancedCryptoPolicyEngine.validateThreshold(threshold, totalParticipants);
    return ThresholdEngine.createThresholdKey(
      organizationId,
      name,
      threshold,
      totalParticipants,
      'ED25519_FROST',
      projectId,
      environmentId
    );
  }

  public static getThresholdKey(keyId: string, organizationId?: string): ThresholdKey {
    return ThresholdEngine.getKey(keyId, organizationId);
  }

  public static listThresholdKeys(organizationId: string): ThresholdKey[] {
    return ThresholdEngine.listKeys(organizationId);
  }

  public static createThresholdSession(
    organizationId: string,
    keyId: string,
    operation: ThresholdOperation,
    messageToSign?: string,
    payloadToAuthorize?: string
  ): ThresholdSession {
    return ThresholdEngine.createSession(organizationId, keyId, operation, messageToSign, payloadToAuthorize);
  }

  public static approveThresholdSession(
    sessionId: string,
    participantId: string,
    organizationId?: string
  ): ThresholdSession {
    return ThresholdEngine.approveSession(sessionId, participantId, organizationId);
  }

  public static executeThresholdSession(
    sessionId: string,
    organizationId?: string
  ): ThresholdSession {
    return ThresholdEngine.executeSession(sessionId, organizationId);
  }

  public static getThresholdSession(sessionId: string, organizationId?: string): ThresholdSession {
    return ThresholdEngine.getSession(sessionId, organizationId);
  }

  // ==========================================
  // 5. Capability Discovery
  // ==========================================

  public static listProviders() {
    return AdvancedCryptoProviderRegistry.listProviders();
  }
}
