/**
 * AMARACUS — Phase 9: Advanced Cryptography API Routes
 * Zero-Knowledge Proofs + FHE + MPC + Threshold Cryptography
 */

import { Router, Request, Response, NextFunction } from 'express';
import { requireAuth, requireOrgMember, requireOrgPermission, validateOwnershipChain } from '../middleware/auth';
import { createRateLimiter } from '../middleware/rate-limiter';
import { AdvancedCryptoService } from '@amaracus/crypto-core';
import { db } from '../lib/data-store';
import { requireOperationAllowance, requireEntitlement } from '../middleware/billing-guard';
import { usageMeter } from '../lib/usage-meter';

export const advancedCryptoRouter = Router({ mergeParams: true });

// Universal pipeline: auth -> tenant resolution -> ownership chain validation -> rate limiting -> entitlement check
advancedCryptoRouter.use(requireAuth);
advancedCryptoRouter.use(requireOrgMember);
advancedCryptoRouter.use(validateOwnershipChain);
advancedCryptoRouter.use(createRateLimiter({ limit: 300, windowMs: 60000 }));
advancedCryptoRouter.use(requireEntitlement('advancedCryptography'));

// Every advanced scheme here is a preview: ZK is Schnorr/Pedersen only (no Groth16/PLONK),
// FHE keys are held by the server, MPC is additive secret sharing in one process, and the
// threshold scheme is not a vetted FROST implementation. Say so on every response.
const PREVIEW_NOTICE = {
  status: 'PREVIEW',
  productionReady: false,
  message:
    'Preview feature, not for production use. ZK supports Schnorr/Pedersen proofs only; FHE keys are held by the server; MPC and threshold signing run inside the AMARACUS server and are not independently audited.',
};
advancedCryptoRouter.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Amaracus-Preview', 'true');
  const json = res.json.bind(res);
  res.json = (body?: any) => {
    if (body && typeof body === 'object' && !Array.isArray(body) && body.preview === undefined) {
      body = { ...body, preview: PREVIEW_NOTICE };
    }
    return json(body);
  };
  next();
});

// Helper: Authoritatively record billable cryptographic operation strictly on successful execution
async function recordBillableOp(req: Request, operationType: string) {
  try {
    const orgId = req.organizationId!;
    if (orgId) {
      const operationId = (req.headers['idempotency-key'] as string) || (req as any).requestId;
      await usageMeter.recordOperation({
        organizationId: orgId,
        operationType,
        quantity: 1,
        operationId,
      });
    }
  } catch (err) {
    console.warn(`[Usage Metering Warning] Could not record ${operationType} usage:`, err);
  }
}

// ==========================================
// 1. ZK Routes
// ==========================================

// GET /zk/circuits
advancedCryptoRouter.get(
  '/zk/circuits',
  requireOrgPermission('zk:circuit:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const circuits = await db.listZkCircuits(orgId);
      const inMem = AdvancedCryptoService.listZkCircuits(orgId);

      // Merge and deduplicate
      const seen = new Set<string>();
      const combined = [];
      for (const c of [...circuits, ...inMem]) {
        const k = `${c.id}:${c.version}`;
        if (!seen.has(k)) {
          seen.add(k);
          combined.push(c);
        }
      }

      return res.json({ data: combined });
    } catch (err) {
      return next(err);
    }
  }
);

// POST /zk/circuits
advancedCryptoRouter.post(
  '/zk/circuits',
  requireOrgPermission('zk:circuit:create'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const { id, name, version, description, provingSystem, publicInputsSchema, privateInputsSchema, constraintsDescription, verificationKey } = req.body;

      const circuit = AdvancedCryptoService.createZkCircuit(orgId, {
        id,
        name,
        version: version || '1.0.0',
        description,
        provingSystem,
        publicInputsSchema: publicInputsSchema || ['commitment'],
        privateInputsSchema: privateInputsSchema || ['secretValue'],
        constraintsDescription: constraintsDescription || 'C == x * G',
        verificationKey,
        status: 'ACTIVE',
        organizationId: orgId
      });

      await db.createZkCircuit({
        id: circuit.id,
        organizationId: orgId,
        name: circuit.name,
        version: circuit.version,
        description: circuit.description,
        provingSystem: circuit.provingSystem,
        publicInputsSchema: circuit.publicInputsSchema,
        privateInputsSchema: circuit.privateInputsSchema,
        constraintsDescription: circuit.constraintsDescription,
        verificationKey: circuit.verificationKey,
        provingKeyMetadata: circuit.provingKeyMetadata,
        status: circuit.status,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'ZK_CIRCUIT_CREATED',
        resourceType: 'ZkCircuit',
        resourceId: circuit.id,
        metadata: { circuitId: circuit.id, version: circuit.version, provingSystem: circuit.provingSystem }
      });

      return res.status(201).json({ data: circuit });
    } catch (err) {
      return next(err);
    }
  }
);

// GET /zk/circuits/:id
advancedCryptoRouter.get(
  '/zk/circuits/:id',
  requireOrgPermission('zk:circuit:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const version = req.query.version as string | undefined;
      const circuit = AdvancedCryptoService.getZkCircuit(req.params.id, version, orgId);
      return res.json({ data: circuit });
    } catch (err) {
      return next(err);
    }
  }
);

// POST /zk/prove
advancedCryptoRouter.post(
  '/zk/prove',
  requireOrgPermission('zk:prove'),
  requireOperationAllowance(1),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const { circuitId, version, statement, witness } = req.body;

      const proof = AdvancedCryptoService.generateZkProof(
        circuitId,
        version || '1.0.0',
        statement,
        witness,
        orgId
      );

      // Audit proof generation with ZERO witness exposure
      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'ZK_PROOF_GENERATED',
        resourceType: 'ZkProof',
        resourceId: circuitId,
        metadata: { circuitId, version: proof.version, provingSystem: proof.provingSystem }
      });

      await recordBillableOp(req, 'ZK_PROVE');
      return res.json({ data: proof });
    } catch (err) {
      return next(err);
    }
  }
);

// POST /zk/verify
advancedCryptoRouter.post(
  '/zk/verify',
  requireOrgPermission('zk:verify'),
  requireOperationAllowance(1),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const { circuitId, version, statement, proof } = req.body;

      const result = AdvancedCryptoService.verifyZkProof(
        circuitId,
        version || '1.0.0',
        statement,
        proof,
        orgId
      );

      await db.createZkProofRecord({
        id: `zkp_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
        organizationId: orgId,
        circuitId,
        circuitVersion: version || '1.0.0',
        publicInputs: statement?.publicInputs || {},
        proofData: proof?.proofData || {},
        verified: result.valid,
        durationMs: result.durationMs,
        createdAt: new Date()
      });

      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: result.valid ? 'ZK_PROOF_VERIFIED' : 'ZK_PROOF_FAILED',
        resourceType: 'ZkProof',
        resourceId: circuitId,
        metadata: { circuitId, version, valid: result.valid, error: result.error }
      });

      await recordBillableOp(req, 'ZK_VERIFY');
      return res.json({ data: result });
    } catch (err) {
      return next(err);
    }
  }
);

// ==========================================
// 2. FHE Routes
// ==========================================

// POST /fhe/keygen
advancedCryptoRouter.post(
  '/fhe/keygen',
  requireOrgPermission('fhe:key:create'),
  requireOperationAllowance(1),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const { scheme, polyModulusDegree } = req.body;

      const keyMetadata = await AdvancedCryptoService.generateFheKey(
        orgId,
        scheme || 'BFV',
        polyModulusDegree || 4096
      );

      await db.createFheKey({
        id: keyMetadata.id,
        organizationId: orgId,
        scheme: keyMetadata.scheme,
        polyModulusDegree: keyMetadata.polyModulusDegree,
        publicKeyBase64: keyMetadata.publicKeyBase64,
        relinKeysBase64: keyMetadata.relinKeysBase64,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'FHE_KEY_CREATED',
        resourceType: 'FheKey',
        resourceId: keyMetadata.id,
        metadata: { keyId: keyMetadata.id, scheme: keyMetadata.scheme, polyModulusDegree: keyMetadata.polyModulusDegree }
      });

      await recordBillableOp(req, 'FHE_KEYGEN');
      return res.status(201).json({ data: keyMetadata });
    } catch (err) {
      return next(err);
    }
  }
);

// GET /fhe/keys
advancedCryptoRouter.get(
  '/fhe/keys',
  requireOrgPermission('fhe:key:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const keys = await db.listFheKeys(orgId);
      return res.json({ data: keys });
    } catch (err) {
      return next(err);
    }
  }
);

// GET /fhe/keys/:id
advancedCryptoRouter.get(
  '/fhe/keys/:id',
  requireOrgPermission('fhe:key:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const key = AdvancedCryptoService.getFheKey(req.params.id, orgId);
      return res.json({ data: key });
    } catch (err) {
      return next(err);
    }
  }
);

// POST /fhe/encrypt
advancedCryptoRouter.post(
  '/fhe/encrypt',
  requireOrgPermission('fhe:encrypt'),
  requireOperationAllowance(1),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const { keyId, value } = req.body;

      const ciphertext = await AdvancedCryptoService.encryptFhe(keyId, value, orgId);

      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'FHE_ENCRYPTION_REQUESTED',
        resourceType: 'FheCiphertext',
        resourceId: keyId,
        metadata: { keyId, scheme: ciphertext.scheme }
      });

      await recordBillableOp(req, 'FHE_ENCRYPT');
      return res.json({ data: ciphertext });
    } catch (err) {
      return next(err);
    }
  }
);

// POST /fhe/decrypt
advancedCryptoRouter.post(
  '/fhe/decrypt',
  requireOrgPermission('fhe:decrypt'),
  requireOperationAllowance(1),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const { keyId, ciphertextBase64 } = req.body;

      const decryptedValue = await AdvancedCryptoService.decryptFhe(keyId, ciphertextBase64, orgId);

      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'FHE_DECRYPTION_REQUESTED',
        resourceType: 'FheCiphertext',
        resourceId: keyId,
        metadata: { keyId }
      });

      await recordBillableOp(req, 'FHE_DECRYPT');
      return res.json({ data: { value: decryptedValue } });
    } catch (err) {
      return next(err);
    }
  }
);

// POST /fhe/evaluate
advancedCryptoRouter.post(
  '/fhe/evaluate',
  requireOrgPermission('fhe:evaluate'),
  requireOperationAllowance(1),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const { keyId, operation, ciphertexts } = req.body;

      const result = await AdvancedCryptoService.evaluateFhe({
        keyId,
        operation,
        ciphertexts
      }, orgId);

      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'FHE_OPERATION_EXECUTED',
        resourceType: 'FheCiphertext',
        resourceId: keyId,
        metadata: { keyId, operation, durationMs: result.durationMs, depth: result.operationDepth }
      });

      await recordBillableOp(req, 'FHE_EVALUATE');
      return res.json({ data: result });
    } catch (err) {
      return next(err);
    }
  }
);

// GET /fhe/limits
advancedCryptoRouter.get(
  '/fhe/limits',
  requireOrgPermission('fhe:key:read'),
  async (_req: Request, res: Response) => {
    return res.json({ data: AdvancedCryptoService.getFheLimits() });
  }
);

// ==========================================
// MPC and threshold signing are disabled: the MPC engine sees every party's
// input, and threshold signing reuses a fixed nonce, which leaks the private key.
// This guard is registered first, so the handlers below are unreachable.
// ==========================================
advancedCryptoRouter.all(['/mpc', '/mpc/*', '/threshold', '/threshold/*'], (req: Request, res: Response) => {
  return res.status(501).json({
    error: {
      code: 'NOT_IMPLEMENTED',
      message: 'MPC and threshold signing are not available.',
      requestId: (req as any).requestId,
    },
  });
});

// ==========================================
// 3. MPC Routes
// ==========================================

// POST /mpc/sessions
advancedCryptoRouter.post(
  '/mpc/sessions',
  requireOrgPermission('mpc:session:create'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const { title, operation, requiredParties, threshold } = req.body;

      const session = AdvancedCryptoService.createMpcSession(
        orgId,
        title || 'Secure Multi-Party Aggregation',
        operation || 'SECURE_SUM',
        requiredParties || 2,
        threshold || 2
      );

      await db.createMpcSession({
        id: session.id,
        organizationId: orgId,
        title: session.title,
        protocol: session.protocol,
        operation: session.operation,
        requiredParties: session.requiredParties,
        threshold: session.threshold,
        status: session.status,
        currentRound: session.currentRound,
        totalRounds: session.totalRounds,
        expiresAt: new Date(session.expiresAt),
        createdAt: new Date(),
        updatedAt: new Date()
      });

      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'MPC_SESSION_CREATED',
        resourceType: 'MpcSession',
        resourceId: session.id,
        metadata: { sessionId: session.id, operation: session.operation, requiredParties: session.requiredParties }
      });

      return res.status(201).json({ data: session });
    } catch (err) {
      return next(err);
    }
  }
);

// GET /mpc/sessions
advancedCryptoRouter.get(
  '/mpc/sessions',
  requireOrgPermission('mpc:session:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const sessions = await db.listMpcSessions(orgId);
      return res.json({ data: sessions });
    } catch (err) {
      return next(err);
    }
  }
);

// GET /mpc/sessions/:id
advancedCryptoRouter.get(
  '/mpc/sessions/:id',
  requireOrgPermission('mpc:session:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const session = AdvancedCryptoService.getMpcSession(req.params.id, orgId);
      return res.json({ data: session });
    } catch (err) {
      return next(err);
    }
  }
);

// POST /mpc/sessions/:id/join
advancedCryptoRouter.post(
  '/mpc/sessions/:id/join',
  requireOrgPermission('mpc:session:join'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const { partyId, name, role } = req.body;

      const session = AdvancedCryptoService.joinMpcSession(
        req.params.id,
        partyId,
        name || partyId,
        role || 'INPUT_PARTY',
        orgId
      );

      await db.updateMpcSession(orgId, session.id, {
        status: session.status,
        currentRound: session.currentRound
      });

      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'MPC_PARTY_JOINED',
        resourceType: 'MpcSession',
        resourceId: session.id,
        metadata: { sessionId: session.id, partyId }
      });

      return res.json({ data: session });
    } catch (err) {
      return next(err);
    }
  }
);

// POST /mpc/sessions/:id/input
advancedCryptoRouter.post(
  '/mpc/sessions/:id/input',
  requireOrgPermission('mpc:input'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const { partyId, input } = req.body;

      const session = AdvancedCryptoService.submitMpcPartyInput(
        req.params.id,
        partyId,
        Number(input),
        orgId
      );

      await db.updateMpcSession(orgId, session.id, {
        status: session.status
      });

      // Strict Zero Secret Leakage: input is NEVER logged!
      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'MPC_INPUT_SUBMITTED',
        resourceType: 'MpcSession',
        resourceId: session.id,
        metadata: { sessionId: session.id, partyId }
      });

      return res.json({ data: session });
    } catch (err) {
      return next(err);
    }
  }
);

// POST /mpc/sessions/:id/execute
advancedCryptoRouter.post(
  '/mpc/sessions/:id/execute',
  requireOrgPermission('mpc:execute'),
  requireOperationAllowance(1),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const session = AdvancedCryptoService.executeMpcRound(req.params.id, orgId);

      await db.updateMpcSession(orgId, session.id, {
        status: session.status,
        currentRound: session.currentRound,
        result: session.result
      });

      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'MPC_SESSION_COMPLETED',
        resourceType: 'MpcSession',
        resourceId: session.id,
        metadata: { sessionId: session.id, status: session.status }
      });

      await recordBillableOp(req, 'MPC_EXECUTE');
      return res.json({ data: session });
    } catch (err) {
      return next(err);
    }
  }
);

// GET /mpc/sessions/:id/result
advancedCryptoRouter.get(
  '/mpc/sessions/:id/result',
  requireOrgPermission('mpc:session:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const session = AdvancedCryptoService.getMpcSession(req.params.id, orgId);
      return res.json({ data: { result: session.result, status: session.status } });
    } catch (err) {
      return next(err);
    }
  }
);

// ==========================================
// 4. Threshold Routes
// ==========================================

// POST /threshold/keys
advancedCryptoRouter.post(
  '/threshold/keys',
  requireOrgPermission('threshold:key:create'),
  requireOperationAllowance(1),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const { name, threshold, totalParticipants } = req.body;

      const key = AdvancedCryptoService.createThresholdKey(
        orgId,
        name || 'M-of-N Threshold Key',
        Number(threshold) || 3,
        Number(totalParticipants) || 5
      );

      await db.createThresholdKey({
        id: key.id,
        organizationId: orgId,
        name: key.name,
        algorithm: key.algorithm,
        threshold: key.threshold,
        totalParticipants: key.totalParticipants,
        groupPublicKey: key.groupPublicKey,
        participants: key.participants,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'THRESHOLD_KEY_CREATED',
        resourceType: 'ThresholdKey',
        resourceId: key.id,
        metadata: { keyId: key.id, threshold: key.threshold, totalParticipants: key.totalParticipants }
      });

      await recordBillableOp(req, 'THRESHOLD_KEYGEN');
      return res.status(201).json({ data: key });
    } catch (err) {
      return next(err);
    }
  }
);

// GET /threshold/keys
advancedCryptoRouter.get(
  '/threshold/keys',
  requireOrgPermission('threshold:key:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const keys = await db.listThresholdKeys(orgId);
      const inMem = AdvancedCryptoService.listThresholdKeys(orgId);

      const seen = new Set<string>();
      const combined = [];
      for (const k of [...keys, ...inMem]) {
        if (!seen.has(k.id)) {
          seen.add(k.id);
          combined.push(k);
        }
      }

      return res.json({ data: combined });
    } catch (err) {
      return next(err);
    }
  }
);

// GET /threshold/keys/:id
advancedCryptoRouter.get(
  '/threshold/keys/:id',
  requireOrgPermission('threshold:key:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const key = AdvancedCryptoService.getThresholdKey(req.params.id, orgId);
      return res.json({ data: key });
    } catch (err) {
      return next(err);
    }
  }
);

// POST /threshold/sessions
advancedCryptoRouter.post(
  '/threshold/sessions',
  requireOrgPermission('threshold:session:create'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const { keyId, operation, messageToSign, payloadToAuthorize } = req.body;

      const session = AdvancedCryptoService.createThresholdSession(
        orgId,
        keyId,
        operation || 'THRESHOLD_SIGN',
        messageToSign,
        payloadToAuthorize
      );

      await db.createThresholdSession({
        id: session.id,
        organizationId: orgId,
        keyId: session.keyId,
        operation: session.operation,
        messageToSign: session.messageToSign,
        payloadToAuthorize: session.payloadToAuthorize,
        threshold: session.threshold,
        totalParticipants: session.totalParticipants,
        approvals: session.approvals,
        status: session.status,
        expiresAt: new Date(session.expiresAt),
        createdAt: new Date(),
        updatedAt: new Date()
      });

      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'THRESHOLD_SESSION_CREATED',
        resourceType: 'ThresholdSession',
        resourceId: session.id,
        metadata: { sessionId: session.id, keyId, threshold: session.threshold }
      });

      return res.status(201).json({ data: session });
    } catch (err) {
      return next(err);
    }
  }
);

// GET /threshold/sessions/:id
advancedCryptoRouter.get(
  '/threshold/sessions/:id',
  requireOrgPermission('threshold:session:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const session = AdvancedCryptoService.getThresholdSession(req.params.id, orgId);
      return res.json({ data: session });
    } catch (err) {
      return next(err);
    }
  }
);

// POST /threshold/sessions/:id/approve
advancedCryptoRouter.post(
  '/threshold/sessions/:id/approve',
  requireOrgPermission('threshold:approve'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const { participantId } = req.body;

      const session = AdvancedCryptoService.approveThresholdSession(
        req.params.id,
        participantId,
        orgId
      );

      await db.updateThresholdSession(orgId, session.id, {
        approvals: session.approvals,
        status: session.status
      });

      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'THRESHOLD_PARTICIPANT_JOINED',
        resourceType: 'ThresholdSession',
        resourceId: session.id,
        metadata: { sessionId: session.id, participantId, approvalsCount: session.approvals.length }
      });

      return res.json({ data: session });
    } catch (err) {
      return next(err);
    }
  }
);

// POST /threshold/sessions/:id/execute
advancedCryptoRouter.post(
  '/threshold/sessions/:id/execute',
  requireOrgPermission('threshold:execute'),
  requireOperationAllowance(1),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.organizationId!;
      const session = AdvancedCryptoService.executeThresholdSession(req.params.id, orgId);

      await db.updateThresholdSession(orgId, session.id, {
        status: session.status,
        combinedResult: session.combinedResult
      });

      await db.createAuditEvent({
        organizationId: orgId,
        userId: (req as any).user?.id,
        action: 'THRESHOLD_OPERATION_COMPLETED',
        resourceType: 'ThresholdSession',
        resourceId: session.id,
        metadata: { sessionId: session.id, operation: session.operation }
      });

      await recordBillableOp(req, 'THRESHOLD_SIGN');
      return res.json({ data: session });
    } catch (err) {
      return next(err);
    }
  }
);

// ==========================================
// 5. Providers Route
// ==========================================

// GET /providers
advancedCryptoRouter.get(
  '/providers',
  requireOrgPermission('advanced:providers:read'),
  async (_req: Request, res: Response) => {
    const providers = AdvancedCryptoService.listProviders();
    return res.json({ data: providers });
  }
);
