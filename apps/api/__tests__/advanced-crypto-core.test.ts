/**
 * AMARACUS — Phase 9: Advanced Cryptography Core Tests
 * Unit tests for ZK, FHE, MPC, and Threshold Cryptography engines.
 */

import {
  AdvancedCryptoService,
  ZkCircuitEngine,
  FheEngine,
  MpcEngine,
  ThresholdEngine,
  AdvancedCryptoProviderRegistry,
  AdvancedCryptoPolicyEngine
} from '@amaracus/crypto-core';

describe('Phase 9 — Advanced Cryptography Core Engines', () => {
  const testOrgId = 'org-adv-test-01';

  // ==========================================
  // 1. Zero-Knowledge Proof (ZK) Tests
  // ==========================================
  describe('Zero-Knowledge Proofs (NIZK Schnorr/Pedersen)', () => {
    const circuitId = 'circuit-secret-commitment-v1';
    const version = '1.0.0';

    it('retrieves default commitment circuit definition with correct schema', () => {
      const circuit = ZkCircuitEngine.getCircuit(circuitId, version);
      expect(circuit.id).toBe(circuitId);
      expect(circuit.version).toBe(version);
      expect(circuit.provingSystem).toBe('NIZK_SCHNORR_PEDERSEN');
      expect(circuit.publicInputsSchema).toContain('commitment');
      expect(circuit.privateInputsSchema).toContain('secretValue');
      expect(circuit.verificationKey.curve).toBe('ed25519');
    });

    it('generates and verifies a valid zero-knowledge proof without leaking secret', () => {
      // Public commitment C = x * G
      const secretValue = 123456789n;
      const commitmentHex = ZkCircuitEngine.computeCommitment(secretValue);

      const statement = {
        circuitId,
        version,
        publicInputs: { commitment: commitmentHex }
      };

      const witness = {
        privateInputs: { secretValue: secretValue.toString() }
      };

      // Prover generates proof
      const proof = AdvancedCryptoService.generateZkProof(circuitId, version, statement, witness, testOrgId);
      expect(proof.circuitId).toBe(circuitId);
      expect(proof.version).toBe(version);
      expect(proof.proofData.commitmentPointA).toBeDefined();
      expect(proof.proofData.responseScalarS).toBeDefined();

      // Ensure secretValue is NEVER exposed in the proof object
      expect(JSON.stringify(proof)).not.toContain(secretValue.toString());

      // Verifier verifies proof (Verifier receives ONLY statement and proof, NEVER witness!)
      const verifyResult = AdvancedCryptoService.verifyZkProof(circuitId, version, statement, proof, testOrgId);
      expect(verifyResult.valid).toBe(true);
      expect(verifyResult.error).toBeUndefined();
    });

    it('fails proof generation if witness does not satisfy the commitment', () => {
      const actualSecret = 42n;
      const fakeSecret = 999n;
      const commitmentHex = ZkCircuitEngine.computeCommitment(actualSecret);

      const statement = {
        circuitId,
        version,
        publicInputs: { commitment: commitmentHex }
      };

      const invalidWitness = {
        privateInputs: { secretValue: fakeSecret.toString() }
      };

      expect(() => {
        AdvancedCryptoService.generateZkProof(circuitId, version, statement, invalidWitness, testOrgId);
      }).toThrow('Witness does not satisfy the public commitment statement');
    });

    it('rejects verification if proof data is modified/tampered', () => {
      const secretValue = 555n;
      const commitmentHex = ZkCircuitEngine.computeCommitment(secretValue);

      const statement = {
        circuitId,
        version,
        publicInputs: { commitment: commitmentHex }
      };

      const proof = AdvancedCryptoService.generateZkProof(
        circuitId,
        version,
        statement,
        { privateInputs: { secretValue: secretValue.toString() } },
        testOrgId
      );

      // Tamper response scalar s
      const tamperedProof = {
        ...proof,
        proofData: {
          ...proof.proofData,
          responseScalarS: 'deadbeef'
        }
      };

      const result = AdvancedCryptoService.verifyZkProof(circuitId, version, statement, tamperedProof, testOrgId);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('failed');
    });

    it('rejects verification if wrong public input is provided', () => {
      const secretValue = 777n;
      const commitmentHex = ZkCircuitEngine.computeCommitment(secretValue);
      const wrongCommitmentHex = ZkCircuitEngine.computeCommitment(888n);

      const statement = {
        circuitId,
        version,
        publicInputs: { commitment: commitmentHex }
      };

      const proof = AdvancedCryptoService.generateZkProof(
        circuitId,
        version,
        statement,
        { privateInputs: { secretValue: secretValue.toString() } },
        testOrgId
      );

      // Verify against wrong statement
      const wrongStatement = {
        circuitId,
        version,
        publicInputs: { commitment: wrongCommitmentHex }
      };

      const result = AdvancedCryptoService.verifyZkProof(circuitId, version, wrongStatement, proof, testOrgId);
      expect(result.valid).toBe(false);
    });

    it('strictly forbids cross-circuit or cross-version proof verification', () => {
      const secretValue = 101n;
      const commitmentHex = ZkCircuitEngine.computeCommitment(secretValue);

      const statement = {
        circuitId,
        version,
        publicInputs: { commitment: commitmentHex }
      };

      const proof = AdvancedCryptoService.generateZkProof(
        circuitId,
        version,
        statement,
        { privateInputs: { secretValue: secretValue.toString() } },
        testOrgId
      );

      // Try to verify with wrong version
      const wrongVersionProof = { ...proof, version: '2.0.0' };
      const res1 = AdvancedCryptoService.verifyZkProof(circuitId, version, statement, wrongVersionProof, testOrgId);
      expect(res1.valid).toBe(false);
      expect(res1.error).toContain("does not match");
    });
  });

  // ==========================================
  // 2. Fully Homomorphic Encryption (FHE) Tests
  // ==========================================
  describe('Fully Homomorphic Encryption (Microsoft SEAL BFV)', () => {
    let keyId: string;

    beforeAll(async () => {
      const keyMeta = await AdvancedCryptoService.generateFheKey(testOrgId, 'BFV', 4096);
      keyId = keyMeta.id;
      expect(keyMeta.scheme).toBe('BFV');
      expect(keyMeta.polyModulusDegree).toBe(4096);
      expect(keyMeta.publicKeyBase64).toBeDefined();
    });

    it('performs roundtrip homomorphic encryption and decryption of an integer', async () => {
      const originalValue = 42;
      const cipher = await AdvancedCryptoService.encryptFhe(keyId, originalValue, testOrgId);
      expect(cipher.ciphertextBase64).toBeDefined();
      expect(cipher.ciphertextBase64.length).toBeGreaterThan(1000);

      const decrypted = await AdvancedCryptoService.decryptFhe(keyId, cipher.ciphertextBase64, testOrgId);
      expect(decrypted).toBe(originalValue);
    });

    it('executes homomorphic addition directly on ciphertexts without decryption (10 + 20 = 30)', async () => {
      const c1 = await AdvancedCryptoService.encryptFhe(keyId, 10, testOrgId);
      const c2 = await AdvancedCryptoService.encryptFhe(keyId, 20, testOrgId);

      const evalResult = await AdvancedCryptoService.evaluateFhe({
        keyId,
        operation: 'ADD',
        ciphertexts: [c1.ciphertextBase64, c2.ciphertextBase64]
      }, testOrgId);

      expect(evalResult.operation).toBe('ADD');
      expect(evalResult.resultCiphertextBase64).toBeDefined();

      const decryptedSum = await AdvancedCryptoService.decryptFhe(keyId, evalResult.resultCiphertextBase64, testOrgId);
      expect(decryptedSum).toBe(30);
    });

    it('executes homomorphic subtraction directly on ciphertexts (50 - 20 = 30)', async () => {
      const c1 = await AdvancedCryptoService.encryptFhe(keyId, 50, testOrgId);
      const c2 = await AdvancedCryptoService.encryptFhe(keyId, 20, testOrgId);

      const evalResult = await AdvancedCryptoService.evaluateFhe({
        keyId,
        operation: 'SUBTRACT',
        ciphertexts: [c1.ciphertextBase64, c2.ciphertextBase64]
      }, testOrgId);

      const decryptedDiff = await AdvancedCryptoService.decryptFhe(keyId, evalResult.resultCiphertextBase64, testOrgId);
      expect(decryptedDiff).toBe(30);
    });

    it('executes homomorphic multiplication directly on ciphertexts (10 * 20 = 200)', async () => {
      const c1 = await AdvancedCryptoService.encryptFhe(keyId, 10, testOrgId);
      const c2 = await AdvancedCryptoService.encryptFhe(keyId, 20, testOrgId);

      const evalResult = await AdvancedCryptoService.evaluateFhe({
        keyId,
        operation: 'MULTIPLY',
        ciphertexts: [c1.ciphertextBase64, c2.ciphertextBase64]
      }, testOrgId);

      expect(evalResult.operationDepth).toBe(2);
      const decryptedProd = await AdvancedCryptoService.decryptFhe(keyId, evalResult.resultCiphertextBase64, testOrgId);
      expect(decryptedProd).toBe(200);
    });

    it('executes homomorphic negation directly on ciphertext (-42)', async () => {
      const c = await AdvancedCryptoService.encryptFhe(keyId, 42, testOrgId);

      const evalResult = await AdvancedCryptoService.evaluateFhe({
        keyId,
        operation: 'NEGATE',
        ciphertexts: [c.ciphertextBase64]
      }, testOrgId);

      const decryptedNeg = await AdvancedCryptoService.decryptFhe(keyId, evalResult.resultCiphertextBase64, testOrgId);
      expect(decryptedNeg).toBe(-42);
    });

    it('rejects non-integer inputs for BFV scheme with clear error', async () => {
      await expect(
        AdvancedCryptoService.encryptFhe(keyId, 3.14159, testOrgId)
      ).rejects.toThrow('BFV scheme operates strictly on exact integers');
    });

    it('rejects malformed ciphertexts on decryption', async () => {
      await expect(
        AdvancedCryptoService.decryptFhe(keyId, 'invalid-malformed-base64', testOrgId)
      ).rejects.toThrow('Failed to load ciphertext');
    });

    it('communicates explicit FHE limits transparently', () => {
      const limits = AdvancedCryptoService.getFheLimits();
      expect(limits.maxPolyModulusDegree).toBe(8192);
      expect(limits.maxMultiplicationDepth).toBe(4);
      expect(limits.supportedSchemes).toContain('BFV');
      expect(limits.supportedOperations).toEqual(['ADD', 'SUBTRACT', 'MULTIPLY', 'NEGATE']);
    });
  });

  // ==========================================
  // 3. Multi-Party Computation (MPC) Tests
  // ==========================================
  describe('Multi-Party Computation (Additive Secret Sharing MPC)', () => {
    it('executes end-to-end 2-party secure sum (10 + 20 = 30) without revealing raw inputs', () => {
      const session = AdvancedCryptoService.createMpcSession(
        testOrgId,
        'Joint Balance Computation',
        'SECURE_SUM',
        2,
        2
      );

      expect(session.status).toBe('WAITING_FOR_PARTIES');

      // Party A and Party B join
      AdvancedCryptoService.joinMpcSession(session.id, 'party-alice', 'Alice', 'INPUT_PARTY', testOrgId);
      const readySession = AdvancedCryptoService.joinMpcSession(session.id, 'party-bob', 'Bob', 'INPUT_PARTY', testOrgId);
      expect(readySession.status).toBe('WAITING_FOR_INPUTS');

      // Party A submits 10 (split into blinded shares internally)
      AdvancedCryptoService.submitMpcPartyInput(session.id, 'party-alice', 10, testOrgId);

      // Party B submits 20
      const compSession = AdvancedCryptoService.submitMpcPartyInput(session.id, 'party-bob', 20, testOrgId);
      expect(compSession.status).toBe('COMPUTING_ROUND');

      // Execute round to compute final aggregate
      const finalSession = AdvancedCryptoService.executeMpcRound(session.id, testOrgId);
      expect(finalSession.status).toBe('COMPLETED');
      expect(finalSession.result?.computedValue).toBe(30);
      expect(finalSession.result?.participatingParties).toEqual(['party-alice', 'party-bob']);
    });

    it('fails round execution if insufficient parties submit inputs', () => {
      const session = AdvancedCryptoService.createMpcSession(testOrgId, 'Incomplete Session', 'SECURE_SUM', 2, 2);
      AdvancedCryptoService.joinMpcSession(session.id, 'party-1', 'P1', 'INPUT_PARTY', testOrgId);
      AdvancedCryptoService.joinMpcSession(session.id, 'party-2', 'P2', 'INPUT_PARTY', testOrgId);

      // Only party 1 submits
      AdvancedCryptoService.submitMpcPartyInput(session.id, 'party-1', 100, testOrgId);

      expect(() => {
        AdvancedCryptoService.executeMpcRound(session.id, testOrgId);
      }).toThrow('Insufficient participants to execute MPC computation');
    });

    it('rejects duplicate party joins', () => {
      const session = AdvancedCryptoService.createMpcSession(testOrgId, 'Duplicate Test', 'SECURE_SUM', 2, 2);
      AdvancedCryptoService.joinMpcSession(session.id, 'party-dup', 'P-Dup', 'INPUT_PARTY', testOrgId);

      expect(() => {
        AdvancedCryptoService.joinMpcSession(session.id, 'party-dup', 'P-Dup', 'INPUT_PARTY', testOrgId);
      }).toThrow('already registered in this session');
    });

    it('rejects unauthorized input submission from party not in session', () => {
      const session = AdvancedCryptoService.createMpcSession(testOrgId, 'Auth Test', 'SECURE_SUM', 2, 2);
      AdvancedCryptoService.joinMpcSession(session.id, 'party-a', 'A', 'INPUT_PARTY', testOrgId);
      AdvancedCryptoService.joinMpcSession(session.id, 'party-b', 'B', 'INPUT_PARTY', testOrgId);

      expect(() => {
        AdvancedCryptoService.submitMpcPartyInput(session.id, 'intruder-party', 999, testOrgId);
      }).toThrow('not authorized in this session');
    });
  });

  // ==========================================
  // 4. Threshold Cryptography Tests
  // ==========================================
  describe('Threshold Cryptography (3-of-5 Quorum)', () => {
    let key: any;

    beforeAll(() => {
      // 3-of-5 threshold key
      key = AdvancedCryptoService.createThresholdKey(
        testOrgId,
        'Treasury Master Key',
        3,
        5
      );
      expect(key.threshold).toBe(3);
      expect(key.totalParticipants).toBe(5);
      expect(key.participants.length).toBe(5);
      expect(key.groupPublicKey).toBeDefined();
    });

    it('rejects execution when only 2 of 5 participants approve (M = 3)', () => {
      const session = AdvancedCryptoService.createThresholdSession(
        testOrgId,
        key.id,
        'THRESHOLD_SIGN',
        'Transfer $1,000,000 to Staging'
      );

      const p1 = key.participants[0].participantId;
      const p2 = key.participants[1].participantId;

      AdvancedCryptoService.approveThresholdSession(session.id, p1, testOrgId);
      AdvancedCryptoService.approveThresholdSession(session.id, p2, testOrgId);

      // Attempt execution with only 2 approvals for 3-of-5 policy
      expect(() => {
        AdvancedCryptoService.executeThresholdSession(session.id, testOrgId);
      }).toThrow('Threshold policy violated: requires 3 participants, but only 2 approved');
    });

    it('successfully executes when exactly 3 of 5 participants approve (M = 3)', () => {
      const session = AdvancedCryptoService.createThresholdSession(
        testOrgId,
        key.id,
        'THRESHOLD_SIGN',
        'Deploy smart contract v2'
      );

      const p1 = key.participants[0].participantId;
      const p2 = key.participants[1].participantId;
      const p3 = key.participants[2].participantId;

      AdvancedCryptoService.approveThresholdSession(session.id, p1, testOrgId);
      AdvancedCryptoService.approveThresholdSession(session.id, p2, testOrgId);
      const readySess = AdvancedCryptoService.approveThresholdSession(session.id, p3, testOrgId);

      expect(readySess.status).toBe('READY');

      const executedSess = AdvancedCryptoService.executeThresholdSession(session.id, testOrgId);
      expect(executedSess.status).toBe('EXECUTED');
      expect(executedSess.combinedResult?.authorized).toBe(true);
      expect(executedSess.combinedResult?.signature).toBeDefined();
    });

    it('successfully executes when 4 or 5 participants approve (super-quorum)', () => {
      const session = AdvancedCryptoService.createThresholdSession(
        testOrgId,
        key.id,
        'THRESHOLD_AUTHORIZATION',
        undefined,
        'Emergency Key Rollover'
      );

      for (let i = 0; i < 4; i++) {
        AdvancedCryptoService.approveThresholdSession(session.id, key.participants[i].participantId, testOrgId);
      }

      const executedSess = AdvancedCryptoService.executeThresholdSession(session.id, testOrgId);
      expect(executedSess.status).toBe('EXECUTED');
      expect(executedSess.combinedResult?.authorized).toBe(true);
    });

    it('prevents double-approval by the same participant', () => {
      const session = AdvancedCryptoService.createThresholdSession(
        testOrgId,
        key.id,
        'THRESHOLD_AUTHORIZATION',
        undefined,
        'Auth Test'
      );

      const p1 = key.participants[0].participantId;
      AdvancedCryptoService.approveThresholdSession(session.id, p1, testOrgId);

      expect(() => {
        AdvancedCryptoService.approveThresholdSession(session.id, p1, testOrgId);
      }).toThrow('already approved this session');
    });
  });

  // ==========================================
  // 5. Provider & Policy Registry Tests
  // ==========================================
  describe('Provider Registry & Policy Enforcement', () => {
    it('lists verified providers with accurate readiness statuses', () => {
      const providers = AdvancedCryptoProviderRegistry.listProviders();
      expect(providers.length).toBeGreaterThanOrEqual(4);

      const sealProvider = providers.find(p => p.providerId === 'fhe-microsoft-seal');
      expect(sealProvider?.status).toBe('SUPPORTED');
      expect(sealProvider?.supportedSchemes).toContain('BFV');
      expect(sealProvider?.limitations.supportsRealNumbers).toBe(false);

      const ckksProvider = providers.find(p => p.providerId === 'fhe-seal-ckks');
      expect(ckksProvider?.status).toBe('EXPERIMENTAL');
    });

    it('enforces policy constraints on ZK, FHE, and Threshold', () => {
      expect(() => {
        AdvancedCryptoPolicyEngine.validateZkSystem('GROTH16_R1CS');
      }).toThrow('not permitted by active organization policy');

      expect(() => {
        AdvancedCryptoPolicyEngine.validateThreshold(1, 5);
      }).toThrow('below the policy minimum');
    });
  });
});
