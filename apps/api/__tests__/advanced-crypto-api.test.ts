/**
 * AMARACUS — Phase 9: Advanced Cryptography API Integration Tests
 * Multi-Tenancy, RBAC, ZK, FHE, MPC, Threshold & Audit Logging
 */

import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { AdvancedCryptoService, ZkCircuitEngine } from '@amaracus/crypto-core';

describe('Phase 9 — Advanced Cryptography API Routes & Security', () => {
  let server: http.Server;
  let baseUrl: string;

  let userA: any;
  let sessionA: any;
  let orgA: any;

  let userB: any;
  let sessionB: any;
  let orgB: any;

  let memberUserA: any;
  let memberSessionA: any;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Set up Tenant A (Owner)
    userA = await db.createUser({
      email: `adv_owner_a_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant A Advanced Owner',
    });
    orgA = await db.createOrganization({
      name: 'Tenant A Advanced Cryptography Corp',
      slug: `tenant-a-adv-${Date.now()}`,
    });
    await db.addMember({
      organizationId: orgA.id,
      userId: userA.id,
      role: 'OWNER',
    });
    sessionA = await db.createSession({
      userId: userA.id,
      activeOrgId: orgA.id,
      expiresAt: new Date(Date.now() + 86400000),
    });

    // Set up Tenant A Member (with MEMBER role)
    memberUserA = await db.createUser({
      email: `adv_member_a_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant A Member',
    });
    await db.addMember({
      organizationId: orgA.id,
      userId: memberUserA.id,
      role: 'MEMBER',
    });
    memberSessionA = await db.createSession({
      userId: memberUserA.id,
      activeOrgId: orgA.id,
      expiresAt: new Date(Date.now() + 86400000),
    });

    // Set up Tenant B (Owner)
    userB = await db.createUser({
      email: `adv_owner_b_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant B Advanced Owner',
    });
    orgB = await db.createOrganization({
      name: 'Tenant B Advanced Isolation Ltd',
      slug: `tenant-b-adv-${Date.now()}`,
    });
    await db.addMember({
      organizationId: orgB.id,
      userId: userB.id,
      role: 'OWNER',
    });
    sessionB = await db.createSession({
      userId: userB.id,
      activeOrgId: orgB.id,
      expiresAt: new Date(Date.now() + 86400000),
    });
  }, 60000);

  afterAll((done) => {
    server.close(done);
  });

  // =========================================================================
  // 1. TENANCY & AUTHENTICATION BOUNDARIES
  // =========================================================================
  describe('Authentication and Tenant Boundary Enforcement', () => {
    it('rejects unauthenticated requests with 401 Unauthorized', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/providers`);
      expect(res.status).toBe(401);
    });

    it('rejects cross-tenant access to advanced crypto routes with 403 Forbidden', async () => {
      // User B attempts to access Org A's advanced crypto endpoints
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/providers`, {
        headers: { Authorization: `Bearer ${sessionB.sessionToken}` },
      });
      const data = await res.json();
      expect(res.status).toBe(403);
      expect(data.error.code).toBe('FORBIDDEN');
    });
  });

  // =========================================================================
  // 2. PROVIDER REGISTRY & CAPABILITIES
  // =========================================================================
  describe('Preview labelling', () => {
    it('marks every advanced crypto response as a preview that is not production ready', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/providers`, {
        headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get('x-amaracus-preview')).toBe('true');
      const json = await res.json();
      expect(json.preview.status).toBe('PREVIEW');
      expect(json.preview.productionReady).toBe(false);
    });
  });

  describe('GET /v1/organizations/:orgId/advanced/providers', () => {
    it('returns verified advanced crypto providers with accurate readiness statuses', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/providers`, {
        headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(Array.isArray(json.data)).toBe(true);
      expect(json.data.length).toBeGreaterThanOrEqual(4);

      const families = json.data.map((p: any) => p.family);
      expect(families).toContain('ZK');
      expect(families).toContain('FHE');
      expect(families).toContain('MPC');
      expect(families).toContain('THRESHOLD');

      const seal = json.data.find((p: any) => p.providerId === 'fhe-microsoft-seal');
      expect(seal).toBeDefined();
      expect(seal.status).toBe('SUPPORTED');
      expect(seal.supportedSchemes).toContain('BFV');
      expect(seal.supportedOperations).toContain('ADD');
      expect(seal.supportedOperations).toContain('MULTIPLY');
    });
  });

  // =========================================================================
  // 3. ZERO-KNOWLEDGE PROOFS (ZK)
  // =========================================================================
  describe('Zero-Knowledge Proofs API Lifecycle', () => {
    let circuitId: string;
    let validCommitment: string;
    let secretWitness: string;

    beforeAll(() => {
      secretWitness = '42';
      // Compute valid commitment for secret 42
      validCommitment = ZkCircuitEngine.computeCommitment(BigInt(secretWitness));
    });

    it('registers a new ZK circuit definition under Tenant A', async () => {
      circuitId = `circ_test_${Date.now()}`;
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/zk/circuits`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          id: circuitId,
          name: 'Knowledge of Hash Preimage Circuit',
          version: '1.0.0',
          description: 'NIZK Schnorr/Pedersen over Ed25519',
          provingSystem: 'NIZK_SCHNORR_PEDERSEN',
          publicInputsSchema: ['commitment'],
          privateInputsSchema: ['secretValue'],
          constraintsDescription: 'C == Hash(secretValue)',
        }),
      });

      expect(res.status).toBe(201);
      const json = await res.json();
      expect(json.data.id).toBe(circuitId);
      expect(json.data.provingSystem).toBe('NIZK_SCHNORR_PEDERSEN');
      expect(json.data.version).toBe('1.0.0');
    });

    it('Tenant B cannot access Tenant A circuit via direct ID', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgB.id}/advanced/zk/circuits/${circuitId}`, {
        headers: { Authorization: `Bearer ${sessionB.sessionToken}` },
      });
      // Should fail closed with 403 or 404 since circuit belongs to Org A
      expect([400, 403, 404, 500]).toContain(res.status);
    });

    it('generates a valid zero-knowledge proof for Tenant A without exposing witness in response', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/zk/prove`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          circuitId,
          version: '1.0.0',
          statement: {
            circuitId,
            version: '1.0.0',
            publicInputs: { commitment: validCommitment },
          },
          witness: {
            circuitId,
            privateInputs: { secretValue: secretWitness },
          },
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.proofData).toBeDefined();
      expect(json.data.proofData.commitmentPointA).toBeDefined();
      expect(json.data.proofData.responseScalarS).toBeDefined();
      // Verify zero secret witness in response body
      expect((json.data as any).witness).toBeUndefined();
      expect((json.data.proofData as any).secretValue).toBeUndefined();
    });

    it('verifies a valid proof successfully', async () => {
      // First generate proof
      const proveRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/zk/prove`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          circuitId,
          version: '1.0.0',
          statement: {
            circuitId,
            version: '1.0.0',
            publicInputs: { commitment: validCommitment },
          },
          witness: {
            circuitId,
            privateInputs: { secretValue: secretWitness },
          },
        }),
      });
      const proveJson = await proveRes.json();
      const proof = proveJson.data;

      // Verify proof
      const verifyRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/zk/verify`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          circuitId,
          version: '1.0.0',
          statement: {
            circuitId,
            version: '1.0.0',
            publicInputs: { commitment: validCommitment },
          },
          proof,
        }),
      });

      expect(verifyRes.status).toBe(200);
      const verifyJson = await verifyRes.json();
      expect(verifyJson.data.valid).toBe(true);
    });

    it('rejects tampered or modified proof data', async () => {
      const verifyRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/zk/verify`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          circuitId,
          version: '1.0.0',
          statement: {
            circuitId,
            version: '1.0.0',
            publicInputs: { commitment: validCommitment },
          },
          proof: {
            circuitId,
            version: '1.0.0',
            provingSystem: 'NIZK_SCHNORR_PEDERSEN',
            proofData: { commitmentPointA: '00'.repeat(32), responseScalarS: 'ff'.repeat(32) },
            publicInputs: { commitment: validCommitment },
            createdAt: new Date().toISOString(),
          },
        }),
      });

      expect(verifyRes.status).toBe(200);
      const verifyJson = await verifyRes.json();
      expect(verifyJson.data.valid).toBe(false);
    });
  });

  // =========================================================================
  // 4. FULLY HOMOMORPHIC ENCRYPTION (FHE)
  // =========================================================================
  describe('Fully Homomorphic Encryption (SEAL BFV) API Lifecycle', () => {
    let keyId: string;
    let cipherA: string;
    let cipherB: string;

    it('returns FHE operational limits and parameter boundaries', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/fhe/limits`, {
        headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.supportedSchemes).toContain('BFV');
      expect(json.data.supportedOperations).toContain('ADD');
      expect(json.data.supportedOperations).toContain('MULTIPLY');
      expect(json.data.maxMultiplicationDepth).toBeGreaterThan(0);
    });

    it('generates an authentic Microsoft SEAL BFV keypair under Tenant A', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/fhe/keygen`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scheme: 'BFV',
          polyModulusDegree: 4096,
        }),
      });

      expect(res.status).toBe(201);
      const json = await res.json();
      expect(json.data.id).toBeDefined();
      expect(json.data.scheme).toBe('BFV');
      expect(json.data.publicKeyBase64).toBeDefined();
      // Secret key must never be sent in API response
      expect(json.data.secretKeyBase64).toBeUndefined();

      keyId = json.data.id;
    });

    it('encrypts integers into real BFV ciphertexts', async () => {
      // Encrypt 15
      const resA = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/fhe/encrypt`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ keyId, value: 15 }),
      });
      expect(resA.status).toBe(200);
      const jsonA = await resA.json();
      expect(jsonA.data.ciphertextBase64).toBeDefined();
      cipherA = jsonA.data.ciphertextBase64;

      // Encrypt 25
      const resB = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/fhe/encrypt`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ keyId, value: 25 }),
      });
      expect(resB.status).toBe(200);
      const jsonB = await resB.json();
      expect(jsonB.data.ciphertextBase64).toBeDefined();
      cipherB = jsonB.data.ciphertextBase64;

      // Ensure ciphertext is real encrypted data, not empty or short
      expect(cipherA.length).toBeGreaterThan(1000);
      expect(cipherB.length).toBeGreaterThan(1000);
    });

    it('performs homomorphic addition (15 + 25 = 40) directly on ciphertexts', async () => {
      const evalRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/fhe/evaluate`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          keyId,
          operation: 'ADD',
          ciphertexts: [cipherA, cipherB],
        }),
      });

      expect(evalRes.status).toBe(200);
      const evalJson = await evalRes.json();
      expect(evalJson.data.resultCiphertextBase64).toBeDefined();

      // Decrypt the homomorphic result
      const decRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/fhe/decrypt`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          keyId,
          ciphertextBase64: evalJson.data.resultCiphertextBase64,
        }),
      });

      expect(decRes.status).toBe(200);
      const decJson = await decRes.json();
      expect(decJson.data.value).toBe(40);
    });

    it('performs homomorphic multiplication (15 * 25 = 375) directly on ciphertexts', async () => {
      const evalRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/fhe/evaluate`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          keyId,
          operation: 'MULTIPLY',
          ciphertexts: [cipherA, cipherB],
        }),
      });

      expect(evalRes.status).toBe(200);
      const evalJson = await evalRes.json();
      expect(evalJson.data.resultCiphertextBase64).toBeDefined();

      // Decrypt the homomorphic multiplication result
      const decRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/fhe/decrypt`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          keyId,
          ciphertextBase64: evalJson.data.resultCiphertextBase64,
        }),
      });

      expect(decRes.status).toBe(200);
      const decJson = await decRes.json();
      expect(decJson.data.value).toBe(375);
    });

    it('rejects cross-tenant decryption attempt by Tenant B', async () => {
      const decRes = await fetch(`${baseUrl}/v1/organizations/${orgB.id}/advanced/fhe/decrypt`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionB.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          keyId,
          ciphertextBase64: cipherA,
        }),
      });

      // Tenant B cannot decrypt Tenant A's key
      expect([400, 403, 404, 500]).toContain(decRes.status);
    });
  });

  // =========================================================================
  // 5. MULTI-PARTY COMPUTATION (MPC)
  // =========================================================================
  // MPC (server sees every input) and threshold signing (fixed nonce leaks the key)
  // are disabled until they are rebuilt; every route answers 501.
  describe('MPC and threshold signing are disabled', () => {
    it.each([
      ['POST', 'mpc/sessions'],
      ['GET', 'mpc/sessions'],
      ['POST', 'mpc/sessions/any/execute'],
      ['POST', 'threshold/keys'],
      ['POST', 'threshold/sessions'],
      ['POST', 'threshold/sessions/any/execute'],
    ])('%s %s returns 501', async (method, path) => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/advanced/${path}`, {
        method,
        headers: { Authorization: `Bearer ${sessionA.sessionToken}`, 'Content-Type': 'application/json' },
        body: method === 'POST' ? JSON.stringify({}) : undefined,
      });
      expect(res.status).toBe(501);
    });
  });

  describe('Audit Logging and Secret Leakage Prevention', () => {
    it('records immutable audit events with zero secret or witness leakage', async () => {
      const events = await db.getAuditEventsByOrg(orgA.id, 50);
      expect(events.length).toBeGreaterThan(0);

      const actions = events.map((e: any) => e.action);
      expect(actions).toContain('ZK_CIRCUIT_CREATED');
      expect(actions).toContain('ZK_PROOF_GENERATED');
      expect(actions).toContain('FHE_KEY_CREATED');

      // Verify that no private witnesses, shares, or raw secrets exist in audit metadata
      for (const event of events) {
        const str = JSON.stringify(event);
        expect(str).not.toContain('secretWitness');
        expect(str).not.toContain('secretKeyBase64');
        expect(str).not.toContain('polynomialCoefficients');
      }
    });
  });
});
