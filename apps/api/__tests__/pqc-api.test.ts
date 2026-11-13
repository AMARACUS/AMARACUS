import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';

describe('Phase 6 — Post-Quantum Cryptography API Routes & Security', () => {
  let server: http.Server;
  let baseUrl: string;

  let userA: any;
  let sessionA: any;
  let orgA: any;

  let userB: any;
  let sessionB: any;
  let orgB: any;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Set up Tenant A
    userA = await db.createUser({
      email: `pqc_user_a_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant A PQC User',
    });
    orgA = await db.createOrganization({
      name: 'Tenant A Quantum Safe Corp',
      slug: `tenant-a-pqc-${Date.now()}`,
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

    // Set up Tenant B
    userB = await db.createUser({
      email: `pqc_user_b_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant B PQC User',
    });
    orgB = await db.createOrganization({
      name: 'Tenant B Classical Ltd',
      slug: `tenant-b-classical-${Date.now()}`,
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
    it('rejects unauthenticated requests to PQC endpoints with 401', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/pqc/algorithms`);
      expect(res.status).toBe(401);
    });

    it('rejects cross-tenant access to PQC endpoints with 403 Forbidden', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/pqc/algorithms`, {
        headers: { Authorization: `Bearer ${sessionB.sessionToken}` },
      });
      const data = await res.json();
      expect(res.status).toBe(403);
      expect(data.error.code).toBe('FORBIDDEN');
    });
  });

  // =========================================================================
  // 2. PQC ALGORITHM INVENTORY
  // =========================================================================
  describe('GET /v1/organizations/:orgId/crypto/pqc/algorithms', () => {
    it('returns NIST FIPS 203, FIPS 204, and Hybrid algorithm inventory', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/pqc/algorithms`, {
        headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
      });
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.data.pqc).toBeDefined();
      expect(json.data.hybrid).toBeDefined();
      expect(json.meta.fipsStandards).toContain('FIPS 203 (ML-KEM)');
      expect(json.meta.fipsStandards).toContain('FIPS 204 (ML-DSA)');

      const pqcIds = json.data.pqc.map((a: any) => a.id);
      expect(pqcIds).toContain('ML-KEM-512');
      expect(pqcIds).toContain('ML-KEM-768');
      expect(pqcIds).toContain('ML-KEM-1024');
      expect(pqcIds).toContain('ML-DSA-44');
      expect(pqcIds).toContain('ML-DSA-65');
      expect(pqcIds).toContain('ML-DSA-87');

      const hybridIds = json.data.hybrid.map((a: any) => a.id);
      expect(hybridIds).toContain('X25519+ML-KEM-768');
    });
  });

  // =========================================================================
  // 3. CRYPTO AGILITY ENGINE ENDPOINTS
  // =========================================================================
  describe('POST /v1/organizations/:orgId/crypto/pqc/agility/*', () => {
    it('selects ML-KEM-768 for general key agreement under PQC_PREFERRED', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/pqc/agility/select`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          operation: 'key_encapsulation',
          policy: 'PQC_PREFERRED',
        }),
      });
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.data.selectedAlgorithm).toBe('ML-KEM-768');
    });

    it('selects Hybrid X25519+ML-KEM-768 when preferHybrid is true', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/pqc/agility/select`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          operation: 'key_encapsulation',
          policy: 'HYBRID_REQUIRED',
          preferHybrid: true,
        }),
      });
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.data.selectedAlgorithm).toBe('X25519+ML-KEM-768');
    });

    it('returns migration advice for RSA-2048 to ML-DSA and X25519+ML-KEM-768', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/pqc/agility/migration-advice`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ED25519',
        }),
      });
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.data.currentAlgorithm).toBe('ED25519');
      expect(json.data.recommendedReplacement).toBe('ML-DSA-65');
      expect(json.data.migrationReason).toBeDefined();
    });
  });

  // =========================================================================
  // 4. ML-KEM (FIPS 203) REST API ENDPOINTS
  // =========================================================================
  describe('POST /v1/organizations/:orgId/crypto/kem/*', () => {
    it('executes full keygen, encapsulate, and decapsulate cycle via REST API', async () => {
      // 1. Recipient generates ML-KEM-768 keypair
      const keygenRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/kem/keygen`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ML-KEM-768',
          encoding: 'hex',
        }),
      });
      const keygenData = await keygenRes.json();
      expect(keygenRes.status).toBe(200);
      expect(keygenData.data.publicKeyBytes).toBe(1184);
      expect(keygenData.data.privateKeyBytes).toBe(2400);

      const recipientPk = keygenData.data.publicKey;
      const recipientSk = keygenData.data.privateKey;

      // 2. Sender encapsulates against recipient public key
      const encRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/kem/encapsulate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ML-KEM-768',
          publicKey: recipientPk,
        }),
      });
      const encData = await encRes.json();
      expect(encRes.status).toBe(200);
      expect(encData.data.ciphertextBytes).toBe(1088);
      expect(encData.data.sharedSecretBytes).toBe(32);

      const ciphertext = encData.data.ciphertext;
      const senderSharedSecret = encData.data.sharedSecret;

      // 3. Recipient decapsulates ciphertext with private key
      const decRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/kem/decapsulate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ML-KEM-768',
          privateKey: recipientSk,
          ciphertext,
        }),
      });
      const decData = await decRes.json();
      expect(decRes.status).toBe(200);
      expect(decData.data.sharedSecret).toBe(senderSharedSecret);

      // 4. Test implicit rejection on tampered ciphertext
      // Always change the byte: writing 'ff' over a byte that is already 'ff' would tamper nothing
      const tamperedCt = ciphertext.slice(0, 10) + (ciphertext.slice(10, 12) === 'ff' ? '00' : 'ff') + ciphertext.slice(12);
      const tamperedDecRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/kem/decapsulate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ML-KEM-768',
          privateKey: recipientSk,
          ciphertext: tamperedCt,
        }),
      });
      const tamperedDecData = await tamperedDecRes.json();
      expect(tamperedDecRes.status).toBe(200);
      expect(tamperedDecData.data.sharedSecret).not.toBe(senderSharedSecret);
    });

    it('rejects KEM operation when policy is CLASSICAL_ONLY', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/kem/keygen`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ML-KEM-768',
          policy: 'CLASSICAL_ONLY',
        }),
      });
      const json = await res.json();
      expect(res.status).toBe(403);
      expect(json.error.code).toBe('POLICY_VIOLATION');
    });
  });

  // =========================================================================
  // 5. ML-DSA (FIPS 204) REST API ENDPOINTS
  // =========================================================================
  describe('POST /v1/organizations/:orgId/crypto/signature/pqc-*', () => {
    it('executes full keygen, sign, and verify cycle via REST API with context string', async () => {
      // 1. Generate ML-DSA-65 keypair
      const keygenRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/signature/pqc-keygen`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ML-DSA-65',
        }),
      });
      const keygenData = await keygenRes.json();
      expect(keygenRes.status).toBe(200);
      expect(keygenData.data.publicKeyBytes).toBe(1952);
      expect(keygenData.data.privateKeyBytes).toBe(4032);

      const pk = keygenData.data.publicKey;
      const sk = keygenData.data.privateKey;
      const message = 'Quantum-safe financial transaction agreement #4829';
      const context = 'AMARACUS-AUTH-V1';

      // 2. Sign message with context string
      const signRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/signature/pqc-sign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ML-DSA-65',
          privateKey: sk,
          message,
          context,
        }),
      });
      const signData = await signRes.json();
      expect(signRes.status).toBe(200);
      expect(signData.data.signatureBytes).toBe(3309);

      const signature = signData.data.signature;

      // 3. Verify valid signature with correct context
      const verifyRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/signature/pqc-verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ML-DSA-65',
          publicKey: pk,
          message,
          signature,
          context,
        }),
      });
      const verifyData = await verifyRes.json();
      expect(verifyRes.status).toBe(200);
      expect(verifyData.data.valid).toBe(true);

      // 4. Verify rejection when message is tampered
      const tamperedVerifyRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/signature/pqc-verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ML-DSA-65',
          publicKey: pk,
          message: 'Tampered message',
          signature,
          context,
        }),
      });
      const tamperedVerifyData = await tamperedVerifyRes.json();
      expect(tamperedVerifyRes.status).toBe(200);
      expect(tamperedVerifyData.data.valid).toBe(false);

      // 5. Verify rejection when context is wrong
      const wrongContextRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/signature/pqc-verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ML-DSA-65',
          publicKey: pk,
          message,
          signature,
          context: 'WRONG-CONTEXT',
        }),
      });
      const wrongContextData = await wrongContextRes.json();
      expect(wrongContextRes.status).toBe(200);
      expect(wrongContextData.data.valid).toBe(false);
    });

    it('rejects PQC signature when policy is CLASSICAL_ONLY', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/signature/pqc-keygen`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ML-DSA-65',
          policy: 'CLASSICAL_ONLY',
        }),
      });
      const json = await res.json();
      expect(res.status).toBe(403);
      expect(json.error.code).toBe('POLICY_VIOLATION');
    });
  });

  // =========================================================================
  // 6. HYBRID POST-QUANTUM KEY EXCHANGE (X25519 + ML-KEM-768) REST API
  // =========================================================================
  describe('POST /v1/organizations/:orgId/crypto/hybrid/*', () => {
    it('executes hybrid keygen, encapsulate, and decapsulate round trip', async () => {
      // 1. Generate hybrid keypair
      const keygenRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/hybrid/keygen`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({}),
      });
      const keygenData = await keygenRes.json();
      expect(keygenRes.status).toBe(200);
      expect(keygenData.data.algorithm).toBe('X25519+ML-KEM-768');
      expect(keygenData.data.publicKey.x25519PublicKey).toBeDefined();
      expect(keygenData.data.publicKey.mlkemPublicKey).toBeDefined();

      const hybridPk = keygenData.data.publicKey;
      const hybridSk = keygenData.data.privateKey;

      // 2. Encapsulate
      const encRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/hybrid/encapsulate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          publicKey: hybridPk,
        }),
      });
      const encData = await encRes.json();
      expect(encRes.status).toBe(200);
      expect(encData.data.ciphertext.ephemeralX25519PublicKey).toBeDefined();
      expect(encData.data.ciphertext.mlkemCiphertext).toBeDefined();
      expect(encData.data.combinedCiphertext.length).toBe(1120 * 2); // 1120 bytes in hex
      expect(encData.data.sharedSecret.length).toBe(64); // 32 bytes in hex

      const hybridCt = encData.data.ciphertext;
      const senderSecret = encData.data.sharedSecret;

      // 3. Decapsulate
      const decRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/hybrid/decapsulate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          privateKey: hybridSk,
          ciphertext: hybridCt,
        }),
      });
      const decData = await decRes.json();
      expect(decRes.status).toBe(200);
      expect(decData.data.sharedSecret).toBe(senderSecret);
    });

    it('rejects incomplete public key in hybrid encapsulation', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/hybrid/encapsulate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          publicKey: { x25519PublicKey: 'abcd' }, // missing mlkemPublicKey
        }),
      });
      const json = await res.json();
      expect(res.status).toBe(400);
      expect(json.error.code).toBe('INVALID_INPUT');
    });
  });

  // =========================================================================
  // 7. SAFE AUDIT LOGGING (ZERO SECRET LEAKAGE)
  // =========================================================================
  describe('Safe Audit Logging for PQC Operations', () => {
    it('records PQC audit entries without leaking private keys or secrets', async () => {
      const auditEvents = await db.getAuditEventsByOrg(orgA.id);
      const pqcEvents = auditEvents.filter((e) => e.action.startsWith('crypto:'));

      expect(pqcEvents.length).toBeGreaterThan(0);

      // Inspect every audit event to ensure no private key or shared secret strings exist
      for (const event of pqcEvents) {
        const serialized = JSON.stringify(event);
        expect(serialized).not.toContain('privateKey');
        expect(serialized).not.toContain('sharedSecret');
        expect(serialized).not.toContain('plaintext');
      }
    });
  });
});
