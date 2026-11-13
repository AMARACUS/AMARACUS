import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import {
  cryptoEngine,
  registry,
  CryptoPolicyEngine,
  LocalDevKeyProvider,
  AzureKeyVaultKeyProvider,
  AzureManagedHsmProvider,
  CustomerAzureKeyVaultProvider,
  CryptoEngineError,
} from '@amaracus/crypto-core';

describe('Phase 6.2 — Formal PQC Acceptance Matrix & Smoke Verification', () => {
  let server: http.Server;
  let baseUrl: string;

  let userA: any;
  let sessionA: any;
  let orgA: any;
  let projA: any;
  let envA: any;

  let userB: any;
  let sessionB: any;
  let orgB: any;
  let projB: any;
  let envB: any;

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
      email: `pqc_acc_a_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant A Acceptance Lead',
    });
    orgA = await db.createOrganization({
      name: 'Tenant A Quantum Safe Corp',
      slug: `tenant-a-acc-${Date.now()}`,
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
    projA = await db.createProject({
      organizationId: orgA.id,
      name: 'PQC Gateway Project',
      slug: 'pqc-gw-proj',
    });
    envA = await db.createEnvironment({
      projectId: projA.id,
      name: 'Production',
      slug: 'production',
      type: 'production',
    });

    // Set up Tenant B
    userB = await db.createUser({
      email: `pqc_acc_b_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant B Classical Auditor',
    });
    orgB = await db.createOrganization({
      name: 'Tenant B Classical Ltd',
      slug: `tenant-b-acc-${Date.now()}`,
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
    projB = await db.createProject({
      organizationId: orgB.id,
      name: 'Legacy Project',
      slug: 'legacy-proj',
    });
    envB = await db.createEnvironment({
      projectId: projB.id,
      name: 'Production',
      slug: 'production',
      type: 'production',
    });
  }, 60000);

  afterAll((done) => {
    server.close(done);
  });

  // =========================================================================
  // SECTION 2: ALGORITHM SUPPORT MATRIX
  // =========================================================================
  describe('Algorithm Support Verification', () => {
    const algorithms = [
      { id: 'ML-KEM-512', category: 'PQC_KEM', fips: 'FIPS-203', level: 1 },
      { id: 'ML-KEM-768', category: 'PQC_KEM', fips: 'FIPS-203', level: 3 },
      { id: 'ML-KEM-1024', category: 'PQC_KEM', fips: 'FIPS-203', level: 5 },
      { id: 'ML-DSA-44', category: 'PQC_SIG', fips: 'FIPS-204', level: 2 },
      { id: 'ML-DSA-65', category: 'PQC_SIG', fips: 'FIPS-204', level: 3 },
      { id: 'ML-DSA-87', category: 'PQC_SIG', fips: 'FIPS-204', level: 5 },
      { id: 'X25519+ML-KEM-768', category: 'HYBRID_KEM', fips: 'HYBRID-NONSTANDARD', level: 3 },
    ];

    algorithms.forEach((alg) => {
      it(`verifies ${alg.id} is registered with correct metadata in central registry`, () => {
        const meta = registry.get(alg.id as any);
        expect(meta).toBeDefined();
        expect(meta.category).toBe(alg.category);
        expect(meta.quantumResistant).toBe(true);
        expect(meta.fipsStatus).toBe(alg.fips);
        expect(meta.securityLevel).toBe(alg.level);
        expect(meta.status).toBe('SUPPORTED');
      });
    });

    it('rejects unsupported algorithm requests truthfully', () => {
      expect(() => registry.get('FRODO-KEM-640' as any)).toThrow('not supported');
      expect(() =>
        CryptoPolicyEngine.validateOperation('DEFAULT_SECURE', 'FRODO-KEM-640' as any, 'kem_encapsulate')
      ).toThrow();
    });
  });

  // =========================================================================
  // SECTION 3: ML-KEM ACCEPTANCE CRITERIA (KEM-001 TO KEM-008)
  // =========================================================================
  describe('ML-KEM Acceptance Criteria (KEM-001 - KEM-008)', () => {
    it('KEM-001: key generation produces valid keypair with exact NIST parameter lengths', async () => {
      const kp512 = await cryptoEngine.kemKeygen({ algorithm: 'ML-KEM-512' });
      expect(kp512.publicKeyBytes).toBe(800);
      expect(kp512.privateKeyBytes).toBe(1632);

      const kp768 = await cryptoEngine.kemKeygen({ algorithm: 'ML-KEM-768' });
      expect(kp768.publicKeyBytes).toBe(1184);
      expect(kp768.privateKeyBytes).toBe(2400);

      const kp1024 = await cryptoEngine.kemKeygen({ algorithm: 'ML-KEM-1024' });
      expect(kp1024.publicKeyBytes).toBe(1568);
      expect(kp1024.privateKeyBytes).toBe(3168);
    });

    it('KEM-002: encapsulation produces valid ciphertext and 256-bit shared secret', async () => {
      const kp = await cryptoEngine.kemKeygen({ algorithm: 'ML-KEM-768' });
      const enc = await cryptoEngine.kemEncapsulate({
        algorithm: 'ML-KEM-768',
        publicKey: kp.publicKey,
      });

      expect(enc.ciphertextBytes).toBe(1088);
      expect(enc.sharedSecretBytes).toBe(32); // 256 bits
      expect(enc.sharedSecret.length).toBe(64); // hex
    });

    it('KEM-003: decapsulation with correct private key reproduces exact same shared secret', async () => {
      const kp = await cryptoEngine.kemKeygen({ algorithm: 'ML-KEM-768' });
      const enc = await cryptoEngine.kemEncapsulate({
        algorithm: 'ML-KEM-768',
        publicKey: kp.publicKey,
      });
      const dec = await cryptoEngine.kemDecapsulate({
        algorithm: 'ML-KEM-768',
        privateKey: kp.privateKey,
        ciphertext: enc.ciphertext,
      });

      expect(dec.sharedSecret).toBe(enc.sharedSecret);
      expect(dec.sharedSecretBytes).toBe(32);
    });

    it('KEM-004: modified ciphertext causes decapsulation failure / implicit rejection (Fujisaki-Okamoto)', async () => {
      const kp = await cryptoEngine.kemKeygen({ algorithm: 'ML-KEM-768' });
      const enc = await cryptoEngine.kemEncapsulate({
        algorithm: 'ML-KEM-768',
        publicKey: kp.publicKey,
      });

      const ctBuf = Buffer.from(enc.ciphertext, 'hex');
      ctBuf[0] ^= 0xff; // Flip bits

      const decTampered = await cryptoEngine.kemDecapsulate({
        algorithm: 'ML-KEM-768',
        privateKey: kp.privateKey,
        ciphertext: ctBuf.toString('hex'),
      });

      // Constant-time implicit rejection: does not crash, but produces pseudo-random mismatched secret
      expect(decTampered.sharedSecret).not.toBe(enc.sharedSecret);
      expect(decTampered.sharedSecret.length).toBe(64);
    });

    it('KEM-005: wrong private key does not reproduce the expected shared secret', async () => {
      const kpA = await cryptoEngine.kemKeygen({ algorithm: 'ML-KEM-768' });
      const kpB = await cryptoEngine.kemKeygen({ algorithm: 'ML-KEM-768' });

      // Encapsulate to A
      const enc = await cryptoEngine.kemEncapsulate({
        algorithm: 'ML-KEM-768',
        publicKey: kpA.publicKey,
      });

      // Decapsulate with B's private key
      const decWrong = await cryptoEngine.kemDecapsulate({
        algorithm: 'ML-KEM-768',
        privateKey: kpB.privateKey,
        ciphertext: enc.ciphertext,
      });

      expect(decWrong.sharedSecret).not.toBe(enc.sharedSecret);
    });

    it('KEM-006: malformed ciphertext is rejected with INVALID_INPUT', async () => {
      const kp = await cryptoEngine.kemKeygen({ algorithm: 'ML-KEM-768' });
      const truncatedCt = '0102030405';

      await expect(
        cryptoEngine.kemDecapsulate({
          algorithm: 'ML-KEM-768',
          privateKey: kp.privateKey,
          ciphertext: truncatedCt,
        })
      ).rejects.toThrow('must be exactly 1088 bytes');
    });

    it('KEM-007: malformed public/private keys are rejected with INVALID_KEY', async () => {
      const badPk = 'deadbeef';
      await expect(
        cryptoEngine.kemEncapsulate({
          algorithm: 'ML-KEM-768',
          publicKey: badPk,
        })
      ).rejects.toThrow('must be exactly 1184 bytes');

      const badSk = 'deadbeef';
      await expect(
        cryptoEngine.kemDecapsulate({
          algorithm: 'ML-KEM-768',
          privateKey: badSk,
          ciphertext: Buffer.alloc(1088).toString('hex'),
        })
      ).rejects.toThrow('must be exactly 2400 bytes');
    });

    it('KEM-008: no secret material is written to audit logs or API error responses', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/kem/keygen`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({ algorithm: 'ML-KEM-768' }),
      });
      const json = await res.json();
      expect(res.status).toBe(200);

      // Verify audit event
      const auditEvents = await db.getAuditEventsByOrg(orgA.id);
      const kemEvent = auditEvents.find((e) => e.action === 'crypto:kem_keygen');
      expect(kemEvent).toBeDefined();

      const serializedAudit = JSON.stringify(kemEvent);
      expect(serializedAudit).not.toContain(json.data.privateKey);
      expect(serializedAudit).not.toContain('privateKey');
    });
  });

  // =========================================================================
  // SECTION 4: ML-DSA ACCEPTANCE CRITERIA (DSA-001 TO DSA-008)
  // =========================================================================
  describe('ML-DSA Acceptance Criteria (DSA-001 - DSA-008)', () => {
    it('DSA-001: key generation produces valid keypair with exact NIST parameter lengths', async () => {
      const kp44 = await cryptoEngine.pqcKeygen({ algorithm: 'ML-DSA-44' });
      expect(kp44.publicKeyBytes).toBe(1312);
      expect(kp44.privateKeyBytes).toBe(2560);

      const kp65 = await cryptoEngine.pqcKeygen({ algorithm: 'ML-DSA-65' });
      expect(kp65.publicKeyBytes).toBe(1952);
      expect(kp65.privateKeyBytes).toBe(4032);

      const kp87 = await cryptoEngine.pqcKeygen({ algorithm: 'ML-DSA-87' });
      expect(kp87.publicKeyBytes).toBe(2592);
      expect(kp87.privateKeyBytes).toBe(4896);
    });

    it('DSA-002: a valid message can be signed', async () => {
      const kp = await cryptoEngine.pqcKeygen({ algorithm: 'ML-DSA-65' });
      const signRes = await cryptoEngine.pqcSign({
        algorithm: 'ML-DSA-65',
        privateKey: kp.privateKey,
        message: 'Formal Acceptance Document 2026',
      });

      expect(signRes.signatureBytes).toBe(3309);
      expect(signRes.signature.length).toBe(3309 * 2);
    });

    it('DSA-003: a valid signature verifies with the corresponding public key', async () => {
      const kp = await cryptoEngine.pqcKeygen({ algorithm: 'ML-DSA-65' });
      const message = 'Standard PQC Verification Test';
      const signRes = await cryptoEngine.pqcSign({
        algorithm: 'ML-DSA-65',
        privateKey: kp.privateKey,
        message,
      });
      const verifyRes = await cryptoEngine.pqcVerify({
        algorithm: 'ML-DSA-65',
        publicKey: kp.publicKey,
        message,
        signature: signRes.signature,
      });

      expect(verifyRes.valid).toBe(true);
    });

    it('DSA-004: modified message fails verification', async () => {
      const kp = await cryptoEngine.pqcKeygen({ algorithm: 'ML-DSA-65' });
      const signRes = await cryptoEngine.pqcSign({
        algorithm: 'ML-DSA-65',
        privateKey: kp.privateKey,
        message: 'Original Untampered Text',
      });
      const verifyRes = await cryptoEngine.pqcVerify({
        algorithm: 'ML-DSA-65',
        publicKey: kp.publicKey,
        message: 'Modified Tampered Text',
        signature: signRes.signature,
      });

      expect(verifyRes.valid).toBe(false);
    });

    it('DSA-005: modified signature fails verification', async () => {
      const kp = await cryptoEngine.pqcKeygen({ algorithm: 'ML-DSA-65' });
      const message = 'Signature Tamper Test';
      const signRes = await cryptoEngine.pqcSign({
        algorithm: 'ML-DSA-65',
        privateKey: kp.privateKey,
        message,
      });

      const sigBuf = Buffer.from(signRes.signature, 'hex');
      sigBuf[20] ^= 0xbb;

      const verifyRes = await cryptoEngine.pqcVerify({
        algorithm: 'ML-DSA-65',
        publicKey: kp.publicKey,
        message,
        signature: sigBuf.toString('hex'),
      });

      expect(verifyRes.valid).toBe(false);
    });

    it('DSA-006: wrong public key fails verification', async () => {
      const kpA = await cryptoEngine.pqcKeygen({ algorithm: 'ML-DSA-65' });
      const kpB = await cryptoEngine.pqcKeygen({ algorithm: 'ML-DSA-65' });
      const message = 'Public Key Confusion Test';

      const signRes = await cryptoEngine.pqcSign({
        algorithm: 'ML-DSA-65',
        privateKey: kpA.privateKey,
        message,
      });

      // Verify with keypair B's public key
      const verifyRes = await cryptoEngine.pqcVerify({
        algorithm: 'ML-DSA-65',
        publicKey: kpB.publicKey,
        message,
        signature: signRes.signature,
      });

      expect(verifyRes.valid).toBe(false);
    });

    it('DSA-007: malformed signature is rejected safely', async () => {
      const kp = await cryptoEngine.pqcKeygen({ algorithm: 'ML-DSA-65' });
      const truncatedSig = 'deadbeefcafe';

      const verifyRes = await cryptoEngine.pqcVerify({
        algorithm: 'ML-DSA-65',
        publicKey: kp.publicKey,
        message: 'Test Message',
        signature: truncatedSig,
      });

      // Safe failure without unhandled error
      expect(verifyRes.valid).toBe(false);
    });

    it('DSA-008: private signing material is never exposed through normal API responses', async () => {
      const kp = await cryptoEngine.pqcKeygen({ algorithm: 'ML-DSA-65' });
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/signature/pqc-sign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ML-DSA-65',
          privateKey: kp.privateKey,
          message: 'Zero Exposure Test',
        }),
      });

      const json = await res.json();
      expect(res.status).toBe(200);
      expect(json.data.signature).toBeDefined();
      expect(json.data).not.toHaveProperty('privateKey');
      expect(JSON.stringify(json.data)).not.toContain(kp.privateKey);
    });
  });

  // =========================================================================
  // SECTION 6: PROVIDER SUPPORT & TRUTHFUL REJECTION
  // =========================================================================
  describe('Provider Support & Truthful Capabilities', () => {
    it('LocalDevKeyProvider natively supports PQC and wraps keys with Master KEK', async () => {
      const provider = new LocalDevKeyProvider();
      expect(provider.capabilities.supportsPqc).toBe(true);

      const created = await provider.createKey({
        name: 'local-pqc-dsa',
        algorithm: 'ML-DSA-65',
        purpose: 'SIGNING',
        organizationId: orgA.id,
        projectId: projA.id,
        environmentId: envA.id,
      });

      expect(created.providerKeyId).toMatch(/^local-/);
      expect(created.encryptedKeyMaterial).toBeDefined();
      const parsedBlob = JSON.parse(created.encryptedKeyMaterial!);
      expect(parsedBlob.alg).toBe('aes-256-gcm');
    });

    it('Azure Key Vault truthfully reports supportsPqc: false and rejects PQC operations', async () => {
      const provider = new AzureKeyVaultKeyProvider();
      expect(provider.capabilities.supportsPqc).toBe(false);

      await expect(
        provider.createKey({
          name: 'azure-pqc-attempt',
          algorithm: 'ML-KEM-768',
          purpose: 'KEY_AGREEMENT',
          organizationId: orgA.id,
          projectId: projA.id,
          environmentId: envA.id,
        })
      ).rejects.toThrow(
        new CryptoEngineError(
          'OPERATION_NOT_SUPPORTED',
          "Azure Key Vault does not support Post-Quantum Cryptography algorithm 'ML-KEM-768'. Azure Key Vault currently only supports classical RSA and EC algorithms."
        )
      );
    });

    it('Azure Managed HSM truthfully reports supportsPqc: false and rejects PQC operations', async () => {
      const provider = new AzureManagedHsmProvider();
      expect(provider.capabilities.supportsPqc).toBe(false);

      await expect(
        provider.createKey({
          name: 'hsm-pqc-attempt',
          algorithm: 'ML-DSA-65',
          purpose: 'SIGNING',
          organizationId: orgA.id,
          projectId: projA.id,
          environmentId: envA.id,
        })
      ).rejects.toThrow(
        new CryptoEngineError(
          'OPERATION_NOT_SUPPORTED',
          "Azure Managed HSM does not support Post-Quantum Cryptography algorithm 'ML-DSA-65'. Azure Managed HSM currently only supports classical oct-HSM (AES), RSA-HSM, and EC-HSM keys."
        )
      );
    });

    it('CustomerAzureKeyVaultProvider truthfully reports pqc: false in testConnection', async () => {
      // Dummy service principal and a vault that denies access: no network, no platform identity.
      const deniedVault: any = {
        keyClient: () => ({ listPropertiesOfKeys: () => ({ [Symbol.asyncIterator]: () => ({ next: () => Promise.reject(Object.assign(new Error('denied'), { statusCode: 403 })) }) }) }),
        cryptoClient: () => ({}),
      };
      const provider = new CustomerAzureKeyVaultProvider(
        {
          name: 'pqc-capability-check',
          ownershipType: 'CUSTOMER_MANAGED',
          providerType: 'AZURE_KEY_VAULT',
          vaultUrl: 'https://test-vault.vault.azure.net/',
          authType: 'SERVICE_PRINCIPAL',
          tenantId: '00000000-0000-0000-0000-000000000000',
          clientId: '00000000-0000-0000-0000-000000000000',
          clientSecret: 'dummy',
        },
        deniedVault
      );
      const res = await provider.testConnection();
      expect(res.pqc).toBe(false);
      expect(res.capabilities.pqc).toBe(false);
      expect(res.capabilities.unavailableReasons?.pqc).toContain('Post-Quantum Cryptography');
    });
  });

  // =========================================================================
  // SECTION 7: KEY MANAGEMENT INTEGRATION & LIFECYCLE (KM-001 TO KM-008)
  // =========================================================================
  describe('Key Management Integration & Full Lifecycle State Transitions', () => {
    let pqcManagedKeyId: string;

    it('creates managed PQC key (ML-DSA-65) with stable ID and scoped to tenant', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          name: 'quantum-signing-root-key',
          description: 'Enterprise post-quantum root signing key',
          projectId: projA.id,
          environmentId: envA.id,
          algorithm: 'ML-DSA-65',
          purpose: 'SIGNING',
          provider: 'LOCAL_DEV',
        }),
      });

      expect(res.status).toBe(201);
      const json = await res.json();
      expect(json.data.id).toBeDefined();
      expect(json.data.algorithm).toBe('ML-DSA-65');
      expect(json.data.purpose).toBe('SIGNING');
      expect(json.data.status).toBe('ACTIVE');
      expect(json.data.provider).toBe('LOCAL_DEV');

      pqcManagedKeyId = json.data.id;

      // Ensure zero private key exposure in response
      expect(json.data).not.toHaveProperty('encryptedKeyMaterial');
      expect(json.data).not.toHaveProperty('privateKey');
    });

    it('ACTIVE state: permitted to sign messages with PQC key', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${pqcManagedKeyId}/sign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          data: 'Quantum Transaction Payload v1',
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.signature).toBeDefined();
      expect(json.data.signature.length).toBe(3309 * 2); // 3309 bytes in hex
    });

    it('transitions to DISABLED state: operations are rejected with KEY_DISABLED', async () => {
      // Disable key
      const postRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${pqcManagedKeyId}/disable`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
      });
      expect(postRes.status).toBe(200);
      const postJson = await postRes.json();
      expect(postJson.data.status).toBe('DISABLED');

      // Attempt to sign with disabled key -> 400 KEY_DISABLED
      const signRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${pqcManagedKeyId}/sign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({ data: 'Payload' }),
      });

      expect(signRes.status).toBe(400);
      const signJson = await signRes.json();
      expect(signJson.error.code).toBe('KEY_DISABLED');
    });

    it('transitions back to ACTIVE state: operations are permitted again', async () => {
      // Re-enable key
      const postRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${pqcManagedKeyId}/enable`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
      });
      expect(postRes.status).toBe(200);

      // Sign again -> succeeds
      const signRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${pqcManagedKeyId}/sign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({ data: 'Payload After Re-enable' }),
      });
      expect(signRes.status).toBe(200);
    });

    it('transitions to REVOKED state: operations are permanently rejected', async () => {
      // Revoke key
      const postRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${pqcManagedKeyId}/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({ reason: 'Scheduled post-quantum root key retirement' }),
      });
      expect(postRes.status).toBe(200);
      const postJson = await postRes.json();
      expect(postJson.data.status).toBe('REVOKED');

      // Attempt to sign with revoked key -> 400 KEY_REVOKED
      const signRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${pqcManagedKeyId}/sign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({ data: 'Payload After Revoke' }),
      });

      expect(signRes.status).toBe(400);
      const signJson = await signRes.json();
      expect(signJson.error.code).toBe('KEY_REVOKED');
    });
  });

  // =========================================================================
  // SECTION 9: HYBRID POST-QUANTUM CRYPTOGRAPHY ACCEPTANCE
  // =========================================================================
  describe('Hybrid Cryptography Dual Combiner Acceptance', () => {
    it('verifies exact composite wire format and dual combiner properties', async () => {
      const kp = await cryptoEngine.hybridKeygen();

      // Combined public key components
      expect(kp.publicKey.x25519PublicKey.length).toBe(64); // 32 bytes
      expect(kp.publicKey.mlkemPublicKey.length).toBe(2368); // 1184 bytes

      // Combined private key components
      expect(kp.privateKey.x25519PrivateKey.length).toBe(64); // 32 bytes
      expect(kp.privateKey.mlkemPrivateKey.length).toBe(4800); // 2400 bytes

      const enc = await cryptoEngine.hybridEncapsulate({
        publicKey: kp.publicKey,
      });

      // Ciphertext format: 32 bytes ephemeral X25519 pk + 1088 bytes ML-KEM-768 ct = 1120 bytes
      expect(enc.combinedCiphertext.length).toBe(1120 * 2);
      expect(enc.sharedSecret.length).toBe(64); // 32 bytes

      const dec = await cryptoEngine.hybridDecapsulate({
        privateKey: kp.privateKey,
        ciphertext: enc.combinedCiphertext,
      });

      expect(dec.sharedSecret).toBe(enc.sharedSecret);
    });
  });

  // =========================================================================
  // SECTION 11: TENANT ISOLATION
  // =========================================================================
  describe('Tenant Isolation & IDOR Defense for PQC Keys', () => {
    let keyA: any;

    beforeAll(async () => {
      // Create PQC Key in Org A
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          name: 'isolated-pqc-key-a',
          projectId: projA.id,
          environmentId: envA.id,
          algorithm: 'ML-DSA-65',
          purpose: 'SIGNING',
          provider: 'LOCAL_DEV',
        }),
      });
      const json = await res.json();
      keyA = json.data;
    });

    it('prevents User B from getting Key A (404 in Org B context, 403 cross-org)', async () => {
      const res404 = await fetch(`${baseUrl}/v1/organizations/${orgB.id}/keys/${keyA.id}`, {
        headers: { Authorization: `Bearer ${sessionB.sessionToken}` },
      });
      expect(res404.status).toBe(404);

      const res403 = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${keyA.id}`, {
        headers: { Authorization: `Bearer ${sessionB.sessionToken}` },
      });
      expect(res403.status).toBe(403);
    });

    it('prevents User B from signing with Key A', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${keyA.id}/sign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionB.sessionToken}`,
        },
        body: JSON.stringify({ data: 'Malicious Signature Attempt' }),
      });
      expect(res.status).toBe(403);
    });

    it('prevents User B from updating or disabling Key A', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${keyA.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionB.sessionToken}`,
        },
        body: JSON.stringify({ status: 'DISABLED' }),
      });
      expect(res.status).toBe(403);
    });
  });

  // =========================================================================
  // SECTION 13 & 14: SECRET LEAKAGE AUDIT & PERSISTENCE
  // =========================================================================
  describe('Secret Leakage Audit & Persistence', () => {
    it('ensures no private keys or shared secrets exist in audit events or database records', async () => {
      const auditEvents = await db.getAuditEventsByOrg(orgA.id);
      expect(auditEvents.length).toBeGreaterThan(0);

      for (const event of auditEvents) {
        const str = JSON.stringify(event);
        expect(str).not.toContain('privateKey');
        expect(str).not.toContain('sharedSecret');
        expect(str).not.toContain('plaintext');
        expect(str).not.toContain('rawKey');
      }
    });

    it('verifies PQC key metadata persists and is accessible across queries', async () => {
      const keys = await db.listKeys({ organizationId: orgA.id });
      const found = keys.find((k) => k.algorithm === 'ML-DSA-65');
      expect(found).toBeDefined();
      expect(found?.algorithm).toBe('ML-DSA-65');
      expect(found?.status).toBeDefined();
    });
  });
});
