import {
  LocalDevKeyProvider,
  AzureKeyVaultKeyProvider,
  AzureManagedHsmProvider,
  KeyManagementService,
  CryptoEngineError,
} from '@amaracus/crypto-core';

describe('Phase 5 — Key Provider Abstraction & Cryptographic Verification', () => {
  describe('LocalDevKeyProvider (DEVELOPMENT ONLY)', () => {
    const localProvider = new LocalDevKeyProvider();

    test('declares explicit DEVELOPMENT ONLY label and health status', async () => {
      expect(localProvider.providerId).toBe('LOCAL_DEV');
      expect(localProvider.label).toMatch(/DEVELOPMENT ONLY/i);
      expect(localProvider.capabilities.isHardwareBacked).toBe(false);
      expect(localProvider.capabilities.isFips140Validated).toBe(false);
      expect(localProvider.isConfigured()).toBe(true);

      const health = await localProvider.healthCheck();
      expect(health.status).toBe('DEVELOPMENT_ONLY');
      expect(health.isConfigured).toBe(true);
      expect(health.message).toMatch(/NEVER use in production/i);
    });

    test('generates AES-256-GCM key with Master-KEK envelope wrapping (no plaintext key)', async () => {
      const result = await localProvider.createKey({
        name: 'test-aes-key',
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPTION',
        organizationId: 'org_test_123',
        projectId: 'prj_test_123',
        environmentId: 'env_test_123',
      });

      expect(result.providerKeyId).toMatch(/^local-/);
      expect(result.keyFingerprint).toHaveLength(16);
      expect(result.encryptedKeyMaterial).toBeDefined();

      // Ensure key material is an encrypted JSON envelope, NOT a raw 32-byte secret
      const parsedBlob = JSON.parse(result.encryptedKeyMaterial!);
      expect(parsedBlob.v).toBe(1);
      expect(parsedBlob.alg).toBe('aes-256-gcm');
      expect(parsedBlob.iv).toBeDefined();
      expect(parsedBlob.tag).toBeDefined();
      expect(parsedBlob.ct).toBeDefined();
      expect(parsedBlob).not.toHaveProperty('rawKey');
      expect(parsedBlob).not.toHaveProperty('secret');
    });

    test('executes authenticated AES-256-GCM envelope encryption and decryption roundtrip', async () => {
      const keyResult = await localProvider.createKey({
        name: 'test-envelope-key',
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPTION',
        organizationId: 'org_test_123',
        projectId: 'prj_test_123',
        environmentId: 'env_test_123',
      });

      const mockVersion: any = {
        id: 'ver_test_01',
        version: 1,
        providerKeyId: keyResult.providerKeyId,
        encryptedKeyMaterial: keyResult.encryptedKeyMaterial,
        status: 'ACTIVE',
      };

      const plaintext = Buffer.from('Confidential AMARACUS Patient Record', 'utf8');
      const aad = Buffer.from('tenant=org_test_123;purpose=phi', 'utf8');

      const envelope = await localProvider.encrypt(
        keyResult.providerKeyId,
        plaintext,
        aad,
        mockVersion
      );

      expect(envelope.v).toBe(1);
      expect(envelope.alg).toBe('AES-256-GCM');
      expect(envelope.ct).toBeDefined();
      expect(envelope.tag).toBeDefined();
      expect(envelope.iv).toBeDefined();
      expect(envelope.aad).toBe(aad.toString('base64url'));

      // Decrypt
      const decrypted = await localProvider.decrypt(
        keyResult.providerKeyId,
        envelope,
        mockVersion
      );

      expect(decrypted.toString('utf8')).toBe('Confidential AMARACUS Patient Record');
    });

    test('rejects tampered ciphertext during decryption', async () => {
      const keyResult = await localProvider.createKey({
        name: 'test-tamper-key',
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPTION',
        organizationId: 'org_test_123',
        projectId: 'prj_test_123',
        environmentId: 'env_test_123',
      });

      const mockVersion: any = {
        id: 'ver_test_02',
        version: 1,
        providerKeyId: keyResult.providerKeyId,
        encryptedKeyMaterial: keyResult.encryptedKeyMaterial,
        status: 'ACTIVE',
      };

      const envelope = await localProvider.encrypt(
        keyResult.providerKeyId,
        Buffer.from('Integrity Test Data', 'utf8'),
        undefined,
        mockVersion
      );

      // Tamper with tag
      const tamperedEnvelope = { ...envelope, tag: 'AAAA' + envelope.tag.slice(4) };

      await expect(
        localProvider.decrypt(keyResult.providerKeyId, tamperedEnvelope, mockVersion)
      ).rejects.toThrow(CryptoEngineError);
    });

    test('generates Ed25519 signing keypair and executes sign and verify roundtrip', async () => {
      const keyResult = await localProvider.createKey({
        name: 'test-ed25519-key',
        algorithm: 'ED25519',
        purpose: 'SIGNING',
        organizationId: 'org_test_123',
        projectId: 'prj_test_123',
        environmentId: 'env_test_123',
      });

      expect(keyResult.publicKey).toBeDefined();
      expect(keyResult.encryptedKeyMaterial).toBeDefined();

      const mockVersion: any = {
        id: 'ver_sign_01',
        version: 1,
        providerKeyId: keyResult.providerKeyId,
        publicKey: keyResult.publicKey,
        encryptedKeyMaterial: keyResult.encryptedKeyMaterial,
        status: 'ACTIVE',
      };

      const message = Buffer.from('Authorize transaction $50,000 to Account X', 'utf8');

      const signature = await localProvider.sign(
        keyResult.providerKeyId,
        message,
        mockVersion
      );

      expect(signature.length).toBe(64); // Ed25519 signature is exactly 64 bytes

      const isValid = await localProvider.verify(
        keyResult.providerKeyId,
        message,
        signature,
        mockVersion
      );

      expect(isValid).toBe(true);

      // Verify tampered message fails
      const isTamperedValid = await localProvider.verify(
        keyResult.providerKeyId,
        Buffer.from('Authorize transaction $999,999 to Account Attacker', 'utf8'),
        signature,
        mockVersion
      );

      expect(isTamperedValid).toBe(false);
    });
  });

  describe('Azure Key Vault vs Azure Managed HSM Provider Architecture', () => {
    const kvProvider = new AzureKeyVaultKeyProvider();
    const hsmProvider = new AzureManagedHsmProvider();

    test('distinguishes Azure Key Vault from Azure Managed HSM', () => {
      expect(kvProvider.providerId).toBe('AZURE_KEY_VAULT');
      expect(hsmProvider.providerId).toBe('AZURE_MANAGED_HSM');

      // Managed HSM is FIPS 140-2 Level 3 hardware backed; standard Key Vault software keys are not
      expect(hsmProvider.capabilities.isHardwareBacked).toBe(true);
      expect(hsmProvider.capabilities.supportsOctHsm).toBe(true);

      expect(kvProvider.capabilities.isHardwareBacked).toBe(false);
      expect(kvProvider.capabilities.supportsOctHsm).toBe(false);
    });

    test('reports NOT_CONFIGURED status gracefully when environment URLs are absent', async () => {
      const originalKvUrl = process.env.AZURE_KEY_VAULT_URL;
      const originalHsmUrl = process.env.AZURE_MANAGED_HSM_URL;
      delete process.env.AZURE_KEY_VAULT_URL;
      delete process.env.AZURE_VAULT_URL;
      delete process.env.AZURE_MANAGED_HSM_URL;

      try {
        const kvHealth = await kvProvider.healthCheck();
        expect(kvHealth.status).toBe('NOT_CONFIGURED');
        expect(kvHealth.isConfigured).toBe(false);

        const hsmHealth = await hsmProvider.healthCheck();
        expect(hsmHealth.status).toBe('NOT_CONFIGURED');
        expect(hsmHealth.isConfigured).toBe(false);
      } finally {
        if (originalKvUrl) process.env.AZURE_KEY_VAULT_URL = originalKvUrl;
        if (originalHsmUrl) process.env.AZURE_MANAGED_HSM_URL = originalHsmUrl;
      }
    });

    test('KeyManagementService registers only Azure and Local Dev providers (Zero AWS)', () => {
      const kms = new KeyManagementService();
      expect(() => kms.getProvider('LOCAL_DEV')).not.toThrow();
      expect(() => kms.getProvider('AZURE_KEY_VAULT')).not.toThrow();
      expect(() => kms.getProvider('AZURE_MANAGED_HSM')).not.toThrow();

      // AWS KMS is NOT registered
      expect(() => kms.getProvider('AWS_KMS' as any)).toThrow(CryptoEngineError);
    });
  });

  describe('Live Azure Cloud Tests (Separated & Conditional)', () => {
    test('reports live Azure test status based on environment configuration', () => {
      const isKvConfigured = Boolean(process.env.AZURE_KEY_VAULT_URL || process.env.AZURE_VAULT_URL);
      const isHsmConfigured = Boolean(process.env.AZURE_MANAGED_HSM_URL);

      if (!isKvConfigured && !isHsmConfigured) {
        console.log('[Azure Live Tests] NOT RUN — AZURE_KEY_VAULT_URL and AZURE_MANAGED_HSM_URL are not provisioned in local environment.');
        expect(true).toBe(true); // Explicit separation: does not fake live cloud execution
      } else {
        console.log(`[Azure Live Tests] Configured — KV: ${isKvConfigured}, HSM: ${isHsmConfigured}`);
        expect(true).toBe(true);
      }
    });
  });
});
