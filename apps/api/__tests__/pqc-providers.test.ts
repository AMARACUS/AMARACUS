import {
  LocalDevKeyProvider,
  AzureKeyVaultKeyProvider,
  AzureManagedHsmProvider,
  CustomerAzureKeyVaultProvider,
  ManagedKeyVersion,
  CryptoEngineError,
} from '@amaracus/crypto-core';

describe('Phase 6 — PQC Key Providers Integration & Truthful Capabilities', () => {
  // =========================================================================
  // 1. LOCAL DEV KEY PROVIDER (PQC SUPPORTED)
  // =========================================================================
  describe('LocalDevKeyProvider PQC Support', () => {
    let provider: LocalDevKeyProvider;

    beforeEach(() => {
      provider = new LocalDevKeyProvider();
    });

    it('declares truthful PQC capability supportsPqc: true', () => {
      expect(provider.capabilities.supportsPqc).toBe(true);
      expect(provider.capabilities.isHardwareBacked).toBe(false);
    });

    it('creates ML-KEM-768 key with Master KEK wrapped private material', async () => {
      const result = await provider.createKey({
        name: 'test-pqc-kem-key',
        algorithm: 'ML-KEM-768',
        purpose: 'KEY_AGREEMENT',
        organizationId: 'org-test-123',
        projectId: 'proj-test-123',
        environmentId: 'env-test-123',
      });

      expect(result.providerKeyId).toMatch(/^local-/);
      expect(result.publicKey).toBeDefined();
      expect(result.publicKey?.length).toBe(1184 * 2); // 1184 bytes in hex
      expect(result.metadata?.type).toBe('PQC_KEM');
      expect(result.metadata?.algorithm).toBe('ML-KEM-768');
      expect(result.metadata?.securityLevel).toBe(3);

      // Verify wrapped key material is AES-256-GCM envelope and not raw private key
      expect(result.encryptedKeyMaterial).toBeDefined();
      const envelope = JSON.parse(result.encryptedKeyMaterial!);
      expect(envelope.alg).toBe('aes-256-gcm');
      expect(envelope.iv).toBeDefined();
      expect(envelope.tag).toBeDefined();
      expect(envelope.ct).toBeDefined();
      // Ensure plaintext private key is not leaked into envelope
      expect(result.encryptedKeyMaterial).not.toContain(result.publicKey);
    });

    it('creates ML-DSA-65 key with Master KEK wrapped private material', async () => {
      const result = await provider.createKey({
        name: 'test-pqc-dsa-key',
        algorithm: 'ML-DSA-65',
        purpose: 'SIGNING',
        organizationId: 'org-test-123',
        projectId: 'proj-test-123',
        environmentId: 'env-test-123',
      });

      expect(result.providerKeyId).toMatch(/^local-/);
      expect(result.publicKey).toBeDefined();
      expect(result.publicKey?.length).toBe(1952 * 2); // 1952 bytes in hex
      expect(result.metadata?.type).toBe('PQC_SIGNING');
      expect(result.metadata?.algorithm).toBe('ML-DSA-65');
      expect(result.metadata?.securityLevel).toBe(3);
    });

    it('creates Hybrid X25519+ML-KEM-768 key', async () => {
      const result = await provider.createKey({
        name: 'test-pqc-hybrid-key',
        algorithm: 'X25519+ML-KEM-768',
        purpose: 'KEY_AGREEMENT',
        organizationId: 'org-test-123',
        projectId: 'proj-test-123',
        environmentId: 'env-test-123',
      });

      expect(result.providerKeyId).toMatch(/^local-/);
      expect(result.publicKey).toBeDefined();
      const pubKeys = JSON.parse(result.publicKey!);
      expect(pubKeys.x25519PublicKey).toBeDefined();
      expect(pubKeys.mlkemPublicKey).toBeDefined();
      expect(result.metadata?.type).toBe('HYBRID_KEM');
      expect(result.metadata?.algorithm).toBe('X25519+ML-KEM-768');
    });

    it('signs and verifies messages using ML-DSA-65 key via provider methods', async () => {
      const created = await provider.createKey({
        name: 'test-sign-key',
        algorithm: 'ML-DSA-65',
        purpose: 'SIGNING',
        organizationId: 'org-test-123',
        projectId: 'proj-test-123',
        environmentId: 'env-test-123',
      });

      const mockVersion: ManagedKeyVersion = {
        id: 'ver-1',
        keyId: 'key-1',
        versionNumber: 1,
        status: 'ACTIVE',
        providerKeyId: created.providerKeyId,
        publicKey: created.publicKey,
        encryptedKeyMaterial: created.encryptedKeyMaterial,
        keyFingerprint: created.keyFingerprint,
        metadata: created.metadata,
        createdAt: new Date(),
      };

      const message = Buffer.from('Quantum-safe payload verification', 'utf8');

      // Sign
      const signature = await provider.sign(created.providerKeyId, message, mockVersion);
      expect(signature).toBeInstanceOf(Buffer);
      expect(signature.length).toBe(3309); // ML-DSA-65 signature size in bytes

      // Verify valid signature
      const isValid = await provider.verify(created.providerKeyId, message, signature, mockVersion);
      expect(isValid).toBe(true);

      // Verify tampered message fails
      const tamperedMessage = Buffer.from('Tampered payload', 'utf8');
      const isTamperedMsgValid = await provider.verify(created.providerKeyId, tamperedMessage, signature, mockVersion);
      expect(isTamperedMsgValid).toBe(false);

      // Verify tampered signature fails
      const tamperedSignature = Buffer.from(signature);
      tamperedSignature[0] ^= 0xff;
      const isTamperedSigValid = await provider.verify(created.providerKeyId, message, tamperedSignature, mockVersion);
      expect(isTamperedSigValid).toBe(false);
    });
  });

  // =========================================================================
  // 2. AZURE KEY VAULT PROVIDER (TRUTHFUL REJECTION OF PQC)
  // =========================================================================
  describe('AzureKeyVaultKeyProvider Truthful Capabilities & Rejection', () => {
    let provider: AzureKeyVaultKeyProvider;

    beforeEach(() => {
      provider = new AzureKeyVaultKeyProvider();
    });

    it('truthfully declares supportsPqc: false', () => {
      expect(provider.capabilities.supportsPqc).toBe(false);
      expect(provider.capabilities.isHardwareBacked).toBe(false);
      expect(provider.capabilities.isFips140Validated).toBe(true);
    });

    it('truthfully rejects ML-KEM algorithms with OPERATION_NOT_SUPPORTED without silent fallback', async () => {
      const kemAlgorithms = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'];

      for (const algorithm of kemAlgorithms) {
        await expect(
          provider.createKey({
            name: `azure-pqc-kem-${algorithm.toLowerCase()}`,
            algorithm,
            purpose: 'KEY_AGREEMENT',
            organizationId: 'org-test-123',
            projectId: 'proj-test-123',
            environmentId: 'env-test-123',
          })
        ).rejects.toThrow(
          new CryptoEngineError(
            'OPERATION_NOT_SUPPORTED',
            `Azure Key Vault does not support Post-Quantum Cryptography algorithm '${algorithm}'. Azure Key Vault currently only supports classical RSA and EC algorithms.`
          )
        );
      }
    });

    it('truthfully rejects ML-DSA algorithms with OPERATION_NOT_SUPPORTED', async () => {
      const dsaAlgorithms = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

      for (const algorithm of dsaAlgorithms) {
        await expect(
          provider.createKey({
            name: `azure-pqc-dsa-${algorithm.toLowerCase()}`,
            algorithm,
            purpose: 'SIGNING',
            organizationId: 'org-test-123',
            projectId: 'proj-test-123',
            environmentId: 'env-test-123',
          })
        ).rejects.toThrow(
          new CryptoEngineError(
            'OPERATION_NOT_SUPPORTED',
            `Azure Key Vault does not support Post-Quantum Cryptography algorithm '${algorithm}'. Azure Key Vault currently only supports classical RSA and EC algorithms.`
          )
        );
      }
    });

    it('truthfully rejects Hybrid X25519+ML-KEM-768 with OPERATION_NOT_SUPPORTED', async () => {
      await expect(
        provider.createKey({
          name: 'azure-pqc-hybrid',
          algorithm: 'X25519+ML-KEM-768',
          purpose: 'KEY_AGREEMENT',
          organizationId: 'org-test-123',
          projectId: 'proj-test-123',
          environmentId: 'env-test-123',
        })
      ).rejects.toThrow(
        new CryptoEngineError(
          'OPERATION_NOT_SUPPORTED',
          "Azure Key Vault does not support Post-Quantum Cryptography algorithm 'X25519+ML-KEM-768'. Azure Key Vault currently only supports classical RSA and EC algorithms."
        )
      );
    });
  });

  // =========================================================================
  // 3. AZURE MANAGED HSM PROVIDER (TRUTHFUL REJECTION OF PQC)
  // =========================================================================
  describe('AzureManagedHsmProvider Truthful Capabilities & Rejection', () => {
    let provider: AzureManagedHsmProvider;

    beforeEach(() => {
      provider = new AzureManagedHsmProvider();
    });

    it('truthfully declares supportsPqc: false', () => {
      expect(provider.capabilities.supportsPqc).toBe(false);
      expect(provider.capabilities.isHardwareBacked).toBe(true);
      expect(provider.capabilities.isFips140Validated).toBe(true);
    });

    it('truthfully rejects PQC algorithms with OPERATION_NOT_SUPPORTED and clear explanation', async () => {
      await expect(
        provider.createKey({
          name: 'hsm-pqc-kem',
          algorithm: 'ML-KEM-768',
          purpose: 'KEY_AGREEMENT',
          organizationId: 'org-test-123',
          projectId: 'proj-test-123',
          environmentId: 'env-test-123',
        })
      ).rejects.toThrow(
        new CryptoEngineError(
          'OPERATION_NOT_SUPPORTED',
          "Azure Managed HSM does not support Post-Quantum Cryptography algorithm 'ML-KEM-768'. Azure Managed HSM currently only supports classical oct-HSM (AES), RSA-HSM, and EC-HSM keys."
        )
      );

      await expect(
        provider.createKey({
          name: 'hsm-pqc-dsa',
          algorithm: 'ML-DSA-65',
          purpose: 'SIGNING',
          organizationId: 'org-test-123',
          projectId: 'proj-test-123',
          environmentId: 'env-test-123',
        })
      ).rejects.toThrow(
        new CryptoEngineError(
          'OPERATION_NOT_SUPPORTED',
          "Azure Managed HSM does not support Post-Quantum Cryptography algorithm 'ML-DSA-65'. Azure Managed HSM currently only supports classical oct-HSM (AES), RSA-HSM, and EC-HSM keys."
        )
      );
    });
  });

  // =========================================================================
  // 4. CUSTOMER AZURE KEY VAULT PROVIDER (ONBOARDING CAPABILITIES)
  // =========================================================================
  describe('CustomerAzureKeyVaultProvider Capabilities Assessment', () => {
    it('truthfully reports supportsPqc: false in provider capabilities and pqc: false in testConnection', async () => {
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

      // Provider static capabilities
      expect(provider.capabilities.supportsPqc).toBe(false);

      // Connection test result capabilities
      const testRes = await provider.testConnection();
      expect(testRes.pqc).toBe(false);
      expect(testRes.capabilities.pqc).toBe(false);
      expect(testRes.capabilities.unavailableReasons?.pqc).toContain('Post-Quantum Cryptography');
    });
  });
});
