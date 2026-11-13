import crypto from 'crypto';
import {
  CryptoScanner,
  QuantumClassifier,
  CryptoRelationshipGraph,
  PolicyEvaluator,
  CryptoMigrationEngine,
  CryptoAgilityEngine,
  CBOMGenerator,
  SnapshotManager,
  CryptoAssetItem,
  CryptoFindingItem,
} from '@amaracus/crypto-core';

describe('Phase 8 — Crypto Intelligence Core Engine', () => {
  const orgId = 'org_test_intel_core';

  describe('1. Unified Cryptographic Asset Discovery (Scanner)', () => {
    it('discovers keys and customer BYOK/HSM keys with accurate metadata and fingerprints', () => {
      const mockKeys = [
        {
          id: 'key_1',
          name: 'payment-signing-key',
          algorithm: 'RSA-2048',
          purpose: 'SIGNING',
          provider: 'LOCAL_DEV',
          status: 'ACTIVE',
          versions: [{ keyFingerprint: 'fp_rsa_2048_abc' }],
          createdAt: new Date(),
        },
      ];

      const mockCustomerKeys = [
        {
          id: 'byok_1',
          keyIdentifier: 'vault-master-kek',
          algorithm: 'AES-256-GCM',
          keyType: 'oct-HSM',
          isHsmBacked: true,
          keyVaultUrl: 'https://contoso-hsm.managedhsm.azure.net',
          status: 'ACTIVE',
          keyFingerprint: 'fp_aes_hsm_xyz',
          createdAt: new Date(),
        },
      ];

      const { assets } = CryptoScanner.scanAll({
        organizationId: orgId,
        keys: mockKeys,
        customerKeys: mockCustomerKeys,
      });

      expect(assets.length).toBe(2);

      const rsaKey = assets.find((a) => a.name === 'payment-signing-key');
      expect(rsaKey).toBeDefined();
      expect(rsaKey?.assetType).toBe('KEY');
      expect(rsaKey?.algorithm).toBe('RSA-2048');
      expect(rsaKey?.quantumStatus).toBe('QUANTUM_VULNERABLE');
      expect(rsaKey?.confidence).toBe('HIGH');

      const byokKey = assets.find((a) => a.name === 'vault-master-kek');
      expect(byokKey).toBeDefined();
      expect(byokKey?.provider).toBe('AZURE_MANAGED_HSM');
      expect(byokKey?.quantumStatus).toBe('CLASSICAL');
    });

    it('discovers X.509 Certificate Authorities and Certificates with lifecycles', () => {
      const now = new Date();
      const inOneYear = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

      const mockCAs = [
        {
          id: 'ca_root_1',
          name: 'Amaracus Corporate Root CA',
          subject: 'CN=Amaracus Corporate Root CA',
          issuer: 'CN=Amaracus Corporate Root CA',
          serialNumber: '01',
          keyAlgorithm: 'RSA-4096',
          signatureAlgorithm: 'SHA256withRSA',
          type: 'ROOT_CA',
          status: 'ACTIVE',
          fingerprint: 'fp_root_ca_1',
          notBefore: now,
          notAfter: inOneYear,
          keyReference: 'key_ca_root',
        },
      ];

      const mockCerts = [
        {
          id: 'cert_tls_1',
          name: 'api.amaracus.dev',
          subject: 'CN=api.amaracus.dev',
          issuer: 'CN=Amaracus Corporate Root CA',
          serialNumber: '02',
          certificateType: 'SERVER',
          keyAlgorithm: 'ECDSA-P256',
          signatureAlgorithm: 'SHA256withECDSA',
          publicKeyAlgorithm: 'EC',
          status: 'ACTIVE',
          fingerprint: 'fp_cert_tls_1',
          notBefore: now,
          notAfter: inOneYear,
          authorityId: 'ca_root_1',
          keyReference: 'key_cert_1',
        },
      ];

      const { assets } = CryptoScanner.scanAll({
        organizationId: orgId,
        certificateAuthorities: mockCAs,
        certificates: mockCerts,
      });

      expect(assets.length).toBe(2);
      const caAsset = assets.find((a) => a.assetType === 'CERTIFICATE_AUTHORITY');
      expect(caAsset?.name).toBe('Amaracus Corporate Root CA');
      expect(caAsset?.source).toBe('CERTIFICATE_INVENTORY');

      const certAsset = assets.find((a) => a.assetType === 'CERTIFICATE');
      expect(certAsset?.name).toBe('api.amaracus.dev');
      expect(certAsset?.quantumStatus).toBe('QUANTUM_VULNERABLE');
    });

    it('detects concrete AST-level source code usages while rejecting comments and string mentions', () => {
      const sampleSource = `
        // This is a comment mentioning RSA-2048 and MD5 which must NOT be flagged as usage
        /*
          Block comment mentioning crypto.createHash('sha1')
        */
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const hash = crypto.createHash('sha256');
        const hmac = crypto.createHmac('sha512', secret);
        const mlkemResult = mlkem.encapsulate(peerPublicKey);
        // Another comment: do not use SHA-1
      `;

      const sourceFiles = [{ path: 'src/crypto/service.ts', content: sampleSource }];

      const { assets, sourceUsages } = CryptoScanner.scanAll({
        organizationId: orgId,
        sourceFiles,
      });

      // Must find actual invocations
      expect(sourceUsages.some((u) => u.operation === 'CIPHER_ENCRYPT' && u.algorithm === 'AES-256-GCM')).toBe(true);
      expect(sourceUsages.some((u) => u.operation === 'HASH' && u.algorithm === 'SHA256')).toBe(true);
      expect(sourceUsages.some((u) => u.operation === 'HMAC' && u.algorithm === 'HMAC-SHA512')).toBe(true);
      expect(sourceUsages.some((u) => u.operation === 'PQC_KEM' && u.algorithm === 'ML-KEM-768')).toBe(true);

      // Must NOT flag commented RSA or MD5
      expect(sourceUsages.some((u) => u.algorithm === 'MD5')).toBe(false);
      expect(sourceUsages.some((u) => u.algorithm === 'SHA-1' || u.algorithm === 'SHA1')).toBe(false);
    });
  });

  describe('2. Quantum Risk Classification (Shor vs Grover Bounds)', () => {
    it('classifies classical asymmetric algorithms as QUANTUM_VULNERABLE with Shor rationale', () => {
      const rsaRes = QuantumClassifier.classify('RSA-2048');
      expect(rsaRes.quantumStatus).toBe('QUANTUM_VULNERABLE');
      expect(rsaRes.rationale).toContain('integer factorization');
      expect(rsaRes.impactMechanism).toContain("Shor's quantum algorithm");

      const eccRes = QuantumClassifier.classify('ECDSA-P256');
      expect(eccRes.quantumStatus).toBe('QUANTUM_VULNERABLE');

      const edRes = QuantumClassifier.classify('Ed25519');
      expect(edRes.quantumStatus).toBe('QUANTUM_VULNERABLE');
    });

    it('classifies NIST FIPS 203/204 algorithms as PQC', () => {
      const mlkemRes = QuantumClassifier.classify('ML-KEM-768');
      expect(mlkemRes.quantumStatus).toBe('PQC');
      expect(mlkemRes.nistStatus).toBe('NIST FIPS 203');

      const mldsaRes = QuantumClassifier.classify('ML-DSA-65');
      expect(mldsaRes.quantumStatus).toBe('PQC');
      expect(mldsaRes.nistStatus).toBe('NIST FIPS 204');
    });

    it('classifies dual combiners as HYBRID', () => {
      const hybridRes = QuantumClassifier.classify('X25519+ML-KEM-768');
      expect(hybridRes.quantumStatus).toBe('HYBRID');
      expect(hybridRes.rationale).toContain('Store-Now-Decrypt-Later');
    });

    it('classifies symmetric primitives >= 256 bits as Grover-resistant CLASSICAL', () => {
      const aes256 = QuantumClassifier.classify('AES-256-GCM');
      expect(aes256.quantumStatus).toBe('CLASSICAL');
      expect(aes256.rationale).toContain('Grover');

      const sha256 = QuantumClassifier.classify('SHA-256');
      expect(sha256.quantumStatus).toBe('CLASSICAL');
    });
  });

  describe('3. Cryptographic Relationship Graph & Impact Traversal', () => {
    it('builds relationships and recursively discovers downstream affected assets', () => {
      const assets: CryptoAssetItem[] = [
        {
          id: 'asset_algo_rsa',
          organizationId: orgId,
          assetType: 'ALGORITHM',
          name: 'RSA-2048',
          algorithm: 'RSA-2048',
          source: 'CONFIGURATION',
          confidence: 'HIGH',
          status: 'ACTIVE',
          quantumStatus: 'QUANTUM_VULNERABLE',
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'asset_ca_root',
          organizationId: orgId,
          assetType: 'CERTIFICATE_AUTHORITY',
          name: 'Corporate Root CA',
          algorithm: 'RSA-4096',
          source: 'CERTIFICATE_INVENTORY',
          confidence: 'HIGH',
          status: 'ACTIVE',
          quantumStatus: 'QUANTUM_VULNERABLE',
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'asset_key_leaf',
          organizationId: orgId,
          assetType: 'KEY',
          name: 'web-tls-key',
          algorithm: 'RSA-2048',
          source: 'KEY_MANAGEMENT',
          confidence: 'HIGH',
          status: 'ACTIVE',
          quantumStatus: 'QUANTUM_VULNERABLE',
          metadata: { keyId: 'raw_key_leaf_1' },
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'asset_cert_leaf',
          organizationId: orgId,
          environmentId: 'env_prod',
          assetType: 'CERTIFICATE',
          name: 'api.internal.corp',
          algorithm: 'RSA-2048',
          source: 'CERTIFICATE_INVENTORY',
          confidence: 'HIGH',
          status: 'ACTIVE',
          quantumStatus: 'QUANTUM_VULNERABLE',
          metadata: { authorityId: 'ca_root', keyReference: 'raw_key_leaf_1' },
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];

      const rels = CryptoRelationshipGraph.inferRelationships(assets, orgId);
      const graph = new CryptoRelationshipGraph(assets, rels);

      // Downstream impact of deprecating RSA-2048:
      const impact = graph.getDownstreamImpact('asset_algo_rsa');
      expect(impact.totalAffected).toBeGreaterThanOrEqual(2);
      expect(impact.affectedKeys.some((k) => k.name === 'web-tls-key')).toBe(true);
      expect(impact.affectedCertificates.some((c) => c.name === 'api.internal.corp')).toBe(true);
    });
  });

  describe('4. Policy Evaluator & Security Findings', () => {
    it('generates CRITICAL finding for expired certificate and HIGH for expiring in <30 days', () => {
      const now = new Date();
      const expiredDate = new Date(now.getTime() - 5 * 24 * 60 * 60 * 1000); // 5 days ago
      const expiringDate = new Date(now.getTime() + 15 * 24 * 60 * 60 * 1000); // in 15 days

      const assets: CryptoAssetItem[] = [
        {
          id: 'cert_expired',
          organizationId: orgId,
          assetType: 'CERTIFICATE',
          name: 'legacy-api.contoso.com',
          algorithm: 'RSA-2048',
          source: 'CERTIFICATE_INVENTORY',
          confidence: 'HIGH',
          status: 'ACTIVE',
          quantumStatus: 'QUANTUM_VULNERABLE',
          metadata: { notAfter: expiredDate.toISOString() },
          firstSeenAt: now,
          lastSeenAt: now,
          createdAt: now,
          updatedAt: now,
        },
        {
          id: 'cert_expiring',
          organizationId: orgId,
          assetType: 'CERTIFICATE',
          name: 'gateway.contoso.com',
          algorithm: 'ECDSA-P256',
          source: 'CERTIFICATE_INVENTORY',
          confidence: 'HIGH',
          status: 'ACTIVE',
          quantumStatus: 'QUANTUM_VULNERABLE',
          metadata: { notAfter: expiringDate.toISOString() },
          firstSeenAt: now,
          lastSeenAt: now,
          createdAt: now,
          updatedAt: now,
        },
      ];

      const findings = PolicyEvaluator.evaluateAssets(assets);
      const expiredFinding = findings.find((f) => f.category === 'EXPIRED_CERTIFICATE');
      expect(expiredFinding).toBeDefined();
      expect(expiredFinding?.severity).toBe('CRITICAL');

      const expiringFinding = findings.find((f) => f.category === 'EXPIRING_SOON');
      expect(expiringFinding).toBeDefined();
      expect(expiringFinding?.severity).toBe('HIGH');
    });

    it('generates finding for weak RSA-1024 and quantum-vulnerable algorithms under PQC_ONLY policy', () => {
      const assets: CryptoAssetItem[] = [
        {
          id: 'key_weak',
          organizationId: orgId,
          assetType: 'KEY',
          name: 'weak-rsa-key',
          algorithm: 'RSA-1024',
          source: 'KEY_MANAGEMENT',
          confidence: 'HIGH',
          status: 'ACTIVE',
          quantumStatus: 'QUANTUM_VULNERABLE',
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'key_ecc',
          organizationId: orgId,
          assetType: 'KEY',
          name: 'ecdsa-auth-key',
          algorithm: 'ED25519',
          source: 'KEY_MANAGEMENT',
          confidence: 'HIGH',
          status: 'ACTIVE',
          quantumStatus: 'QUANTUM_VULNERABLE',
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];

      const findings = PolicyEvaluator.evaluateAssets(assets, 'PQC_ONLY');
      expect(findings.some((f) => f.category === 'WEAK_KEY_SIZE' && f.severity === 'CRITICAL')).toBe(true);
      expect(findings.some((f) => f.category === 'NON_COMPLIANT_POLICY' && f.severity === 'HIGH')).toBe(true);
    });
  });

  describe('5. Crypto-Agility Engine & Migration Recommendations', () => {
    it('recommends ML-DSA-65 for classical signatures and X25519+ML-KEM-768 for key exchange', () => {
      const sigRec = CryptoMigrationEngine.getMigrationRecommendation('RSA-2048');
      expect(sigRec.recommendedAlgorithm).toBe('ML-DSA-65');
      expect(sigRec.strategy).toBe('HYBRID_DUAL_RUN');
      expect(sigRec.standardReference).toContain('FIPS 204');

      const kemRec = CryptoMigrationEngine.getMigrationRecommendation('ECDH');
      expect(kemRec.recommendedAlgorithm).toBe('X25519+ML-KEM-768');
      expect(kemRec.strategy).toBe('HYBRID_DUAL_RUN');
    });

    it('supports policy-driven algorithm selection decoupling applications from primitives', () => {
      const defaultSig = CryptoAgilityEngine.selectAlgorithm({ operation: 'digital_signature', policy: 'DEFAULT_SECURE' });
      expect(defaultSig).toBe('ED25519');

      const pqcSig = CryptoAgilityEngine.selectAlgorithm({ operation: 'digital_signature', policy: 'PQC_ONLY' });
      expect(pqcSig).toBe('ML-DSA-65');

      const hybridKem = CryptoAgilityEngine.selectAlgorithm({ operation: 'key_encapsulation', policy: 'HYBRID_REQUIRED' });
      expect(hybridKem).toBe('X25519+ML-KEM-768');
    });
  });

  describe('6. CBOM Generation & Strict Zero Secret Leakage', () => {
    it('generates a machine-readable CBOM with manifest integrity hash and 0 secret leaks', () => {
      const assets: CryptoAssetItem[] = [
        {
          id: 'asset_cert_prod',
          organizationId: orgId,
          assetType: 'CERTIFICATE',
          name: 'gateway.prod.amaracus.net',
          algorithm: 'RSA-2048',
          provider: 'AMARACUS_PKI',
          source: 'CERTIFICATE_INVENTORY',
          confidence: 'HIGH',
          status: 'ACTIVE',
          quantumStatus: 'QUANTUM_VULNERABLE',
          fingerprint: 'sha256_fp_gateway_123',
          metadata: {
            subject: 'CN=gateway.prod.amaracus.net',
            serialNumber: '998877',
            // Sensitive fields that MUST be omitted:
            encryptedKeyMaterial: 'SECRET_SHOULD_NOT_LEAK',
            password: 'secret_password_test',
          },
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];

      const cbom = CBOMGenerator.generate({
        organizationId: orgId,
        assets,
        environment: 'PRODUCTION',
      });

      expect(cbom.cbomVersion).toBe('1.0.0');
      expect(cbom.organizationId).toBe(orgId);
      expect(cbom.components.length).toBe(1);
      expect(cbom.integrity.algorithm).toBe('SHA-256');
      expect(cbom.integrity.hash).toHaveLength(64);

      // Verify ZERO SECRET LEAKAGE
      const cbomJson = JSON.stringify(cbom);
      expect(cbomJson).not.toContain('SECRET_SHOULD_NOT_LEAK');
      expect(cbomJson).not.toContain('secret_password_test');
      expect(cbomJson).not.toContain('PRIVATE KEY');
    });
  });

  describe('7. Inventory Snapshots & Drift Detection', () => {
    it('detects NEW, CHANGED, REMOVED, and UNCHANGED assets across scans', () => {
      const assetA: CryptoAssetItem = {
        id: 'asset_a',
        organizationId: orgId,
        assetType: 'KEY',
        name: 'key-a',
        algorithm: 'RSA-2048',
        source: 'KEY_MANAGEMENT',
        confidence: 'HIGH',
        status: 'ACTIVE',
        quantumStatus: 'QUANTUM_VULNERABLE',
        fingerprint: 'fp_a_v1',
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const assetB: CryptoAssetItem = {
        id: 'asset_b',
        organizationId: orgId,
        assetType: 'KEY',
        name: 'key-b',
        algorithm: 'AES-256-GCM',
        source: 'KEY_MANAGEMENT',
        confidence: 'HIGH',
        status: 'ACTIVE',
        quantumStatus: 'CLASSICAL',
        fingerprint: 'fp_b_v1',
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      // Initial Snapshot
      const snap1 = SnapshotManager.createSnapshot({
        organizationId: orgId,
        assets: [assetA, assetB],
      });
      expect(snap1.totalAssets).toBe(2);
      expect(snap1.drift?.newAssets).toHaveLength(2);

      // Second Scan:
      // assetA is modified (fingerprint changed)
      // assetB is removed
      // assetC is newly added
      const assetAModified: CryptoAssetItem = {
        ...assetA,
        fingerprint: 'fp_a_v2_rotated',
      };
      const assetC: CryptoAssetItem = {
        id: 'asset_c',
        organizationId: orgId,
        assetType: 'KEY',
        name: 'key-c',
        algorithm: 'ML-KEM-768',
        source: 'KEY_MANAGEMENT',
        confidence: 'HIGH',
        status: 'ACTIVE',
        quantumStatus: 'PQC',
        fingerprint: 'fp_c_v1',
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const snap2 = SnapshotManager.createSnapshot({
        organizationId: orgId,
        assets: [assetAModified, assetC],
        previousSnapshot: snap1,
      });

      expect(snap2.drift?.newAssets).toContain('asset_c');
      expect(snap2.drift?.changedAssets).toContain('asset_a');
      expect(snap2.drift?.removedAssets).toContain('asset_b');
    });
  });
});
