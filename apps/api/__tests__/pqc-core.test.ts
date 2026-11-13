import {
  cryptoEngine,
  registry,
  CryptoPolicyEngine,
  CRYPTO_POLICIES,
  CryptoAgilityEngine,
  MlKemEngine,
  MlDsaEngine,
  HybridKemEngine,
} from '@amaracus/crypto-core';

describe('Phase 6 — Post-Quantum Cryptography Core Engines', () => {
  // =========================================================================
  // 1. NIST FIPS 203: ML-KEM (Module-Lattice Key Encapsulation Mechanism)
  // =========================================================================
  describe('NIST FIPS 203: ML-KEM Engine', () => {
    const kemAlgorithms: Array<'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024'> = [
      'ML-KEM-512',
      'ML-KEM-768',
      'ML-KEM-1024',
    ];

    kemAlgorithms.forEach((algorithm) => {
      describe(`${algorithm}`, () => {
        it('generates keypair with exact NIST FIPS 203 parameter lengths', async () => {
          const keypair = await cryptoEngine.kemKeygen({ algorithm, encoding: 'hex' });

          expect(keypair.algorithm).toBe(algorithm);
          expect(keypair.encoding).toBe('hex');

          // Expected byte lengths according to FIPS 203:
          // ML-KEM-512:  pk = 800 bytes (1600 hex),  sk = 1632 bytes (3264 hex)
          // ML-KEM-768:  pk = 1184 bytes (2368 hex), sk = 2400 bytes (4800 hex)
          // ML-KEM-1024: pk = 1568 bytes (3136 hex), sk = 3168 bytes (6336 hex)
          const expectedLengths: Record<string, { pk: number; sk: number; sec: number }> = {
            'ML-KEM-512': { pk: 800, sk: 1632, sec: 1 },
            'ML-KEM-768': { pk: 1184, sk: 2400, sec: 3 },
            'ML-KEM-1024': { pk: 1568, sk: 3168, sec: 5 },
          };

          const expected = expectedLengths[algorithm];
          expect(keypair.publicKeyBytes).toBe(expected.pk);
          expect(keypair.privateKeyBytes).toBe(expected.sk);
          expect(keypair.securityLevel).toBe(expected.sec);
          expect(keypair.publicKey.length).toBe(expected.pk * 2);
          expect(keypair.privateKey.length).toBe(expected.sk * 2);
        });

        it('performs complete encapsulation and decapsulation round-trip with identical shared secret', async () => {
          // 1. Recipient generates keypair
          const recipientKeys = await cryptoEngine.kemKeygen({ algorithm });

          // 2. Sender encapsulates against recipient's public key
          const encResult = await cryptoEngine.kemEncapsulate(
            {
              algorithm,
              publicKey: recipientKeys.publicKey,
            },
            'PQC_PREFERRED'
          );

          expect(encResult.algorithm).toBe(algorithm);
          expect(encResult.sharedSecretBytes).toBe(32); // 256-bit shared secret per FIPS 203
          expect(encResult.sharedSecret.length).toBe(64); // 32 bytes in hex

          // Expected ciphertext lengths per FIPS 203:
          // 512: 768 bytes, 768: 1088 bytes, 1024: 1568 bytes
          const expectedCtBytes: Record<string, number> = {
            'ML-KEM-512': 768,
            'ML-KEM-768': 1088,
            'ML-KEM-1024': 1568,
          };
          expect(encResult.ciphertextBytes).toBe(expectedCtBytes[algorithm]);
          expect(encResult.ciphertext.length).toBe(expectedCtBytes[algorithm] * 2);

          // 3. Recipient decapsulates using private key
          const decResult = await cryptoEngine.kemDecapsulate(
            {
              algorithm,
              privateKey: recipientKeys.privateKey,
              ciphertext: encResult.ciphertext,
            },
            'PQC_PREFERRED'
          );

          // 4. Verification: Both parties arrive at identical 256-bit shared secret
          expect(decResult.sharedSecret).toBe(encResult.sharedSecret);
          expect(decResult.sharedSecretBytes).toBe(32);
        });

        it('implicitly rejects tampered ciphertext without leaking secret (Fujisaki-Okamoto property)', async () => {
          const recipientKeys = await cryptoEngine.kemKeygen({ algorithm });
          const encResult = await cryptoEngine.kemEncapsulate(
            {
              algorithm,
              publicKey: recipientKeys.publicKey,
            },
            'PQC_PREFERRED'
          );

          // Flip one nibble in the ciphertext
          const ctBytes = Buffer.from(encResult.ciphertext, 'hex');
          ctBytes[0] ^= 0xff;
          const tamperedCt = ctBytes.toString('hex');

          // Decapsulation of tampered ciphertext MUST succeed without crashing,
          // but return a pseudo-random secret that does NOT match the sender's secret
          const decResult = await cryptoEngine.kemDecapsulate(
            {
              algorithm,
              privateKey: recipientKeys.privateKey,
              ciphertext: tamperedCt,
            },
            'PQC_PREFERRED'
          );

          expect(decResult.sharedSecret).not.toBe(encResult.sharedSecret);
          expect(decResult.sharedSecret.length).toBe(64);
        });

        it('rejects invalid key sizes safely', async () => {
          const invalidPk = Buffer.alloc(100, 0xaa).toString('hex');
          await expect(
            cryptoEngine.kemEncapsulate({
              algorithm,
              publicKey: invalidPk,
            })
          ).rejects.toThrow('must be exactly');
        });
      });
    });
  });

  // =========================================================================
  // 2. NIST FIPS 204: ML-DSA (Module-Lattice Digital Signature Algorithm)
  // =========================================================================
  describe('NIST FIPS 204: ML-DSA Engine', () => {
    const dsaAlgorithms: Array<'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87'> = [
      'ML-DSA-44',
      'ML-DSA-65',
      'ML-DSA-87',
    ];

    dsaAlgorithms.forEach((algorithm) => {
      describe(`${algorithm}`, () => {
        it('generates keypair with exact NIST FIPS 204 parameter lengths', async () => {
          const keypair = await cryptoEngine.pqcKeygen({ algorithm, encoding: 'hex' });

          expect(keypair.algorithm).toBe(algorithm);

          // Expected byte lengths according to FIPS 204:
          // ML-DSA-44: pk = 1312 bytes, sk = 2560 bytes, sec = 2
          // ML-DSA-65: pk = 1952 bytes, sk = 4032 bytes, sec = 3
          // ML-DSA-87: pk = 2592 bytes, sk = 4896 bytes, sec = 5
          const expectedLengths: Record<string, { pk: number; sk: number; sec: number }> = {
            'ML-DSA-44': { pk: 1312, sk: 2560, sec: 2 },
            'ML-DSA-65': { pk: 1952, sk: 4032, sec: 3 },
            'ML-DSA-87': { pk: 2592, sk: 4896, sec: 5 },
          };

          const expected = expectedLengths[algorithm];
          expect(keypair.publicKeyBytes).toBe(expected.pk);
          expect(keypair.privateKeyBytes).toBe(expected.sk);
          expect(keypair.securityLevel).toBe(expected.sec);
          expect(keypair.publicKey.length).toBe(expected.pk * 2);
          expect(keypair.privateKey.length).toBe(expected.sk * 2);
        });

        it('signs and verifies a message successfully', async () => {
          const keypair = await cryptoEngine.pqcKeygen({ algorithm });
          const message = 'CRITICAL_FINANCIAL_TRANSACTION_PAYLOAD_2026_Q4';

          const signResult = await cryptoEngine.pqcSign(
            {
              algorithm,
              privateKey: keypair.privateKey,
              message,
            },
            'PQC_PREFERRED'
          );

          // Expected signature bytes per FIPS 204:
          // 44: 2420 bytes, 65: 3309 bytes, 87: 4627 bytes
          const expectedSigBytes: Record<string, number> = {
            'ML-DSA-44': 2420,
            'ML-DSA-65': 3309,
            'ML-DSA-87': 4627,
          };
          expect(signResult.signatureBytes).toBe(expectedSigBytes[algorithm]);
          expect(signResult.signature.length).toBe(expectedSigBytes[algorithm] * 2);

          const verifyResult = await cryptoEngine.pqcVerify(
            {
              algorithm,
              publicKey: keypair.publicKey,
              message,
              signature: signResult.signature,
            },
            'PQC_PREFERRED'
          );

          expect(verifyResult.valid).toBe(true);
        });

        it('rejects tampered messages with valid signature', async () => {
          const keypair = await cryptoEngine.pqcKeygen({ algorithm });
          const message = 'ORIGINAL_UNMODIFIED_MESSAGE';

          const signResult = await cryptoEngine.pqcSign(
            {
              algorithm,
              privateKey: keypair.privateKey,
              message,
            },
            'PQC_PREFERRED'
          );

          const verifyResult = await cryptoEngine.pqcVerify(
            {
              algorithm,
              publicKey: keypair.publicKey,
              message: 'TAMPERED_MESSAGE_ATTEMPT',
              signature: signResult.signature,
            },
            'PQC_PREFERRED'
          );

          expect(verifyResult.valid).toBe(false);
        });

        it('rejects tampered signatures', async () => {
          const keypair = await cryptoEngine.pqcKeygen({ algorithm });
          const message = 'TEST_MESSAGE';

          const signResult = await cryptoEngine.pqcSign(
            {
              algorithm,
              privateKey: keypair.privateKey,
              message,
            },
            'PQC_PREFERRED'
          );

          // Mutate signature bytes
          const sigBuf = Buffer.from(signResult.signature, 'hex');
          sigBuf[10] ^= 0x55;

          const verifyResult = await cryptoEngine.pqcVerify(
            {
              algorithm,
              publicKey: keypair.publicKey,
              message,
              signature: sigBuf.toString('hex'),
            },
            'PQC_PREFERRED'
          );

          expect(verifyResult.valid).toBe(false);
        });

        it('supports optional context string according to FIPS 204', async () => {
          const keypair = await cryptoEngine.pqcKeygen({ algorithm });
          const message = 'TRANSACTION_REQUIRING_CONTEXT';
          const context = 'amaracus-tenant-production-domain';

          const signResult = await cryptoEngine.pqcSign(
            {
              algorithm,
              privateKey: keypair.privateKey,
              message,
              context,
            },
            'PQC_PREFERRED'
          );

          // Correct context verifies
          const goodVerify = await cryptoEngine.pqcVerify(
            {
              algorithm,
              publicKey: keypair.publicKey,
              message,
              signature: signResult.signature,
              context,
            },
            'PQC_PREFERRED'
          );
          expect(goodVerify.valid).toBe(true);

          // Wrong context fails
          const badVerify = await cryptoEngine.pqcVerify(
            {
              algorithm,
              publicKey: keypair.publicKey,
              message,
              signature: signResult.signature,
              context: 'wrong-context-string',
            },
            'PQC_PREFERRED'
          );
          expect(badVerify.valid).toBe(false);
        });
      });
    });
  });

  // =========================================================================
  // 3. HYBRID POST-QUANTUM KEY EXCHANGE (X25519 + ML-KEM-768)
  // =========================================================================
  describe('Hybrid Key Exchange: X25519 + ML-KEM-768 Dual Combiner', () => {
    it('generates composite keypair with X25519 and ML-KEM-768 components', async () => {
      const keypair = await cryptoEngine.hybridKeygen();

      expect(keypair.algorithm).toBe('X25519+ML-KEM-768');

      // Public key: 32 bytes (64 hex) X25519 + 1184 bytes (2368 hex) ML-KEM-768
      expect(keypair.publicKey.x25519PublicKey.length).toBe(64);
      expect(keypair.publicKey.mlkemPublicKey.length).toBe(2368);

      // Private key: 32 bytes (64 hex) X25519 + 2400 bytes (4800 hex) ML-KEM-768
      expect(keypair.privateKey.x25519PrivateKey.length).toBe(64);
      expect(keypair.privateKey.mlkemPrivateKey.length).toBe(4800);
    });

    it('performs hybrid encapsulation and decapsulation deriving identical shared secret', async () => {
      // 1. Bob generates hybrid keypair
      const bobKeys = await cryptoEngine.hybridKeygen();

      // 2. Alice encapsulates against Bob's hybrid public key
      const aliceResult = await cryptoEngine.hybridEncapsulate(
        {
          algorithm: 'X25519+ML-KEM-768',
          publicKey: bobKeys.publicKey,
        },
        'HYBRID_REQUIRED'
      );

      expect(aliceResult.algorithm).toBe('X25519+ML-KEM-768');
      expect(aliceResult.sharedSecret.length).toBe(64); // 32-byte derived secret
      expect(aliceResult.combinedCiphertext.length).toBe((32 + 1088) * 2); // 1120 bytes

      // 3. Bob decapsulates using his hybrid private key
      const bobResult = await cryptoEngine.hybridDecapsulate(
        {
          algorithm: 'X25519+ML-KEM-768',
          privateKey: bobKeys.privateKey,
          ciphertext: aliceResult.combinedCiphertext,
        },
        'HYBRID_REQUIRED'
      );

      // 4. Both arrive at exact same shared secret
      expect(bobResult.sharedSecret).toBe(aliceResult.sharedSecret);
    });

    it('fails safely if either component of the hybrid ciphertext is tampered', async () => {
      const bobKeys = await cryptoEngine.hybridKeygen();
      const aliceResult = await cryptoEngine.hybridEncapsulate({
        publicKey: bobKeys.publicKey,
      });

      // Tamper classical X25519 component
      const ctBuf = Buffer.from(aliceResult.combinedCiphertext, 'hex');
      ctBuf[5] ^= 0xaa;
      const tamperedCt = ctBuf.toString('hex');

      const bobResult = await cryptoEngine.hybridDecapsulate({
        privateKey: bobKeys.privateKey,
        ciphertext: tamperedCt,
      });

      // Must NOT produce Alice's original shared secret
      expect(bobResult.sharedSecret).not.toBe(aliceResult.sharedSecret);
    });
  });

  // =========================================================================
  // 4. CRYPTO AGILITY ENGINE & POLICIES
  // =========================================================================
  describe('Crypto Agility Engine', () => {
    it('selects algorithm based on high-level security intent and active policy', () => {
      // When hybrid is mandated by policy
      const selectedHybrid = cryptoEngine.agility.selectAlgorithm({
        operation: 'key_encapsulation',
        policy: 'HYBRID_REQUIRED',
      });
      expect(selectedHybrid).toBe('X25519+ML-KEM-768');

      // Under PQC_ONLY, select standard PQC KEM
      const selectedPqcKem = cryptoEngine.agility.selectAlgorithm({
        operation: 'key_encapsulation',
        policy: 'PQC_ONLY',
      });
      expect(selectedPqcKem).toBe('ML-KEM-768');

      // Under PQC_ONLY with max security level 5
      const selectedL5Kem = cryptoEngine.agility.selectAlgorithm({
        operation: 'key_encapsulation',
        policy: 'PQC_ONLY',
        minSecurityLevel: 5,
      });
      expect(selectedL5Kem).toBe('ML-KEM-1024');

      // Digital signatures under PQC_ONLY
      const selectedSig = cryptoEngine.agility.selectAlgorithm({
        operation: 'digital_signature',
        policy: 'PQC_ONLY',
      });
      expect(selectedSig).toBe('ML-DSA-65');

      // Digital signatures with level 5
      const selectedL5Sig = cryptoEngine.agility.selectAlgorithm({
        operation: 'digital_signature',
        policy: 'PQC_ONLY',
        minSecurityLevel: 5,
      });
      expect(selectedL5Sig).toBe('ML-DSA-87');
    });

    it('provides clear migration advice for classical algorithms', () => {
      const x25519Advice = cryptoEngine.agility.getMigrationAdvice('X25519');
      expect(x25519Advice.recommendedReplacement).toBe('X25519+ML-KEM-768');
      expect(x25519Advice.migrationReason).toContain('Store-Now-Decrypt-Later');

      const ed25519Advice = cryptoEngine.agility.getMigrationAdvice('ED25519');
      expect(ed25519Advice.recommendedReplacement).toBe('ML-DSA-65');
      expect(ed25519Advice.migrationReason).toContain('Shor');
    });

    it('enforces PQC_ONLY policy by blocking classical algorithms', () => {
      // Under PQC_ONLY, X25519 is prohibited
      expect(() =>
        CryptoPolicyEngine.validateOperation('PQC_ONLY', 'X25519', 'key_agreement')
      ).toThrow('prohibited under active cryptographic policy');

      // Under PQC_ONLY, ED25519 is prohibited
      expect(() =>
        CryptoPolicyEngine.validateOperation('PQC_ONLY', 'ED25519', 'sign')
      ).toThrow('prohibited under active cryptographic policy');

      // Under PQC_ONLY, ML-KEM-768 is permitted
      expect(() =>
        CryptoPolicyEngine.validateOperation('PQC_ONLY', 'ML-KEM-768', 'kem_encapsulate')
      ).not.toThrow();

      // Under PQC_ONLY, ML-DSA-65 is permitted
      expect(() =>
        CryptoPolicyEngine.validateOperation('PQC_ONLY', 'ML-DSA-65', 'pqc_sign')
      ).not.toThrow();
    });

    it('enforces CLASSICAL_ONLY policy by blocking PQC algorithms', () => {
      expect(() =>
        CryptoPolicyEngine.validateOperation('CLASSICAL_ONLY', 'ML-KEM-768', 'kem_encapsulate')
      ).toThrow('prohibited under active cryptographic policy');

      expect(() =>
        CryptoPolicyEngine.validateOperation('CLASSICAL_ONLY', 'ML-DSA-65', 'pqc_sign')
      ).toThrow('prohibited under active cryptographic policy');

      expect(() =>
        CryptoPolicyEngine.validateOperation('CLASSICAL_ONLY', 'ED25519', 'sign')
      ).not.toThrow();
    });
  });
});