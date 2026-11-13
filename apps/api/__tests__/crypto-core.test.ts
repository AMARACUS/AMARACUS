import {
  registry,
  cryptoEngine,
  CryptoPolicyEngine,
  CRYPTO_POLICIES,
  toBuffer,
  encodeBuffer,
  constantTimeEqual,
  CURRENT_ENVELOPE_VERSION,
  serializeEnvelope,
  parseEnvelope,
} from '@amaracus/crypto-core';

describe('Phase 4 — Core Cryptography Engine (KAT & Tamper Tests)', () => {
  // --- 1. ALGORITHM REGISTRY ---
  describe('Algorithm Registry', () => {
    it('provides single-source-of-truth metadata for all required algorithms', () => {
      const all = registry.getAll();
      expect(all.length).toBeGreaterThanOrEqual(12);

      const requiredAlgs = [
        'SHA-256',
        'SHA-384',
        'SHA-512',
        'SHA3-256',
        'SHA3-384',
        'SHA3-512',
        'HMAC-SHA-256',
        'HMAC-SHA-384',
        'HMAC-SHA-512',
        'AES-256-GCM',
        'ED25519',
        'X25519',
      ];

      for (const alg of requiredAlgs) {
        const meta = registry.get(alg);
        expect(meta).toBeDefined();
        expect(meta.id).toBe(alg);
        expect(meta.securityStatus).toBe('recommended');
      }
    });

    it('rejects unsupported algorithm requests safely', () => {
      expect(() => registry.get('MD5')).toThrow('not supported');
      expect(() => registry.validate('DES', 'encrypt')).toThrow('not supported');
    });

    it('rejects operations not supported by an algorithm', () => {
      expect(() => registry.validate('SHA-256', 'encrypt')).toThrow('does not support operation');
    });
  });

  // --- 2. HASHING (NIST / RFC KNOWN-ANSWER TESTS) ---
  describe('Hashing Known-Answer Tests (RFC 6234 / NIST FIPS 180-4 & 202)', () => {
    // Known test vector: "abc"
    const input = 'abc';

    it('SHA-256 matches official NIST test vector for "abc"', async () => {
      const res = await cryptoEngine.hash({ algorithm: 'SHA-256', data: input });
      expect(res.digest).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
      expect(res.byteLength).toBe(32);
    });

    it('SHA-384 matches official NIST test vector for "abc"', async () => {
      const res = await cryptoEngine.hash({ algorithm: 'SHA-384', data: input });
      expect(res.digest).toBe(
        'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'
      );
      expect(res.byteLength).toBe(48);
    });

    it('SHA-512 matches official NIST test vector for "abc"', async () => {
      const res = await cryptoEngine.hash({ algorithm: 'SHA-512', data: input });
      expect(res.digest).toBe(
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
      );
      expect(res.byteLength).toBe(64);
    });

    it('SHA3-256 matches official NIST FIPS 202 test vector for "abc"', async () => {
      const res = await cryptoEngine.hash({ algorithm: 'SHA3-256', data: input });
      expect(res.digest).toBe('3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
    });

    it('produces distinct digests for different inputs and empty inputs', async () => {
      const empty = await cryptoEngine.hash({ algorithm: 'SHA-256', data: '' });
      expect(empty.digest).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

      const a = await cryptoEngine.hash({ algorithm: 'SHA-256', data: 'hello' });
      const b = await cryptoEngine.hash({ algorithm: 'SHA-256', data: 'hello!' });
      expect(a.digest).not.toBe(b.digest);
    });
  });

  // --- 3. HMAC (RFC 4231 KNOWN-ANSWER TESTS) ---
  describe('HMAC Known-Answer Tests (RFC 4231)', () => {
    // RFC 4231 Test Case 1: Key = 20 bytes of 0x0b, Data = "Hi There"
    const key = Buffer.alloc(20, 0x0b);
    const data = 'Hi There';

    it('HMAC-SHA-256 matches RFC 4231 Test Case 1', async () => {
      const res = await cryptoEngine.hmac({
        algorithm: 'HMAC-SHA-256',
        key,
        data,
      });
      expect(res.mac).toBe('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');

      // Verify
      const isValid = await cryptoEngine.verifyHmac({
        algorithm: 'HMAC-SHA-256',
        key,
        data,
        mac: res.mac,
      });
      expect(isValid).toBe(true);
    });

    it('HMAC-SHA-512 matches RFC 4231 Test Case 1', async () => {
      const res = await cryptoEngine.hmac({
        algorithm: 'HMAC-SHA-512',
        key,
        data,
      });
      expect(res.mac).toBe(
        '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854'
      );
    });

    it('rejects tampered messages or keys with constant-time comparison', async () => {
      const mac = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7';

      // Modified message
      const badMsg = await cryptoEngine.verifyHmac({
        algorithm: 'HMAC-SHA-256',
        key,
        data: 'Hi There!',
        mac,
      });
      expect(badMsg).toBe(false);

      // Modified key
      const badKey = await cryptoEngine.verifyHmac({
        algorithm: 'HMAC-SHA-256',
        key: Buffer.alloc(20, 0x0c),
        data,
        mac,
      });
      expect(badKey).toBe(false);

      // Modified MAC
      const badMac = await cryptoEngine.verifyHmac({
        algorithm: 'HMAC-SHA-256',
        key,
        data,
        mac: 'a' + mac.substring(1),
      });
      expect(badMac).toBe(false);
    });
  });

  // --- 4. AES-256-GCM AEAD ENCRYPTION & TAMPER TESTS ---
  describe('AES-256-GCM Authenticated Encryption & Integrity Verification', () => {
    const key = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex'); // 32 bytes
    const plaintext = 'AMARACUS Production Cryptographic Payload';
    const aad = 'Tenant:Org_123,Env:Production';

    it('performs round-trip encryption and authenticated decryption', async () => {
      const envelope = await cryptoEngine.encrypt({
        algorithm: 'AES-256-GCM',
        key,
        plaintext,
        aad,
      });

      expect(envelope.v).toBe(CURRENT_ENVELOPE_VERSION);
      expect(envelope.alg).toBe('AES-256-GCM');
      expect(envelope.iv).toBeDefined();
      expect(envelope.ct).toBeDefined();
      expect(envelope.tag).toBeDefined();
      expect(envelope.aad).toBeDefined();

      const decrypted = await cryptoEngine.decrypt({
        envelope,
        key,
      });

      expect(decrypted).toBe(plaintext);
    });

    it('generates unique nonces for repeated encryptions with identical plaintext', async () => {
      const e1 = await cryptoEngine.encrypt({ algorithm: 'AES-256-GCM', key, plaintext });
      const e2 = await cryptoEngine.encrypt({ algorithm: 'AES-256-GCM', key, plaintext });

      expect(e1.iv).not.toBe(e2.iv);
      expect(e1.ct).not.toBe(e2.ct);
    });

    it('fails decryption when ciphertext is tampered', async () => {
      const envelope = await cryptoEngine.encrypt({ algorithm: 'AES-256-GCM', key, plaintext, aad });
      // Mutate ciphertext
      const tamperedCt = Buffer.from(envelope.ct, 'base64url');
      tamperedCt[0] ^= 0xff;
      envelope.ct = tamperedCt.toString('base64url');

      await expect(cryptoEngine.decrypt({ envelope, key })).rejects.toThrow('Decryption failed');
    });

    it('fails decryption when authentication tag is tampered', async () => {
      const envelope = await cryptoEngine.encrypt({ algorithm: 'AES-256-GCM', key, plaintext, aad });
      const tamperedTag = Buffer.from(envelope.tag, 'base64url');
      tamperedTag[0] ^= 0x01;
      envelope.tag = tamperedTag.toString('base64url');

      await expect(cryptoEngine.decrypt({ envelope, key })).rejects.toThrow('Decryption failed');
    });

    it('fails decryption when AAD is tampered or omitted', async () => {
      const envelope = await cryptoEngine.encrypt({ algorithm: 'AES-256-GCM', key, plaintext, aad });
      // Tamper AAD
      envelope.aad = Buffer.from('Tenant:Org_ATTACKER').toString('base64url');

      await expect(cryptoEngine.decrypt({ envelope, key })).rejects.toThrow('Decryption failed');
    });

    it('fails decryption with wrong key', async () => {
      const envelope = await cryptoEngine.encrypt({ algorithm: 'AES-256-GCM', key, plaintext });
      const wrongKey = Buffer.from('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'hex');

      await expect(cryptoEngine.decrypt({ envelope, key: wrongKey })).rejects.toThrow('Decryption failed');
    });

    it('rejects invalid key length (must be exactly 32 bytes)', async () => {
      const shortKey = Buffer.from('0123456789', 'hex');
      await expect(cryptoEngine.encrypt({ algorithm: 'AES-256-GCM', key: shortKey, plaintext })).rejects.toThrow(
        'requires exactly 32 bytes'
      );
    });
  });

  // --- 5. DIGITAL SIGNATURES (ED25519) ---
  describe('Ed25519 Digital Signatures', () => {
    it('signs and verifies messages with real Ed25519 keypair', async () => {
      const { publicKey, privateKey } = await cryptoEngine.generateKeyPair('ED25519');
      const message = 'Authorize Cryptographic Key Rotation for Environment Production';

      const res = await cryptoEngine.sign({
        algorithm: 'ED25519',
        privateKey,
        message,
      });

      expect(res.signature).toBeDefined();
      expect(res.algorithm).toBe('ED25519');

      const isValid = await cryptoEngine.verify({
        algorithm: 'ED25519',
        publicKey,
        message,
        signature: res.signature,
      });
      expect(isValid).toBe(true);
    });

    it('rejects tampered message with Ed25519 signature', async () => {
      const { publicKey, privateKey } = await cryptoEngine.generateKeyPair('ED25519');
      const message = 'Legitimate Message';

      const res = await cryptoEngine.sign({ algorithm: 'ED25519', privateKey, message });

      const isValid = await cryptoEngine.verify({
        algorithm: 'ED25519',
        publicKey,
        message: 'Tampered Message',
        signature: res.signature,
      });
      expect(isValid).toBe(false);
    });

    it('rejects signature verified with wrong public key', async () => {
      const kp1 = await cryptoEngine.generateKeyPair('ED25519');
      const kp2 = await cryptoEngine.generateKeyPair('ED25519');
      const message = 'Payload';

      const res = await cryptoEngine.sign({ algorithm: 'ED25519', privateKey: kp1.privateKey, message });

      const isValid = await cryptoEngine.verify({
        algorithm: 'ED25519',
        publicKey: kp2.publicKey,
        message,
        signature: res.signature,
      });
      expect(isValid).toBe(false);
    });

    it('handles malformed signature without crashing', async () => {
      const { publicKey } = await cryptoEngine.generateKeyPair('ED25519');
      const isValid = await cryptoEngine.verify({
        algorithm: 'ED25519',
        publicKey,
        message: 'test',
        signature: '1234abcd', // Invalid length
      });
      expect(isValid).toBe(false);
    });
  });

  // --- 6. KEY AGREEMENT (X25519) ---
  describe('X25519 Diffie-Hellman Key Agreement', () => {
    it('derives identical shared secret between Alice and Bob', async () => {
      const alice = await cryptoEngine.generateKeyPair('X25519');
      const bob = await cryptoEngine.generateKeyPair('X25519');

      // Alice derives secret using Bob's public key
      const aliceSecret = await cryptoEngine.keyAgreement({
        algorithm: 'X25519',
        privateKey: alice.privateKey,
        publicKey: bob.publicKey,
      });

      // Bob derives secret using Alice's public key
      const bobSecret = await cryptoEngine.keyAgreement({
        algorithm: 'X25519',
        privateKey: bob.privateKey,
        publicKey: alice.publicKey,
      });

      expect(aliceSecret.sharedSecret).toBe(bobSecret.sharedSecret);
      expect(aliceSecret.sharedSecret.length).toBe(64); // 32 bytes hex encoded = 64 characters
    });
  });

  // --- 7. CRYPTO POLICIES ---
  describe('Crypto Policy Engine', () => {
    it('enforces DEFAULT_SECURE policy', () => {
      expect(() =>
        CryptoPolicyEngine.validateOperation('DEFAULT_SECURE', 'SHA-256', 'hash')
      ).not.toThrow();

      expect(() =>
        CryptoPolicyEngine.validateOperation('DEFAULT_SECURE', 'AES-256-GCM', 'encrypt')
      ).not.toThrow();

      // Experimental algorithm rejected in production policy
      expect(() =>
        CryptoPolicyEngine.validateOperation('DEFAULT_SECURE', 'ML-KEM-768', 'key_agreement')
      ).toThrow('prohibited under active cryptographic policy');
    });

    it('allows experimental algorithms under PERMISSIVE_DEV policy', () => {
      expect(() =>
        CryptoPolicyEngine.validateOperation('PERMISSIVE_DEV', 'ML-KEM-768', 'key_agreement')
      ).not.toThrow();
    });
  });

  // --- 8. CSPRNG RANDOMNESS ---
  describe('Secure Randomness (CSPRNG)', () => {
    it('generates cryptographically secure random bytes of specified length', () => {
      const r1 = cryptoEngine.randomBytes(32, 'hex');
      const r2 = cryptoEngine.randomBytes(32, 'hex');

      expect(r1.length).toBe(32);
      expect(r1.random.length).toBe(64);
      expect(r1.random).not.toBe(r2.random);
    });

    it('rejects invalid lengths', () => {
      expect(() => cryptoEngine.randomBytes(0)).toThrow('between 1 and 65536');
      expect(() => cryptoEngine.randomBytes(100000)).toThrow('between 1 and 65536');
    });
  });
});
