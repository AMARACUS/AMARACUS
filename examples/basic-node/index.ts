import {
  Amaracus,
  AmaracusError,
  AmaracusAuthenticationError,
  AmaracusValidationError,
  AmaracusNotFoundError,
} from '@amaracus/sdk';

async function main() {
  console.log('================================================================');
  console.log(' AMARACUS Developer Platform — Official SDK Quickstart');
  console.log('================================================================\n');

  const apiKey = process.env.AMARACUS_API_KEY || 'am_live_example_key_replace_with_yours';
  const baseUrl = process.env.AMARACUS_BASE_URL || 'http://localhost:4000';

  // 1. Initialize SDK Client
  const amaracus = new Amaracus({
    apiKey,
    baseUrl,
    timeout: 10000,
    maxRetries: 2,
  });

  try {
    // 2. Discover Platform Capabilities
    console.log('[1/7] Discovering AMARACUS Platform Capabilities...');
    const capabilities = await amaracus.capabilities.get();
    console.log(`  ✓ API Version: ${capabilities.version}`);
    console.log(`  ✓ Supported Operations: ${capabilities.supportedOperations.join(', ')}`);
    console.log(`  ✓ Zero-Secret-Leakage Guarantee: ${capabilities.features.zeroSecretLeakage}`);
    console.log(`  ✓ Billing Protection Active: ${capabilities.features.billingUsageProtection}\n`);

    // 3. Create a Managed Logical Encryption Key
    console.log('[2/7] Creating Managed Logical Symmetric Key...');
    const keyName = `app-payments-key-${Date.now()}`;
    const encryptionKey = await amaracus.keys.create({
      name: keyName,
      algorithm: 'AES-256-GCM',
      purpose: 'ENCRYPT_DECRYPT',
      description: 'Master key for protecting sensitive cardholder payloads',
    });
    console.log(`  ✓ Key Created: ${encryptionKey.id} (${encryptionKey.name})`);
    console.log(`  ✓ Algorithm: ${encryptionKey.algorithm} | Version: ${encryptionKey.currentVersion}\n`);

    // 4. Encrypt Plaintext with Managed Key
    console.log('[3/7] Encrypting Plaintext Payload...');
    const plaintext = 'Sensitive financial transaction: transfer $50,000 to Account #8812';
    const encrypted = await amaracus.encrypt({
      key: encryptionKey.id,
      data: plaintext,
      aad: 'tenant-org-corp-123',
    });
    console.log(`  ✓ Ciphertext: ${encrypted.ciphertext.substring(0, 32)}...`);
    console.log(`  ✓ IV: ${encrypted.iv} | Tag: ${encrypted.tag}`);
    console.log(`  ✓ Operation ID: ${encrypted.operationId}\n`);

    // 5. Decrypt Ciphertext Envelope
    console.log('[4/7] Decrypting Ciphertext Envelope...');
    const decrypted = await amaracus.decrypt({
      key: encryptionKey.id,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      tag: encrypted.tag,
      aad: 'tenant-org-corp-123',
    });
    console.log(`  ✓ Decrypted Plaintext: "${decrypted.plaintext}"`);
    console.log(`  ✓ Authenticity Verified: ${decrypted.plaintext === plaintext}\n`);

    // 6. Cryptographic Hashing (SHA-256)
    console.log('[5/7] Computing Cryptographic Hash...');
    const hashResult = await amaracus.hash({
      data: Buffer.from('Immutable audit ledger entry', 'utf-8'),
      algorithm: 'SHA-256',
    });
    console.log(`  ✓ SHA-256 Digest: ${hashResult.digest}`);
    console.log(`  ✓ Byte Length: ${hashResult.byteLength}\n`);

    // 7. Digital Signature (ED25519)
    console.log('[6/7] Creating Asymmetric Signing Key & Signing Document...');
    const signingKey = await amaracus.keys.create({
      name: `signer-${Date.now()}`,
      algorithm: 'ED25519',
      purpose: 'SIGN_VERIFY',
    });

    const docToSign = 'Official SLA Contract v1.0 between Amaracus and Developer';
    const signature = await amaracus.sign({
      key: signingKey.id,
      data: docToSign,
    });
    console.log(`  ✓ Signature: ${signature.signature.substring(0, 40)}...`);

    const verification = await amaracus.verify({
      key: signingKey.id,
      data: docToSign,
      signature: signature.signature,
    });
    console.log(`  ✓ Signature Valid: ${verification.valid}\n`);

    // 8. Key Lifecycle Rotation & Cleanup
    console.log('[7/7] Rotating & Cleaning Up Key...');
    const rotatedKey = await amaracus.keys.rotate(encryptionKey.id);
    console.log(`  ✓ Rotated Key to Version: ${rotatedKey.currentVersion}`);

    await amaracus.keys.delete(encryptionKey.id);
    await amaracus.keys.delete(signingKey.id);
    console.log('  ✓ Keys Safely Destroyed.\n');

    console.log('🎉 AMARACUS SDK Quickstart Completed Successfully!');
  } catch (err: unknown) {
    if (err instanceof AmaracusAuthenticationError) {
      console.error('❌ Authentication Error: Invalid or missing API key.');
      console.error(`   Request ID: ${err.requestId}`);
    } else if (err instanceof AmaracusValidationError) {
      console.error(`❌ Validation Error: ${err.message}`);
    } else if (err instanceof AmaracusNotFoundError) {
      console.error(`❌ Not Found: ${err.message}`);
    } else if (err instanceof AmaracusError) {
      console.error(`❌ AMARACUS Error [${err.code}]: ${err.message}`);
      console.error(`   Status: ${err.status} | Request ID: ${err.requestId}`);
    } else {
      console.error('❌ Unexpected Error:', err);
    }
  }
}

if (require.main === module) {
  main().catch(console.error);
}
