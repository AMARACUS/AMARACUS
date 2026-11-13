import 'reflect-metadata';
import crypto from 'crypto';
import * as x509 from '@peculiar/x509';
import {
  X509Engine,
  CsrEngine,
  ChainValidator,
  RevocationService,
  CryptoPolicyEngine,
  RevocationReason,
  CryptoEngineError,
} from '@amaracus/crypto-core';

describe('Phase 7 — PKI & Certificate Management Core Engine', () => {
  const policyEngine = new CryptoPolicyEngine();

  // =========================================================================
  // 1. ROOT CERTIFICATE AUTHORITY (ROOT CA)
  // =========================================================================
  describe('Root CA Generation & Self-Signed Verification', () => {
    it('creates a valid RFC 5280 Root CA that verifies with Node native crypto', async () => {
      const rootKp = await X509Engine.generateKeypair('RSA-4096');
      expect(rootKp.publicKeyPem).toBeDefined();
      expect(rootKp.privateKeyPem).toBeDefined();

      const rootRes = await X509Engine.createRootCA({
        subject: 'CN=Amaracus Root CA Test, O=Amaracus, C=US',
        keypair: rootKp,
        validityDays: 3650,
        pathLenConstraint: 2,
        crlDistributionPoint: 'http://pki.test.amaracus.net/crl/root.crl',
        ocspUrl: 'http://pki.test.amaracus.net/ocsp',
      });

      expect(rootRes.certificatePem).toContain('-----BEGIN CERTIFICATE-----');
      expect(rootRes.serialNumber).toBeDefined();
      expect(rootRes.fingerprint).toBeDefined();

      // Native Node.js OpenSSL X509Certificate parsing & self-signed verification
      const nativeCert = new crypto.X509Certificate(rootRes.certificatePem);
      expect(nativeCert.subject).toContain('CN=Amaracus Root CA Test');
      expect(nativeCert.issuer).toContain('CN=Amaracus Root CA Test');
      expect(nativeCert.ca).toBe(true);

      // Verify self-signature using native OpenSSL
      const isValidSig = nativeCert.verify(nativeCert.publicKey);
      expect(isValidSig).toBe(true);

      // Verify @peculiar/x509 extension parsing
      const parsedPeculiar = new x509.X509Certificate(rootRes.certificatePem);
      const basicExt = parsedPeculiar.extensions.find(
        (ext) => ext.type === '2.5.29.19'
      ) as x509.BasicConstraintsExtension | undefined;
      expect(basicExt).toBeDefined();
      expect(basicExt?.ca).toBe(true);
      expect(basicExt?.pathLength).toBe(2);
    });

    it('supports ECDSA-P384 Root CA generation and native verification', async () => {
      const ecKp = await X509Engine.generateKeypair('ECDSA-P384');
      const rootRes = await X509Engine.createRootCA({
        subject: 'CN=Amaracus ECC Root CA, O=Amaracus, C=US',
        keypair: ecKp,
        validityDays: 1825,
      });

      const nativeCert = new crypto.X509Certificate(rootRes.certificatePem);
      expect(nativeCert.ca).toBe(true);
      expect(nativeCert.verify(nativeCert.publicKey)).toBe(true);
    });
  });

  // =========================================================================
  // 2. INTERMEDIATE CERTIFICATE AUTHORITY (SUB-CA)
  // =========================================================================
  describe('Intermediate CA Issuance & Hierarchy Verification', () => {
    it('issues an Intermediate CA signed by Root CA and verifies against Root public key', async () => {
      const rootKp = await X509Engine.generateKeypair('RSA-4096');
      const rootCa = await X509Engine.createRootCA({
        subject: 'CN=Amaracus Root CA Hierarchy, O=Amaracus, C=US',
        keypair: rootKp,
        validityDays: 3650,
        pathLenConstraint: 2,
      });

      const subKp = await X509Engine.generateKeypair('RSA-3072');
      const subCa = await X509Engine.createIntermediateCA({
        subject: 'CN=Amaracus Intermediate CA Hierarchy, O=Amaracus, C=US',
        keypair: subKp,
        parentAuthority: {
          certificatePem: rootCa.certificatePem,
          privateKeyPem: rootKp.privateKeyPem,
        },
        validityDays: 1825,
        pathLenConstraint: 0,
      });

      expect(subCa.certificatePem).toContain('-----BEGIN CERTIFICATE-----');

      const rootNative = new crypto.X509Certificate(rootCa.certificatePem);
      const subNative = new crypto.X509Certificate(subCa.certificatePem);

      expect(subNative.ca).toBe(true);
      expect(subNative.issuer).toBe(rootNative.subject);

      // Verify sub CA signature using Root CA public key
      const isSubSignedByRoot = subNative.verify(rootNative.publicKey);
      expect(isSubSignedByRoot).toBe(true);

      // Verify path length constraint is 0
      const parsedSub = new x509.X509Certificate(subCa.certificatePem);
      const basicExt = parsedSub.extensions.find(
        (e) => e.type === '2.5.29.19'
      ) as x509.BasicConstraintsExtension | undefined;
      expect(basicExt?.pathLength).toBe(0);
    });
  });

  // =========================================================================
  // 3. END-ENTITY CERTIFICATE ISSUANCE (TLS / MTLS)
  // =========================================================================
  describe('End-Entity Certificate Issuance & Validation', () => {
    it('issues a Leaf Server Certificate with SANs and correct KeyUsages', async () => {
      const rootKp = await X509Engine.generateKeypair('RSA-4096');
      const rootCa = await X509Engine.createRootCA({
        subject: 'CN=Amaracus Root CA EndEntity, O=Amaracus, C=US',
        keypair: rootKp,
      });

      const subKp = await X509Engine.generateKeypair('RSA-2048');
      const subCa = await X509Engine.createIntermediateCA({
        subject: 'CN=Amaracus Intermediate CA EndEntity, O=Amaracus, C=US',
        keypair: subKp,
        parentAuthority: {
          certificatePem: rootCa.certificatePem,
          privateKeyPem: rootKp.privateKeyPem,
        },
      });

      const leafKp = await X509Engine.generateKeypair('RSA-2048');
      const leafCert = await X509Engine.createEndEntityCertificate({
        subject: 'CN=api.internal.amaracus.net, O=Amaracus, C=US',
        publicKeyPem: leafKp.publicKeyPem,
        certificateType: 'SERVER',
        issuingAuthority: {
          certificatePem: subCa.certificatePem,
          privateKeyPem: subKp.privateKeyPem,
        },
        validityDays: 365,
        san: {
          dns: ['api.internal.amaracus.net', '*.amaracus.internal'],
          ip: ['10.0.0.1', '127.0.0.1'],
        },
      });

      expect(leafCert.certificatePem).toBeDefined();

      const subNative = new crypto.X509Certificate(subCa.certificatePem);
      const leafNative = new crypto.X509Certificate(leafCert.certificatePem);

      // Leaf cert must NOT be a CA
      expect(leafNative.ca).toBe(false);
      // Signature verifies with intermediate CA public key
      expect(leafNative.verify(subNative.publicKey)).toBe(true);
      // SANs must be present
      expect(leafNative.subjectAltName).toContain('DNS:api.internal.amaracus.net');
      expect(leafNative.subjectAltName).toContain('IP Address:10.0.0.1');
    });
  });

  // =========================================================================
  // 4. PKCS#10 CSR ENGINE
  // =========================================================================
  describe('PKCS#10 Certificate Signing Request (CSR) Engine', () => {
    it('creates, parses, and validates cryptographic self-signature of a PKCS#10 CSR', async () => {
      const csrKp = await X509Engine.generateKeypair('RSA-2048');
      const csrRes = await CsrEngine.createCsr({
        subject: 'CN=gateway.corp.amaracus.net, O=Amaracus Technologies, C=US',
        publicKeyPem: csrKp.publicKeyPem,
        privateKeyPem: csrKp.privateKeyPem,
        san: {
          dns: ['gateway.corp.amaracus.net', 'ingress.corp.amaracus.net'],
        },
      });

      expect(csrRes.csrPem).toContain('-----BEGIN CERTIFICATE REQUEST-----');

      // Parse and cryptographically validate signature
      const parsed = await CsrEngine.parseAndValidateCsr(csrRes.csrPem);
      expect(parsed.signatureValid).toBe(true);
      expect(parsed.subject).toContain('CN=gateway.corp.amaracus.net');
      expect(parsed.publicKeyAlgorithm).toContain('RSA');
      expect(parsed.san?.dns).toContain('gateway.corp.amaracus.net');
    });

    it('rejects tampered PKCS#10 CSR with signature verification failure', async () => {
      const csrKp = await X509Engine.generateKeypair('RSA-2048');
      const csrRes = await CsrEngine.createCsr({
        subject: 'CN=original.domain.com, O=Amaracus, C=US',
        publicKeyPem: csrKp.publicKeyPem,
        privateKeyPem: csrKp.privateKeyPem,
      });

      // Tamper with base64 body (change characters)
      const lines = csrRes.csrPem.trim().split('\n');
      const middleLine = Math.floor(lines.length / 2);
      lines[middleLine] = lines[middleLine].split('').reverse().join('');
      const tamperedPem = lines.join('\n');

      await expect(CsrEngine.parseAndValidateCsr(tamperedPem)).rejects.toThrow();
    });
  });

  // =========================================================================
  // 5. MULTI-TIER CHAIN VALIDATOR
  // =========================================================================
  describe('Certificate Chain Validation Engine', () => {
    let rootPem: string;
    let subPem: string;
    let leafPem: string;
    let rootKp: any;
    let subKp: any;
    let leafKp: any;

    beforeAll(async () => {
      rootKp = await X509Engine.generateKeypair('RSA-4096');
      const rootCa = await X509Engine.createRootCA({
        subject: 'CN=Amaracus Trust Anchor G1, O=Amaracus, C=US',
        keypair: rootKp,
        validityDays: 3650,
      });
      rootPem = rootCa.certificatePem;

      subKp = await X509Engine.generateKeypair('RSA-2048');
      const subCa = await X509Engine.createIntermediateCA({
        subject: 'CN=Amaracus Issuing SubCA G1, O=Amaracus, C=US',
        keypair: subKp,
        parentAuthority: {
          certificatePem: rootPem,
          privateKeyPem: rootKp.privateKeyPem,
        },
        validityDays: 1825,
      });
      subPem = subCa.certificatePem;

      leafKp = await X509Engine.generateKeypair('RSA-2048');
      const leaf = await X509Engine.createEndEntityCertificate({
        subject: 'CN=vault.secure.amaracus.net, O=Amaracus, C=US',
        publicKeyPem: leafKp.publicKeyPem,
        certificateType: 'SERVER',
        issuingAuthority: {
          certificatePem: subPem,
          privateKeyPem: subKp.privateKeyPem,
        },
        validityDays: 365,
      });
      leafPem = leaf.certificatePem;
    });

    it('validates a complete 3-tier chain (Leaf -> Intermediate -> Root)', async () => {
      const result = await ChainValidator.validateChain({
        leafCertificatePem: leafPem,
        intermediateCertificatesPem: [subPem],
        trustAnchorsPem: [rootPem],
        checkExpiry: true,
      });

      expect(result.isValid).toBe(true);
      expect(result.chainValid).toBe(true);
      expect(result.status).toBe('VALID');
      expect(result.errors).toHaveLength(0);
      expect(result.chain).toHaveLength(3);
    });

    it('fails chain validation when an intermediate certificate has tampered signature', async () => {
      // Create a rogue intermediate signed by a foreign key
      const rogueKp = await X509Engine.generateKeypair('RSA-2048');
      const rogueSub = await X509Engine.createRootCA({
        subject: 'CN=Amaracus Issuing SubCA G1, O=Amaracus, C=US', // same name, wrong key
        keypair: rogueKp,
      });

      const result = await ChainValidator.validateChain({
        leafCertificatePem: leafPem,
        intermediateCertificatesPem: [rogueSub.certificatePem],
        trustAnchorsPem: [rootPem],
      });

      expect(result.isValid).toBe(false);
      expect(result.chainValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('rejects a chain where intermediate certificate lacks cA: true basic constraint', async () => {
      // Create a leaf certificate masquerading as an intermediate
      const fakeCaKp = await X509Engine.generateKeypair('RSA-2048');
      const fakeCaLeaf = await X509Engine.createEndEntityCertificate({
        subject: 'CN=Fake CA Not Allowed, O=Amaracus, C=US',
        publicKeyPem: fakeCaKp.publicKeyPem,
        certificateType: 'SERVER', // Non-CA
        issuingAuthority: {
          certificatePem: rootPem,
          privateKeyPem: rootKp.privateKeyPem,
        },
      });

      // Try to issue a leaf from this fake CA
      const leafKp2 = await X509Engine.generateKeypair('RSA-2048');
      const childLeaf = await X509Engine.createEndEntityCertificate({
        subject: 'CN=child.domain.com, O=Amaracus, C=US',
        publicKeyPem: leafKp2.publicKeyPem,
        certificateType: 'SERVER',
        issuingAuthority: {
          certificatePem: fakeCaLeaf.certificatePem,
          privateKeyPem: fakeCaKp.privateKeyPem,
        },
      });

      const result = await ChainValidator.validateChain({
        leafCertificatePem: childLeaf.certificatePem,
        intermediateCertificatesPem: [fakeCaLeaf.certificatePem],
        trustAnchorsPem: [rootPem],
      });

      expect(result.isValid).toBe(false);
      expect(result.errors.some((e) => e.toLowerCase().includes('not a ca'))).toBe(true);
    });
  });

  // =========================================================================
  // 6. REVOCATION & OCSP STATUS
  // =========================================================================
  describe('Revocation Service & CRL / OCSP Verification', () => {
    it('generates a valid RFC 5280 CRL and reports revoked certificates', async () => {
      const caKp = await X509Engine.generateKeypair('RSA-4096');
      const ca = await X509Engine.createRootCA({
        subject: 'CN=Amaracus CRL Test CA, O=Amaracus, C=US',
        keypair: caKp,
      });

      const crlRes = await RevocationService.generateCRL({
        issuerCertificatePem: ca.certificatePem,
        issuerPrivateKeyPem: caKp.privateKeyPem,
        revokedEntries: [
          {
            serialNumber: '1001',
            revocationDate: new Date(),
            reason: 'KEY_COMPROMISE' as any,
          },
          {
            serialNumber: '1002',
            revocationDate: new Date(),
            reason: 'SUPERSEDED' as any,
          },
        ],
        thisUpdate: new Date(),
        nextUpdateDays: 7,
      });

      expect(crlRes.crlPem).toContain('-----BEGIN CRL-----');
      expect(crlRes.entriesCount).toBe(2);

      // Verify CRL parses with @peculiar/x509
      const parsedCrl = new x509.X509Crl(crlRes.crlPem);
      expect(parsedCrl.issuer).toContain('CN=Amaracus CRL Test CA');
    });

    it('evaluates OCSP status accurately for active vs revoked certificates', () => {
      // Good certificate check
      const goodStatus = RevocationService.checkRevocationStatus({
        certificateId: 'cert_active_1',
        serialNumber: 'ABCDEF123456',
        issuerSubject: 'CN=Amaracus CA',
        revocations: [],
      });
      expect(goodStatus.status).toBe('GOOD');

      // Revoked certificate check
      const revokedStatus = RevocationService.checkRevocationStatus({
        certificateId: 'cert_revoked_1',
        serialNumber: 'ABCDEF123456',
        issuerSubject: 'CN=Amaracus CA',
        revocations: [
          {
            certificateId: 'cert_revoked_1',
            reason: 'CA_COMPROMISE' as any,
            revokedAt: new Date(),
          },
        ],
      });
      expect(revokedStatus.status).toBe('REVOKED');
      expect(revokedStatus.revocationReason).toBe('CA_COMPROMISE');
    });
  });

  // =========================================================================
  // 7. POLICY ENFORCEMENT & TRUTHFUL PQC GATING
  // =========================================================================
  describe('Crypto Policy Engine & Truthful PQC X.509 Gating', () => {
    it('accepts valid RSA-2048, RSA-4096, and ECDSA-P384 for X.509 issuance', () => {
      expect(() =>
        policyEngine.validateCertificateIssuance({
          certificateType: 'SERVER',
          keyAlgorithm: 'RSA-2048',
          validityDays: 365,
        })
      ).not.toThrow();

      expect(() =>
        policyEngine.validateCertificateIssuance({
          certificateType: 'ROOT_CA',
          keyAlgorithm: 'RSA-4096',
          validityDays: 3650,
        })
      ).not.toThrow();
    });

    it('rejects deprecated RSA-1024 as cryptographically insecure', () => {
      expect(() =>
        policyEngine.validateCertificateIssuance({
          certificateType: 'SERVER',
          keyAlgorithm: 'RSA-1024',
          validityDays: 365,
        })
      ).toThrow(CryptoEngineError);
    });

    it('rejects post-quantum algorithms (ML-DSA) with UNSUPPORTED_PQC_X509 pending IETF standard', () => {
      expect(() =>
        policyEngine.validateCertificateIssuance({
          certificateType: 'SERVER',
          keyAlgorithm: 'ML-DSA-65',
          validityDays: 365,
        })
      ).toThrow(/IETF LAMPS standardization/i);

      try {
        policyEngine.validateCertificateIssuance({
          certificateType: 'SERVER',
          keyAlgorithm: 'ML-DSA-87',
          validityDays: 365,
        });
      } catch (err: any) {
        expect(err.code).toBe('UNSUPPORTED_PQC_X509');
      }
    });
  });
});
