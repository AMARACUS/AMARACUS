import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import crypto from 'crypto';
import {
  CertificateType,
  CertificateStatus,
  IssueCertificateParams,
  CertificateValidationResult,
  SubjectNameParams,
  SubjectAlternativeNames,
  KeyUsageType,
  ExtendedKeyUsageType,
} from './types';
import { CryptoEngineError } from '../errors';

// Initialize WebCrypto provider for @peculiar/x509
if (crypto.webcrypto) {
  x509.cryptoProvider.set(crypto.webcrypto as any);
}

export class X509Engine {
  /**
   * Format a subject name from an object or string
   */
  static formatSubject(subject: SubjectNameParams | string): string {
    if (typeof subject === 'string') {
      return subject.trim();
    }
    const parts: string[] = [];
    if (subject.commonName) parts.push(`CN=${subject.commonName.trim()}`);
    if (subject.organization) parts.push(`O=${subject.organization.trim()}`);
    if (subject.organizationalUnit) parts.push(`OU=${subject.organizationalUnit.trim()}`);
    if (subject.country) parts.push(`C=${subject.country.trim()}`);
    if (subject.stateOrProvince) parts.push(`ST=${subject.stateOrProvince.trim()}`);
    if (subject.locality) parts.push(`L=${subject.locality.trim()}`);
    return parts.join(', ');
  }

  /**
   * Generate a random 16-byte hex serial number (positive integer per RFC 5280)
   */
  static generateSerialNumber(): string {
    const bytes = crypto.randomBytes(16);
    // Ensure the first bit is 0 so serial is always positive
    bytes[0] &= 0x7f;
    if (bytes[0] === 0x00) bytes[0] = 0x01;
    return bytes.toString('hex').toLowerCase();
  }

  /**
   * Compute SHA-256 and SHA-1 fingerprints from a certificate PEM
   */
  static calculateFingerprint(certPem: string): { sha256: string; sha1: string } {
    const cert = new crypto.X509Certificate(certPem);
    const sha256 = cert.fingerprint256.replace(/:/g, '').toLowerCase();
    const sha1 = cert.fingerprint.replace(/:/g, '').toLowerCase();
    return { sha256, sha1 };
  }

  /**
   * Generate an asymmetric keypair suitable for PKI certificates
   */
  static async generateKeypair(algorithm: string = 'RSA-2048'): Promise<{
    publicKeyPem: string;
    privateKeyPem: string;
    keyAlgorithm: string;
    publicKeySpkiHex: string;
  }> {
    const algUpper = algorithm.toUpperCase();

    if (algUpper.startsWith('RSA')) {
      const modulusLength = algUpper.includes('4096')
        ? 4096
        : algUpper.includes('3072')
        ? 3072
        : 2048;

      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const spkiDer = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });

      return {
        publicKeyPem: publicKey,
        privateKeyPem: privateKey,
        keyAlgorithm: `RSA-${modulusLength}`,
        publicKeySpkiHex: spkiDer.toString('hex'),
      };
    }

    if (algUpper.includes('ECDSA') || algUpper.startsWith('EC') || algUpper.includes('P-') || algUpper.includes('P256') || algUpper.includes('P384')) {
      const namedCurve = algUpper.includes('384')
        ? 'secp384r1'
        : algUpper.includes('521')
        ? 'secp521r1'
        : 'prime256v1';

      const keyName = algUpper.includes('384')
        ? 'ECDSA-P384'
        : algUpper.includes('521')
        ? 'ECDSA-P521'
        : 'ECDSA-P256';

      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const spkiDer = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });

      return {
        publicKeyPem: publicKey,
        privateKeyPem: privateKey,
        keyAlgorithm: keyName,
        publicKeySpkiHex: spkiDer.toString('hex'),
      };
    }

    if (algUpper === 'ED25519') {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const spkiDer = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });

      return {
        publicKeyPem: publicKey,
        privateKeyPem: privateKey,
        keyAlgorithm: 'ED25519',
        publicKeySpkiHex: spkiDer.toString('hex'),
      };
    }

    throw new CryptoEngineError(
      'UNSUPPORTED_ALGORITHM',
      `Unsupported key algorithm for PKI: '${algorithm}'. Supported: RSA-2048, RSA-3072, RSA-4096, ECDSA-P256, ECDSA-P384, ED25519.`
    );
  }

  /**
   * Import a PEM key into WebCrypto CryptoKey
   */
  private static async importWebCryptoKey(
    keyPem: string,
    type: 'public' | 'private',
    keyAlg: string
  ): Promise<CryptoKey> {
    if (!crypto.webcrypto?.subtle) {
      throw new CryptoEngineError('INTERNAL_CRYPTO_ERROR', 'WebCrypto subtle is not available in current Node environment.');
    }

    const algUpper = keyAlg.toUpperCase();
    let importAlgorithm: any;
    let keyUsages: KeyUsage[];

    if (algUpper.startsWith('RSA')) {
      importAlgorithm = {
        name: 'RSASSA-PKCS1-v1_5',
        hash: algUpper.includes('384') ? 'SHA-384' : 'SHA-256',
      };
      keyUsages = type === 'public' ? ['verify'] : ['sign'];
    } else if (algUpper.startsWith('EC') || algUpper.includes('P-') || algUpper.includes('P256') || algUpper.includes('P384')) {
      importAlgorithm = {
        name: 'ECDSA',
        namedCurve: algUpper.includes('384') ? 'P-384' : 'P-256',
      };
      keyUsages = type === 'public' ? ['verify'] : ['sign'];
    } else if (algUpper === 'ED25519') {
      importAlgorithm = { name: 'Ed25519' };
      keyUsages = type === 'public' ? ['verify'] : ['sign'];
    } else {
      importAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      keyUsages = type === 'public' ? ['verify'] : ['sign'];
    }

    if (type === 'public') {
      const keyObj = crypto.createPublicKey(keyPem);
      const der = keyObj.export({ type: 'spki', format: 'der' });
      return await crypto.webcrypto.subtle.importKey('spki', der, importAlgorithm, true, keyUsages);
    } else {
      const keyObj = crypto.createPrivateKey(keyPem);
      const der = keyObj.export({ type: 'pkcs8', format: 'der' });
      return await crypto.webcrypto.subtle.importKey('pkcs8', der, importAlgorithm, true, keyUsages);
    }
  }

  /**
   * Determine signing algorithm object from key algorithm
   */
  private static getSigningAlgorithm(keyAlg: string): any {
    const algUpper = keyAlg.toUpperCase();
    if (algUpper.startsWith('RSA')) {
      return {
        name: 'RSASSA-PKCS1-v1_5',
        hash: algUpper.includes('384') ? 'SHA-384' : 'SHA-256',
      };
    }
    if (algUpper.startsWith('EC') || algUpper.includes('P-') || algUpper.includes('P256') || algUpper.includes('P384')) {
      return {
        name: 'ECDSA',
        hash: algUpper.includes('384') ? 'SHA-384' : 'SHA-256',
      };
    }
    if (algUpper === 'ED25519') {
      return { name: 'Ed25519' };
    }
    return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  }

  /**
   * Determine key algorithm name from public key PEM
   */
  static inspectKeyAlgorithm(publicKeyPem: string): string {
    try {
      const keyObj = crypto.createPublicKey(publicKeyPem);
      if (keyObj.asymmetricKeyType === 'rsa') {
        const details = keyObj.asymmetricKeyDetails;
        const bits = details?.modulusLength || 2048;
        return `RSA-${bits}`;
      }
      if (keyObj.asymmetricKeyType === 'ec') {
        const details = keyObj.asymmetricKeyDetails;
        if (details?.namedCurve === 'secp384r1' || details?.namedCurve === 'P-384') return 'ECDSA-P384';
        return 'ECDSA-P256';
      }
      if (keyObj.asymmetricKeyType === 'ed25519') {
        return 'ED25519';
      }
      return keyObj.asymmetricKeyType?.toUpperCase() || 'RSA-2048';
    } catch {
      return 'RSA-2048';
    }
  }

  /**
   * Create a self-signed Root Certificate Authority (Root CA)
   */
  static async createRootCertificate(params: {
    subject: SubjectNameParams | string;
    publicKeyPem?: string;
    privateKeyPem?: string;
    keypair?: { publicKeyPem: string; privateKeyPem: string };
    validityDays?: number;
    serialNumber?: string;
    pathLenConstraint?: number;
    crlDistributionPoint?: string;
    ocspUrl?: string;
  }): Promise<{
    certificatePem: string;
    serialNumber: string;
    fingerprint: string;
    notBefore: Date;
    notAfter: Date;
  }> {
    const formattedSubject = this.formatSubject(params.subject);
    const publicKeyPem = params.publicKeyPem || params.keypair?.publicKeyPem;
    const privateKeyPem = params.privateKeyPem || params.keypair?.privateKeyPem;

    if (!publicKeyPem || !privateKeyPem) {
      throw new CryptoEngineError(
        'INVALID_INPUT',
        'Creating a Root CA requires publicKeyPem and privateKeyPem (or keypair).'
      );
    }

    const keyAlg = this.inspectKeyAlgorithm(publicKeyPem);
    const signingAlg = this.getSigningAlgorithm(keyAlg);

    const publicKey = await this.importWebCryptoKey(publicKeyPem, 'public', keyAlg);
    const privateKey = await this.importWebCryptoKey(privateKeyPem, 'private', keyAlg);

    const serialNumber = params.serialNumber || this.generateSerialNumber();
    const notBefore = new Date();
    // Default 10 years for Root CA
    const validityDays = params.validityDays || 3650;
    const notAfter = new Date(notBefore.getTime() + validityDays * 24 * 3600 * 1000);

    const extensions: x509.Extension[] = [
      new x509.BasicConstraintsExtension(true, params.pathLenConstraint ?? 1, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign | x509.KeyUsageFlags.digitalSignature,
        true
      ),
      await x509.SubjectKeyIdentifierExtension.create(publicKey),
    ];

    if (params.crlDistributionPoint) {
      extensions.push(
        new x509.CRLDistributionPointsExtension([params.crlDistributionPoint])
      );
    }

    const cert = await x509.X509CertificateGenerator.create({
      serialNumber,
      subject: formattedSubject,
      issuer: formattedSubject, // Root CA is self-issued
      notBefore,
      notAfter,
      signingAlgorithm: signingAlg,
      publicKey,
      signingKey: privateKey,
      extensions,
    });

    const certificatePem = cert.toString('pem');
    const { sha256 } = this.calculateFingerprint(certificatePem);

    // Verify generated certificate with native OpenSSL
    const nativeCert = new crypto.X509Certificate(certificatePem);
    if (!nativeCert.verify(nativeCert.publicKey)) {
      throw new CryptoEngineError('INTERNAL_CRYPTO_ERROR', 'Root CA self-verification failed.');
    }

    return {
      certificatePem,
      serialNumber,
      fingerprint: sha256,
      notBefore,
      notAfter,
    };
  }

  /**
   * Create an Intermediate Certificate Authority signed by a Parent CA
   */
  static async createIntermediateCertificate(params: {
    subject: SubjectNameParams | string;
    issuerCertificatePem?: string;
    issuerPrivateKeyPem?: string;
    publicKeyPem?: string;
    keypair?: { publicKeyPem: string; privateKeyPem: string };
    parentAuthority?: { certificatePem: string; privateKeyPem: string };
    validityDays?: number;
    serialNumber?: string;
    pathLenConstraint?: number;
    crlDistributionPoint?: string;
    ocspUrl?: string;
  }): Promise<{
    certificatePem: string;
    serialNumber: string;
    fingerprint: string;
    notBefore: Date;
    notAfter: Date;
    chainPem: string;
  }> {
    const formattedSubject = this.formatSubject(params.subject);
    const publicKeyPem = params.publicKeyPem || params.keypair?.publicKeyPem;
    const issuerCertificatePem = params.issuerCertificatePem || params.parentAuthority?.certificatePem;
    const issuerPrivateKeyPem = params.issuerPrivateKeyPem || params.parentAuthority?.privateKeyPem;

    if (!publicKeyPem || !issuerCertificatePem || !issuerPrivateKeyPem) {
      throw new CryptoEngineError(
        'INVALID_INPUT',
        'Creating an Intermediate CA requires publicKeyPem, issuerCertificatePem, and issuerPrivateKeyPem.'
      );
    }

    const issuerCert = new x509.X509Certificate(issuerCertificatePem);
    const issuerSubject = issuerCert.subject;

    const subjectKeyAlg = this.inspectKeyAlgorithm(publicKeyPem);
    const issuerKeyAlg = this.inspectKeyAlgorithm(issuerCert.publicKey.toString('pem'));
    const signingAlg = this.getSigningAlgorithm(issuerKeyAlg);

    const publicKey = await this.importWebCryptoKey(publicKeyPem, 'public', subjectKeyAlg);
    const issuerPrivateKey = await this.importWebCryptoKey(issuerPrivateKeyPem, 'private', issuerKeyAlg);

    const serialNumber = params.serialNumber || this.generateSerialNumber();
    const notBefore = new Date();
    // Default 5 years for Intermediate CA
    const validityDays = params.validityDays || 1825;
    const notAfter = new Date(notBefore.getTime() + validityDays * 24 * 3600 * 1000);

    const extensions: x509.Extension[] = [
      new x509.BasicConstraintsExtension(true, params.pathLenConstraint ?? 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign | x509.KeyUsageFlags.digitalSignature,
        true
      ),
      await x509.SubjectKeyIdentifierExtension.create(publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(issuerCert.publicKey),
    ];

    if (params.crlDistributionPoint) {
      extensions.push(
        new x509.CRLDistributionPointsExtension([params.crlDistributionPoint])
      );
    }

    const cert = await x509.X509CertificateGenerator.create({
      serialNumber,
      subject: formattedSubject,
      issuer: issuerSubject,
      notBefore,
      notAfter,
      signingAlgorithm: signingAlg,
      publicKey,
      signingKey: issuerPrivateKey,
      extensions,
    });

    const certificatePem = cert.toString('pem');
    const { sha256 } = this.calculateFingerprint(certificatePem);

    // Verify intermediate signature using parent public key
    const nativeIntermediate = new crypto.X509Certificate(certificatePem);
    const nativeIssuer = new crypto.X509Certificate(issuerCertificatePem);
    if (!nativeIntermediate.verify(nativeIssuer.publicKey)) {
      throw new CryptoEngineError('INTERNAL_CRYPTO_ERROR', 'Intermediate CA signature verification against issuer failed.');
    }

    const chainPem = `${certificatePem.trim()}\n${issuerCertificatePem.trim()}`;

    return {
      certificatePem,
      serialNumber,
      fingerprint: sha256,
      notBefore,
      notAfter,
      chainPem,
    };
  }

  /**
   * Issue an End-Entity Certificate (SERVER, CLIENT, CODE_SIGNING, etc.)
   */
  static async issueEndEntityCertificate(params: IssueCertificateParams): Promise<{
    certificatePem: string;
    serialNumber: string;
    fingerprint: string;
    notBefore: Date;
    notAfter: Date;
    chainPem: string;
  }> {
    const issuerCertificatePem = params.issuerCertificatePem || (params as any).issuingAuthority?.certificatePem;
    const signingPrivateKeyPem = params.signingPrivateKeyPem || (params as any).issuingAuthority?.privateKeyPem;
    const certType = params.type || (params as any).certificateType || 'SERVER';

    if (!issuerCertificatePem || !signingPrivateKeyPem) {
      throw new CryptoEngineError(
        'INVALID_INPUT',
        'Issuing an end-entity certificate requires issuerCertificatePem and signingPrivateKeyPem.'
      );
    }

    const formattedSubject = this.formatSubject(params.subject);
    const issuerCert = new x509.X509Certificate(issuerCertificatePem);
    const issuerSubject = issuerCert.subject;

    const subjectKeyAlg = this.inspectKeyAlgorithm(params.publicKeyPem);
    const issuerKeyAlg = this.inspectKeyAlgorithm(issuerCert.publicKey.toString('pem'));
    const signingAlg = this.getSigningAlgorithm(issuerKeyAlg);

    const publicKey = await this.importWebCryptoKey(params.publicKeyPem, 'public', subjectKeyAlg);
    const issuerPrivateKey = await this.importWebCryptoKey(signingPrivateKeyPem, 'private', issuerKeyAlg);

    const serialNumber = params.serialNumber || this.generateSerialNumber();
    const notBefore = new Date();
    // Default 397 days (standard maximum for TLS certificates per CA/B forum)
    const validityDays = params.validityDays || 397;
    const notAfter = new Date(notBefore.getTime() + validityDays * 24 * 3600 * 1000);

    // Resolve Key Usages based on CertificateType or explicit params
    const keyUsageFlags = this.resolveKeyUsages(certType, params.keyUsage);
    const ekuOids = this.resolveExtendedKeyUsages(certType, params.extendedKeyUsage);

    const extensions: x509.Extension[] = [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(keyUsageFlags, true),
      await x509.SubjectKeyIdentifierExtension.create(publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(issuerCert.publicKey),
    ];

    if (ekuOids.length > 0) {
      extensions.push(new x509.ExtendedKeyUsageExtension(ekuOids, false));
    }

    // Build SAN extension if provided
    if (params.san) {
      const sanItems: any[] = [];
      if (params.san.dns) {
        for (const dns of params.san.dns) {
          sanItems.push({ type: 'dns', value: dns.trim() });
        }
      }
      const ips = params.san.ip || (params.san as any).ips;
      if (ips) {
        for (const ip of ips) {
          sanItems.push({ type: 'ip', value: ip.trim() });
        }
      }
      if (params.san.uri) {
        for (const uri of params.san.uri) {
          sanItems.push({ type: 'url', value: uri.trim() });
        }
      }
      if (params.san.email) {
        for (const email of params.san.email) {
          sanItems.push({ type: 'email', value: email.trim() });
        }
      }
      if (sanItems.length > 0) {
        extensions.push(new x509.SubjectAlternativeNameExtension(sanItems, false));
      }
    }

    if (params.crlDistributionPoint) {
      extensions.push(
        new x509.CRLDistributionPointsExtension([params.crlDistributionPoint])
      );
    }

    const cert = await x509.X509CertificateGenerator.create({
      serialNumber,
      subject: formattedSubject,
      issuer: issuerSubject,
      notBefore,
      notAfter,
      signingAlgorithm: signingAlg,
      publicKey,
      signingKey: issuerPrivateKey,
      extensions,
    });

    const certificatePem = cert.toString('pem');
    const { sha256 } = this.calculateFingerprint(certificatePem);

    // Verify end-entity certificate with native OpenSSL
    const nativeCert = new crypto.X509Certificate(certificatePem);
    const nativeIssuer = new crypto.X509Certificate(issuerCertificatePem);
    if (!nativeCert.verify(nativeIssuer.publicKey)) {
      throw new CryptoEngineError('INTERNAL_CRYPTO_ERROR', 'End-entity certificate verification against issuer failed.');
    }

    const chainPem = `${certificatePem.trim()}\n${issuerCertificatePem.trim()}`;

    return {
      certificatePem,
      serialNumber,
      fingerprint: sha256,
      notBefore,
      notAfter,
      chainPem,
    };
  }

  // Convenient static aliases
  static createRootCA = X509Engine.createRootCertificate;
  static createIntermediateCA = X509Engine.createIntermediateCertificate;
  static createEndEntityCertificate = X509Engine.issueEndEntityCertificate;

  /**
   * Validate a certificate structurally and cryptographically
   */
  static async validateCertificate(
    certPem: string,
    options?: {
      trustAnchorPem?: string;
      intermediatePems?: string[];
      revokedSerialNumbers?: string[];
    }
  ): Promise<CertificateValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    let nativeCert: crypto.X509Certificate;
    let parsedCert: x509.X509Certificate;

    try {
      nativeCert = new crypto.X509Certificate(certPem);
      parsedCert = new x509.X509Certificate(certPem);
    } catch (err: any) {
      return {
        valid: false,
        status: 'FAILED',
        subject: '',
        issuer: '',
        serialNumber: '',
        fingerprint: '',
        notBefore: new Date(0),
        notAfter: new Date(0),
        daysRemaining: 0,
        isCa: false,
        keyUsage: [],
        extendedKeyUsage: [],
        san: {},
        signatureAlgorithm: '',
        publicKeyAlgorithm: '',
        errors: [`Certificate parse failure: ${err.message}`],
        warnings: [],
      };
    }

    const now = new Date();
    const notBefore = new Date(nativeCert.validFrom);
    const notAfter = new Date(nativeCert.validTo);
    const msRemaining = notAfter.getTime() - now.getTime();
    const daysRemaining = Math.floor(msRemaining / (1000 * 60 * 60 * 24));

    let status: CertificateStatus = 'ACTIVE';

    if (now < notBefore) {
      status = 'REQUESTED';
      errors.push(`Certificate is not yet valid (notBefore: ${notBefore.toISOString()})`);
    } else if (now > notAfter) {
      status = 'EXPIRED';
      errors.push(`Certificate has expired (notAfter: ${notAfter.toISOString()})`);
    } else if (daysRemaining <= 30) {
      status = 'EXPIRING';
      warnings.push(`Certificate is expiring soon (${daysRemaining} days remaining)`);
    }

    // Check revocation
    const serial = nativeCert.serialNumber.toLowerCase();
    const isRevoked = options?.revokedSerialNumbers?.some(
      (s) => s.toLowerCase() === serial
    );
    if (isRevoked) {
      status = 'REVOKED';
      errors.push(`Certificate serial '${serial}' is listed in revocation list`);
    }

    // Basic constraints
    const basicConstraints = parsedCert.extensions.find(
      (e) => e.type === '2.5.29.19'
    ) as x509.BasicConstraintsExtension | undefined;
    const isCa = basicConstraints ? basicConstraints.ca : false;
    const pathLenConstraint = basicConstraints?.pathLength;

    // Key usage
    const keyUsages: string[] = [];
    const kuExt = parsedCert.extensions.find(
      (e) => e.type === '2.5.29.15'
    ) as x509.KeyUsagesExtension | undefined;
    if (kuExt) {
      const flags = kuExt.usages;
      if (flags & x509.KeyUsageFlags.digitalSignature) keyUsages.push('digitalSignature');
      if (flags & x509.KeyUsageFlags.nonRepudiation) keyUsages.push('nonRepudiation');
      if (flags & x509.KeyUsageFlags.keyEncipherment) keyUsages.push('keyEncipherment');
      if (flags & x509.KeyUsageFlags.dataEncipherment) keyUsages.push('dataEncipherment');
      if (flags & x509.KeyUsageFlags.keyAgreement) keyUsages.push('keyAgreement');
      if (flags & x509.KeyUsageFlags.keyCertSign) keyUsages.push('keyCertSign');
      if (flags & x509.KeyUsageFlags.cRLSign) keyUsages.push('cRLSign');
    }

    // Extended key usage
    const ekuUsages: string[] = [];
    const ekuExt = parsedCert.extensions.find(
      (e) => e.type === '2.5.29.37'
    ) as x509.ExtendedKeyUsageExtension | undefined;
    if (ekuExt) {
      for (const oid of ekuExt.usages) {
        if (oid === x509.ExtendedKeyUsage.serverAuth) ekuUsages.push('serverAuth');
        else if (oid === x509.ExtendedKeyUsage.clientAuth) ekuUsages.push('clientAuth');
        else if (oid === x509.ExtendedKeyUsage.codeSigning) ekuUsages.push('codeSigning');
        else if (oid === x509.ExtendedKeyUsage.emailProtection) ekuUsages.push('emailProtection');
        else if (oid === x509.ExtendedKeyUsage.timeStamping) ekuUsages.push('timeStamping');
        else if (oid === '1.3.6.1.5.5.7.3.9' || oid === (x509.ExtendedKeyUsage as any).ocspSigning) ekuUsages.push('OCSPSigning');
        else ekuUsages.push(String(oid));
      }
    }

    // SAN
    const san: SubjectAlternativeNames = {};
    const sanExt = parsedCert.extensions.find(
      (e) => e.type === '2.5.29.17'
    ) as x509.SubjectAlternativeNameExtension | undefined;
    if (sanExt && (sanExt as any).names) {
      const items = (sanExt as any).names.items || (sanExt as any).names.toJSON?.() || [];
      for (const name of items) {
        if (name.type === 'dns') {
          san.dns = san.dns || [];
          san.dns.push(name.value);
        } else if (name.type === 'ip') {
          san.ip = san.ip || [];
          san.ip.push(name.value);
        } else if (name.type === 'url') {
          san.uri = san.uri || [];
          san.uri.push(name.value);
        } else if (name.type === 'email') {
          san.email = san.email || [];
          san.email.push(name.value);
        }
      }
    }

    // Trust anchor / chain validation
    let chainValid = true;
    if (options?.trustAnchorPem) {
      try {
        const anchorCert = new crypto.X509Certificate(options.trustAnchorPem);
        if (options.intermediatePems && options.intermediatePems.length > 0) {
          // Multi-tier chain
          let currentCert = nativeCert;
          for (const intPem of options.intermediatePems) {
            const intCert = new crypto.X509Certificate(intPem);
            if (!currentCert.verify(intCert.publicKey)) {
              chainValid = false;
              errors.push(`Signature verification failed between subject '${currentCert.subject}' and intermediate '${intCert.subject}'`);
              break;
            }
            currentCert = intCert;
          }
          if (chainValid && !currentCert.verify(anchorCert.publicKey)) {
            chainValid = false;
            errors.push(`Intermediate CA is not signed by trust anchor '${anchorCert.subject}'`);
          }
        } else {
          // Direct check against anchor
          if (!nativeCert.verify(anchorCert.publicKey)) {
            chainValid = false;
            errors.push(`Certificate signature is not signed by trust anchor '${anchorCert.subject}'`);
          }
        }
      } catch (err: any) {
        chainValid = false;
        errors.push(`Chain verification error: ${err.message}`);
      }
    }

    const { sha256, sha1 } = this.calculateFingerprint(certPem);

    const valid = errors.length === 0;

    return {
      valid,
      status: isRevoked ? 'REVOKED' : status,
      subject: nativeCert.subject,
      issuer: nativeCert.issuer,
      serialNumber: nativeCert.serialNumber,
      fingerprint: sha256,
      fingerprintSha1: sha1,
      notBefore,
      notAfter,
      daysRemaining,
      isCa,
      pathLenConstraint,
      keyUsage: keyUsages,
      extendedKeyUsage: ekuUsages,
      san,
      signatureAlgorithm: parsedCert.signatureAlgorithm?.name || 'SHA256withRSA',
      publicKeyAlgorithm: nativeCert.publicKey.asymmetricKeyType?.toUpperCase() || 'RSA',
      publicKeySizeBits: (nativeCert.publicKey.asymmetricKeyDetails?.modulusLength) || undefined,
      chainValid: options?.trustAnchorPem ? chainValid : undefined,
      revoked: isRevoked,
      errors,
      warnings,
    };
  }

  // --- PRIVATE RESOLVER HELPERS ---

  private static resolveKeyUsages(type: CertificateType, explicit?: KeyUsageType[]): number {
    if (explicit && explicit.length > 0) {
      let flags = 0;
      for (const u of explicit) {
        if (u === 'digitalSignature') flags |= x509.KeyUsageFlags.digitalSignature;
        if (u === 'nonRepudiation') flags |= x509.KeyUsageFlags.nonRepudiation;
        if (u === 'keyEncipherment') flags |= x509.KeyUsageFlags.keyEncipherment;
        if (u === 'dataEncipherment') flags |= x509.KeyUsageFlags.dataEncipherment;
        if (u === 'keyAgreement') flags |= x509.KeyUsageFlags.keyAgreement;
        if (u === 'keyCertSign') flags |= x509.KeyUsageFlags.keyCertSign;
        if (u === 'cRLSign') flags |= x509.KeyUsageFlags.cRLSign;
      }
      return flags;
    }

    switch (type) {
      case 'ROOT_CA':
      case 'INTERMEDIATE_CA':
        return x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign | x509.KeyUsageFlags.digitalSignature;
      case 'SERVER':
        return x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment | x509.KeyUsageFlags.keyAgreement;
      case 'CLIENT':
        return x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyAgreement;
      case 'CODE_SIGNING':
        return x509.KeyUsageFlags.digitalSignature;
      case 'EMAIL':
        return x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment | x509.KeyUsageFlags.nonRepudiation;
      case 'DEVICE':
        return x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment;
      default:
        return x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment;
    }
  }

  private static resolveExtendedKeyUsages(type: CertificateType, explicit?: ExtendedKeyUsageType[]): string[] {
    if (explicit && explicit.length > 0) {
      const oids: string[] = [];
      for (const e of explicit) {
        if (e === 'serverAuth') oids.push(x509.ExtendedKeyUsage.serverAuth);
        if (e === 'clientAuth') oids.push(x509.ExtendedKeyUsage.clientAuth);
        if (e === 'codeSigning') oids.push(x509.ExtendedKeyUsage.codeSigning);
        if (e === 'emailProtection') oids.push(x509.ExtendedKeyUsage.emailProtection);
        if (e === 'timeStamping') oids.push(x509.ExtendedKeyUsage.timeStamping);
        if (e === 'OCSPSigning') oids.push(x509.ExtendedKeyUsage.ocspSigning);
      }
      return oids;
    }

    switch (type) {
      case 'SERVER':
        return [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth];
      case 'CLIENT':
        return [x509.ExtendedKeyUsage.clientAuth];
      case 'CODE_SIGNING':
        return [x509.ExtendedKeyUsage.codeSigning];
      case 'EMAIL':
        return [x509.ExtendedKeyUsage.emailProtection];
      case 'DEVICE':
        return [x509.ExtendedKeyUsage.clientAuth];
      default:
        return [];
    }
  }
}
