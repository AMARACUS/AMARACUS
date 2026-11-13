import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import crypto from 'crypto';
import { ChainValidationResult } from './types';

interface ParsedCert {
  native: crypto.X509Certificate;
  parsed: x509.X509Certificate;
}

type ChainEntry = ChainValidationResult['certificates'][number];

export class ChainValidator {
  /**
   * Validate a full X.509 certificate chain from Leaf up to a trusted Root CA.
   *
   * - Every PEM in `rootCertPem` / `trustAnchorsPem` is a candidate anchor; the one whose
   *   subject matches the top certificate's issuer and whose key verifies it is used.
   * - `checkExpiry` (default true) controls notBefore/notAfter checks.
   * - `checkRevocation` (default true) rejects any chain certificate whose serial number
   *   is in `revokedSerialNumbers`.
   * - Issuer/subject names are compared in exact RDN order.
   */
  static async validateChain(params: {
    leafCertPem?: string;
    leafCertificatePem?: string;
    intermediatePems?: string[];
    intermediateCertificatesPem?: string[];
    rootCertPem?: string;
    trustAnchorsPem?: string[] | string;
    checkExpiry?: boolean;
    checkRevocation?: boolean;
    revokedSerialNumbers?: string[];
  }): Promise<ChainValidationResult & { isValid: boolean; chainValid: boolean; status: string; chain: any[] }> {
    const leafCertPem = params.leafCertPem || params.leafCertificatePem;
    const intermediatePems = params.intermediatePems || params.intermediateCertificatesPem || [];
    const anchorPems = [
      ...(params.rootCertPem ? [params.rootCertPem] : []),
      ...(Array.isArray(params.trustAnchorsPem) ? params.trustAnchorsPem : params.trustAnchorsPem ? [params.trustAnchorsPem] : []),
    ].filter((pem, i, all) => pem && all.indexOf(pem) === i);
    const checkExpiry = params.checkExpiry !== false;
    const checkRevocation = params.checkRevocation !== false;
    const revoked = new Set((params.revokedSerialNumbers || []).map(normalizeSerial));

    const fail = (errors: string[], certificates: ChainEntry[] = []) => ({
      valid: false,
      isValid: false,
      chainValid: false,
      status: 'INVALID',
      chainLength: certificates.length,
      certificates,
      chain: certificates,
      errors,
    });

    if (!leafCertPem || anchorPems.length === 0) {
      return fail(['Missing required certificate PEMs for chain validation.']);
    }

    const errors: string[] = [];
    const now = new Date();

    // 1. Parse the leaf and intermediates (path order: leaf, intermediate[0], ...)
    let leaf: ParsedCert;
    try {
      leaf = parse(leafCertPem);
    } catch (err: any) {
      return fail([`Leaf certificate parse failure: ${err.message}`]);
    }

    const intermediates: ParsedCert[] = [];
    for (let i = 0; i < intermediatePems.length; i++) {
      try {
        intermediates.push(parse(intermediatePems[i]));
      } catch (err: any) {
        errors.push(`Intermediate CA #${i + 1} parse failure: ${err.message}`);
      }
    }

    // 2. Parse anchors and pick the one that issued the top of the path
    const anchors: ParsedCert[] = [];
    for (let i = 0; i < anchorPems.length; i++) {
      try {
        anchors.push(parse(anchorPems[i]));
      } catch (err: any) {
        errors.push(`Trust anchor #${i + 1} parse failure: ${err.message}`);
      }
    }

    const path = [leaf, ...intermediates];
    const top = path[path.length - 1];
    const root = anchors.find((a) => dnEquals(top.parsed.issuerName, a.parsed.subjectName) && top.native.verify(a.native.publicKey));

    const certificates: ChainEntry[] = [...path, ...(root ? [root] : [])].map(describe);

    if (!root) {
      errors.push(`No trust anchor issued '${top.native.subject.replace(/\n/g, ', ')}' (issuer '${top.native.issuer.replace(/\n/g, ', ')}').`);
      return fail(errors, certificates);
    }

    // 3. Trust anchor checks
    if (!root.native.verify(root.native.publicKey)) {
      errors.push(`Root CA signature verification failed (self-signature invalid).`);
    }
    checkCa(root, `Trust anchor '${root.native.subject}'`, errors);

    // 4. Intermediate CA constraints
    for (const int of intermediates) {
      checkCa(int, `Intermediate certificate '${int.native.subject}'`, errors);
    }

    // 5. Each link: issuer name matches (exact RDN order) and signature verifies
    const issuers = [...intermediates, root];
    for (let i = 0; i < path.length; i++) {
      const cert = path[i];
      const issuer = issuers[i];
      const label = i === 0 ? 'Leaf' : 'Intermediate';
      if (!dnEquals(cert.parsed.issuerName, issuer.parsed.subjectName)) {
        errors.push(`${label} issuer '${cert.native.issuer}' does not match '${issuer.native.subject}'.`);
      }
      if (!cert.native.verify(issuer.native.publicKey)) {
        errors.push(`${label} certificate '${cert.native.subject}' signature verification failed against '${issuer.native.subject}'.`);
      }
    }

    // 6. Validity periods
    if (checkExpiry) {
      for (const cert of [...path, root]) {
        if (now < new Date(cert.native.validFrom)) {
          errors.push(`Certificate '${cert.native.subject}' is not yet valid (notBefore: ${cert.native.validFrom}).`);
        }
        if (now > new Date(cert.native.validTo)) {
          errors.push(`Certificate '${cert.native.subject}' has expired (notAfter: ${cert.native.validTo}).`);
        }
      }
    }

    // 7. Revocation
    if (checkRevocation && revoked.size > 0) {
      for (const cert of path) {
        if (revoked.has(normalizeSerial(cert.native.serialNumber))) {
          errors.push(`Certificate '${cert.native.subject}' (serial ${cert.native.serialNumber}) has been revoked.`);
        }
      }
    }

    const isValid = errors.length === 0;
    return {
      valid: isValid,
      isValid,
      chainValid: isValid,
      status: isValid ? 'VALID' : 'INVALID',
      chainLength: certificates.length,
      certificates,
      chain: certificates,
      trustAnchor: root.native.subject,
      errors,
    };
  }
}

function parse(pem: string): ParsedCert {
  return { native: new crypto.X509Certificate(pem), parsed: new x509.X509Certificate(pem) };
}

function describe(cert: ParsedCert): ChainEntry {
  const bc = cert.parsed.extensions.find((e) => e.type === '2.5.29.19') as x509.BasicConstraintsExtension | undefined;
  return {
    subject: cert.native.subject,
    issuer: cert.native.issuer,
    serialNumber: cert.native.serialNumber,
    isCa: bc ? bc.ca : false,
    fingerprint: cert.native.fingerprint256.replace(/:/g, '').toLowerCase(),
  };
}

function checkCa(cert: ParsedCert, label: string, errors: string[]): void {
  const bc = cert.parsed.extensions.find((e) => e.type === '2.5.29.19') as x509.BasicConstraintsExtension | undefined;
  if (!bc || !bc.ca) {
    errors.push(`${label} is not a CA (basicConstraints cA must be true).`);
  }
  const ku = cert.parsed.extensions.find((e) => e.type === '2.5.29.15') as x509.KeyUsagesExtension | undefined;
  if (ku && !(ku.usages & x509.KeyUsageFlags.keyCertSign)) {
    errors.push(`${label} is missing keyCertSign key usage.`);
  }
}

/**
 * Compares two names RDN by RDN, in order. Attribute values compare case-insensitively
 * with whitespace collapsed (RFC 5280 §7.1 style); the RDN sequence itself must match exactly.
 */
function dnEquals(a: x509.Name, b: x509.Name): boolean {
  const ra = a.toJSON();
  const rb = b.toJSON();
  if (ra.length !== rb.length) return false;
  return ra.every((rdn, i) => canonicalRdn(rdn) === canonicalRdn(rb[i]));
}

function canonicalRdn(rdn: Record<string, string[]>): string {
  return Object.keys(rdn)
    .sort()
    .map((type) => `${type}=${rdn[type].map((v) => v.trim().replace(/\s+/g, ' ').toLowerCase()).sort().join('+')}`)
    .join('+');
}

function normalizeSerial(serial: string): string {
  return String(serial).replace(/[:\s]/g, '').toLowerCase().replace(/^0+(?=.)/, '');
}
