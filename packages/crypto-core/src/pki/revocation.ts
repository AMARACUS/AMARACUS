import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import crypto from 'crypto';
import { RevocationReason } from './types';
import { X509Engine } from './x509-engine';

if (crypto.webcrypto) {
  x509.cryptoProvider.set(crypto.webcrypto as any);
}

export interface RevokedCertificateEntry {
  serialNumber: string;
  revocationDate: Date;
  reason?: RevocationReason;
}

export interface CrlGenerateParams {
  issuerCertificatePem: string;
  issuerPrivateKeyPem: string;
  revokedEntries: RevokedCertificateEntry[];
  thisUpdate?: Date;
  nextUpdateDays?: number;
  crlNumber?: number;
}

export interface OcspResponse {
  certificateId: string;
  serialNumber: string;
  status: 'GOOD' | 'REVOKED' | 'UNKNOWN';
  producedAt: Date;
  thisUpdate: Date;
  nextUpdate: Date;
  revocationReason?: RevocationReason;
  revocationTime?: Date;
  responder: string;
}

export class RevocationService {
  /**
   * Generate an RFC 5280 Certificate Revocation List (CRL) signed by issuing CA
   */
  static async generateCrl(params: CrlGenerateParams): Promise<{
    crlPem: string;
    thisUpdate: Date;
    nextUpdate: Date;
    entriesCount: number;
  }> {
    const issuerCert = new x509.X509Certificate(params.issuerCertificatePem);
    const issuerKeyAlg = X509Engine.inspectKeyAlgorithm(issuerCert.publicKey.toString('pem'));
    const issuerPrivateKeyObj = crypto.createPrivateKey(params.issuerPrivateKeyPem);
    const pkcs8Der = issuerPrivateKeyObj.export({ type: 'pkcs8', format: 'der' });

    let signingAlgorithm: any;
    const algUpper = issuerKeyAlg.toUpperCase();

    if (algUpper.startsWith('RSA')) {
      signingAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    } else if (algUpper.startsWith('EC') || algUpper.includes('P256') || algUpper.includes('P384')) {
      signingAlgorithm = { name: 'ECDSA', namedCurve: algUpper.includes('384') ? 'P-384' : 'P-256' };
    } else if (algUpper === 'ED25519') {
      signingAlgorithm = { name: 'Ed25519' };
    } else {
      signingAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    }

    const signingKey = await crypto.webcrypto.subtle.importKey(
      'pkcs8',
      pkcs8Der,
      signingAlgorithm,
      true,
      ['sign']
    );

    const thisUpdate = params.thisUpdate || new Date();
    const nextUpdateDays = params.nextUpdateDays || 7;
    const nextUpdate = new Date(thisUpdate.getTime() + nextUpdateDays * 24 * 3600 * 1000);

    const entries: any[] = [];
    for (const item of params.revokedEntries) {
      let crlReason: x509.X509CrlReason = x509.X509CrlReason.unspecified;
      if (item.reason === 'KEY_COMPROMISE') crlReason = x509.X509CrlReason.keyCompromise;
      else if (item.reason === 'CA_COMPROMISE') crlReason = x509.X509CrlReason.cACompromise;
      else if (item.reason === 'AFFILIATION_CHANGED') crlReason = x509.X509CrlReason.affiliationChanged;
      else if (item.reason === 'SUPERSEDED') crlReason = x509.X509CrlReason.superseded;
      else if (item.reason === 'CESSATION_OF_OPERATION') crlReason = x509.X509CrlReason.cessationOfOperation;
      else if (item.reason === 'CERTIFICATE_HOLD') crlReason = x509.X509CrlReason.certificateHold;
      else if (item.reason === 'PRIVILEGE_WITHDRAWN') crlReason = x509.X509CrlReason.privilegeWithdrawn;

      entries.push({
        serialNumber: item.serialNumber,
        revocationDate: item.revocationDate,
        reason: crlReason,
      });
    }

    const crl = await x509.X509CrlGenerator.create({
      issuer: issuerCert.subject,
      thisUpdate,
      nextUpdate,
      signingAlgorithm,
      signingKey,
      entries,
    });

    const crlPem = crl.toString('pem');

    return {
      crlPem,
      thisUpdate,
      nextUpdate,
      entriesCount: entries.length,
    };
  }

  static generateCRL = RevocationService.generateCrl;

  /**
   * Check revocation status for a certificate
   */
  static checkRevocationStatus(params: {
    certificateId: string;
    serialNumber: string;
    issuerSubject: string;
    revocations: {
      certificateId: string;
      reason: RevocationReason;
      revokedAt: Date;
    }[];
  }): OcspResponse {
    const now = new Date();
    const thisUpdate = now;
    const nextUpdate = new Date(now.getTime() + 24 * 3600 * 1000); // 24-hour cache TTL

    const matched = params.revocations.find(
      (r) => r.certificateId === params.certificateId
    );

    if (matched) {
      return {
        certificateId: params.certificateId,
        serialNumber: params.serialNumber,
        status: 'REVOKED',
        producedAt: now,
        thisUpdate,
        nextUpdate,
        revocationReason: matched.reason,
        revocationTime: matched.revokedAt,
        responder: params.issuerSubject,
      };
    }

    return {
      certificateId: params.certificateId,
      serialNumber: params.serialNumber,
      status: 'GOOD',
      producedAt: now,
      thisUpdate,
      nextUpdate,
      responder: params.issuerSubject,
    };
  }
}
