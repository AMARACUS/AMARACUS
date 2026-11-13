import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import crypto from 'crypto';
import {
  ParsedCsr,
  SubjectNameParams,
  SubjectAlternativeNames,
  KeyUsageType,
  ExtendedKeyUsageType,
} from './types';
import { X509Engine } from './x509-engine';
import { CryptoEngineError } from '../errors';

if (crypto.webcrypto) {
  x509.cryptoProvider.set(crypto.webcrypto as any);
}

export class CsrEngine {
  /**
   * Generate a PKCS#10 Certificate Signing Request (CSR)
   */
  static async createCsr(params: {
    subject: SubjectNameParams | string;
    publicKeyPem: string;
    privateKeyPem: string;
    san?: SubjectAlternativeNames;
    keyUsage?: KeyUsageType[];
    extendedKeyUsage?: ExtendedKeyUsageType[];
  }): Promise<{
    csrPem: string;
    subject: string;
    publicKeyPem: string;
  }> {
    const formattedSubject = X509Engine.formatSubject(params.subject);
    const keyAlg = X509Engine.inspectKeyAlgorithm(params.publicKeyPem);

    const publicKeyObj = crypto.createPublicKey(params.publicKeyPem);
    const privateKeyObj = crypto.createPrivateKey(params.privateKeyPem);

    const spkiDer = publicKeyObj.export({ type: 'spki', format: 'der' });
    const pkcs8Der = privateKeyObj.export({ type: 'pkcs8', format: 'der' });

    let signingAlgorithm: any;
    const algUpper = keyAlg.toUpperCase();

    if (algUpper.startsWith('RSA')) {
      signingAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    } else if (algUpper.startsWith('EC') || algUpper.includes('P256') || algUpper.includes('P384')) {
      signingAlgorithm = { name: 'ECDSA', namedCurve: algUpper.includes('384') ? 'P-384' : 'P-256' };
    } else if (algUpper === 'ED25519') {
      signingAlgorithm = { name: 'Ed25519' };
    } else {
      signingAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    }

    const publicKey = await crypto.webcrypto.subtle.importKey(
      'spki',
      spkiDer,
      signingAlgorithm,
      true,
      ['verify']
    );

    const privateKey = await crypto.webcrypto.subtle.importKey(
      'pkcs8',
      pkcs8Der,
      signingAlgorithm,
      true,
      ['sign']
    );

    const extensions: x509.Extension[] = [];

    // SAN extension
    if (params.san) {
      const sanItems: any[] = [];
      if (params.san.dns) {
        for (const dns of params.san.dns) {
          sanItems.push({ type: 'dns', value: dns.trim() });
        }
      }
      if (params.san.ip) {
        for (const ip of params.san.ip) {
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

    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: formattedSubject,
      signingAlgorithm,
      keys: { publicKey, privateKey },
      extensions,
    });

    const csrPem = csr.toString('pem');

    return {
      csrPem,
      subject: formattedSubject,
      publicKeyPem: params.publicKeyPem,
    };
  }

  /**
   * Parse a PKCS#10 CSR and verify its cryptographic signature
   */
  static async parseAndValidateCsr(csrPem: string): Promise<ParsedCsr> {
    let csr: x509.Pkcs10CertificateRequest;
    try {
      csr = new x509.Pkcs10CertificateRequest(csrPem);
    } catch (err: any) {
      throw new CryptoEngineError('INVALID_INPUT', `Malformed CSR PEM: ${err.message}`);
    }

    let signatureValid = false;
    try {
      signatureValid = await csr.verify();
    } catch (err: any) {
      signatureValid = false;
    }

    const publicKeyPem = csr.publicKey.toString('pem');
    const publicKeyAlgorithm = X509Engine.inspectKeyAlgorithm(publicKeyPem);
    const signatureAlgorithm = csr.signatureAlgorithm?.name || 'SHA256withRSA';

    const san: SubjectAlternativeNames = {};
    const sanExt = csr.extensions.find(
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

    const keyUsage: KeyUsageType[] = [];
    const kuExt = csr.extensions.find(
      (e) => e.type === '2.5.29.15'
    ) as x509.KeyUsagesExtension | undefined;
    if (kuExt) {
      const flags = kuExt.usages;
      if (flags & x509.KeyUsageFlags.digitalSignature) keyUsage.push('digitalSignature');
      if (flags & x509.KeyUsageFlags.keyEncipherment) keyUsage.push('keyEncipherment');
      if (flags & x509.KeyUsageFlags.keyAgreement) keyUsage.push('keyAgreement');
    }

    const extendedKeyUsage: ExtendedKeyUsageType[] = [];
    const ekuExt = csr.extensions.find(
      (e) => e.type === '2.5.29.37'
    ) as x509.ExtendedKeyUsageExtension | undefined;
    if (ekuExt) {
      for (const oid of ekuExt.usages) {
        if (oid === x509.ExtendedKeyUsage.serverAuth) extendedKeyUsage.push('serverAuth');
        else if (oid === x509.ExtendedKeyUsage.clientAuth) extendedKeyUsage.push('clientAuth');
        else if (oid === x509.ExtendedKeyUsage.codeSigning) extendedKeyUsage.push('codeSigning');
        else if (oid === x509.ExtendedKeyUsage.emailProtection) extendedKeyUsage.push('emailProtection');
      }
    }

    return {
      subject: csr.subject,
      publicKeyPem,
      publicKeyAlgorithm,
      signatureAlgorithm,
      signatureValid,
      san,
      keyUsage,
      extendedKeyUsage,
      rawPem: csrPem,
    };
  }
}
