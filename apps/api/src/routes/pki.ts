import { selfHostGate, selfHostMeterOnSuccess } from '../middleware/selfhost-metering';
import 'reflect-metadata';
import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { requireAuth, requireOrgMember, requireOrgPermission } from '../middleware/auth';
import { createRateLimiter } from '../middleware/rate-limiter';
import { db, CertificateAuthorityRecord, CertificateRecord } from '../lib/data-store';
import { requireOperationAllowance } from '../middleware/billing-guard';
import { usageMeter } from '../lib/usage-meter';
import {
  X509Engine,
  CsrEngine,
  ChainValidator,
  RevocationService,
  CertificateType,
  CertificateStatus,
  RevocationReason,
  SubjectAlternativeNames,
  CryptoPolicyEngine,
  CryptoEngineError,
} from '@amaracus/crypto-core';
import { createSecureUploadMiddleware, SecureUploadRequest } from '../middleware/file-upload';
import { secureStorage, CERT_MAX_FILE_SIZE } from '../lib/file-security';

const router = Router({ mergeParams: true });
const policyEngine = new CryptoPolicyEngine();

// Common middleware for all PKI routes
router.use(requireAuth);
router.use(requireOrgMember);
router.use(createRateLimiter({ limit: 300, windowMs: 60 * 1000 }));

// Helper to record safe audit events (strictly no private keys)
async function recordPkiAudit(
  req: Request,
  action: string,
  resourceId: string,
  metadata?: Record<string, any>
) {
  try {
    const orgId = req.params.orgId || req.organizationId || (req as any).activeOrgId;
    const userId = (req as any).user?.id || null;
    await db.createAuditEvent({
      action,
      organizationId: orgId,
      userId,
      resourceType: 'PKI',
      resourceId,
      metadata: {
        ...metadata,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      },
    });
  } catch (err) {
    console.error('[PKI Audit Error]:', err);
  }
}

// Helper to sanitize Certificate Authority for API output
function sanitizeCa(ca: CertificateAuthorityRecord) {
  return {
    id: ca.id,
    name: ca.name,
    description: ca.description,
    organizationId: ca.organizationId,
    projectId: ca.projectId,
    environmentId: ca.environmentId,
    type: ca.type,
    status: ca.status,
    subject: ca.subject,
    issuer: ca.issuer,
    parentAuthorityId: ca.parentAuthorityId,
    keyReference: ca.keyReference,
    keyAlgorithm: ca.keyAlgorithm,
    signatureAlgorithm: ca.signatureAlgorithm,
    certificatePem: ca.certificatePem,
    serialNumber: ca.serialNumber,
    fingerprint: ca.fingerprint,
    notBefore: ca.notBefore,
    notAfter: ca.notAfter,
    pathLenConstraint: ca.pathLenConstraint,
    crlDistributionPoint: ca.crlDistributionPoint,
    ocspUrl: ca.ocspUrl,
    metadata: ca.metadata,
    createdAt: ca.createdAt,
    updatedAt: ca.updatedAt,
  };
}

// Helper to sanitize Certificate for API output
function sanitizeCert(cert: CertificateRecord) {
  const now = new Date();
  let calculatedStatus = cert.status;
  if (cert.status !== 'REVOKED' && cert.status !== 'SUSPENDED' && cert.status !== 'REPLACED') {
    if (now > new Date(cert.notAfter)) {
      calculatedStatus = 'EXPIRED';
    } else {
      const msRemaining = new Date(cert.notAfter).getTime() - now.getTime();
      const daysRemaining = Math.floor(msRemaining / (1000 * 60 * 60 * 24));
      if (daysRemaining <= 30) {
        calculatedStatus = 'EXPIRING';
      }
    }
  }

  const msRemaining = new Date(cert.notAfter).getTime() - now.getTime();
  const daysRemaining = Math.floor(msRemaining / (1000 * 60 * 60 * 24));

  return {
    id: cert.id,
    name: cert.name,
    organizationId: cert.organizationId,
    projectId: cert.projectId,
    environmentId: cert.environmentId,
    authorityId: cert.authorityId,
    keyReference: cert.keyReference,
    subject: cert.subject,
    issuer: cert.issuer,
    serialNumber: cert.serialNumber,
    certificateType: cert.certificateType,
    keyAlgorithm: cert.keyAlgorithm,
    signatureAlgorithm: cert.signatureAlgorithm,
    publicKeyAlgorithm: cert.publicKeyAlgorithm,
    status: calculatedStatus,
    daysRemaining: daysRemaining > 0 ? daysRemaining : 0,
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
    fingerprint: cert.fingerprint,
    fingerprintSha1: cert.fingerprintSha1,
    certificatePem: cert.certificatePem,
    chainPem: cert.chainPem,
    chainReference: cert.chainReference,
    san: cert.san,
    keyUsage: cert.keyUsage,
    extendedKeyUsage: cert.extendedKeyUsage,
    renewalOfId: cert.renewalOfId,
    replacedById: cert.replacedById,
    revocation: cert.revocation || null,
    createdAt: cert.createdAt,
    updatedAt: cert.updatedAt,
  };
}

// ============================================================================
// 1. CERTIFICATE AUTHORITIES (CA) ENDPOINTS
// ============================================================================

/**
 * POST /v1/organizations/:orgId/pki/certificate-authorities
 * Create a Root CA or an Intermediate CA
 */
router.post(
  '/certificate-authorities',
  requireOrgPermission('pki:ca:create'),
  selfHostGate(),
  selfHostMeterOnSuccess('CA_CREATE'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const {
        name,
        description,
        projectId,
        environmentId,
        type = 'ROOT_CA',
        subject,
        parentAuthorityId,
        keyAlgorithm = 'RSA-4096',
        validityDays,
        pathLenConstraint,
        crlDistributionPoint,
        ocspUrl,
      } = req.body;

      if (!name || !projectId || !environmentId || !subject) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: 'Missing required fields: name, projectId, environmentId, subject.',
          },
        });
      }

      const caType = type.toUpperCase() as CertificateType;
      if (caType !== 'ROOT_CA' && caType !== 'INTERMEDIATE_CA') {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: "CA type must be 'ROOT_CA' or 'INTERMEDIATE_CA'.",
          },
        });
      }

      // Enforce policy rules
      policyEngine.validateCertificateIssuance({
        certificateType: caType,
        keyAlgorithm,
        validityDays,
      });

      // Generate asymmetric keypair for this CA
      const keypair = await X509Engine.generateKeypair(keyAlgorithm);

      // Create CryptographicKey record to represent this key in KMS
      const caKey = await db.createKey({
        organizationId: orgId,
        projectId,
        environmentId,
        name: `ca-key-${name.toLowerCase().replace(/[^a-z0-9]/g, '-')}-${Date.now()}`,
        description: `Key for Certificate Authority: ${name}`,
        algorithm: keyAlgorithm,
        purpose: 'SIGNING',
        provider: 'LOCAL_DEV',
      });

      // Add key version storing the private key material wrapped under Master KEK
      await db.addKeyVersion({
        keyId: caKey.id,
        version: 1,
        providerKeyId: `local-${crypto.randomUUID()}`,
        publicKey: keypair.publicKeySpkiHex,
        encryptedKeyMaterial: keypair.privateKeyPem, // In local store, stored wrapped
        keyFingerprint: crypto.createHash('sha256').update(keypair.publicKeyPem).digest('hex').substring(0, 16),
      });

      let certPem = '';
      let serialNumber = '';
      let fingerprint = '';
      let notBefore: Date;
      let notAfter: Date;
      let issuerSubject = '';

      if (caType === 'ROOT_CA') {
        const rootRes = await X509Engine.createRootCertificate({
          subject,
          publicKeyPem: keypair.publicKeyPem,
          privateKeyPem: keypair.privateKeyPem,
          validityDays: validityDays || 3650,
          pathLenConstraint: pathLenConstraint ?? 1,
          crlDistributionPoint,
          ocspUrl,
        });
        certPem = rootRes.certificatePem;
        serialNumber = rootRes.serialNumber;
        fingerprint = rootRes.fingerprint;
        notBefore = rootRes.notBefore;
        notAfter = rootRes.notAfter;
        issuerSubject = X509Engine.formatSubject(subject);
      } else {
        // INTERMEDIATE_CA requires parentAuthorityId
        if (!parentAuthorityId) {
          return res.status(400).json({
            error: {
              code: 'INVALID_INPUT',
              message: "Intermediate CA requires 'parentAuthorityId' referencing the issuing CA.",
            },
          });
        }

        const parentCa = await db.getCertificateAuthority(parentAuthorityId, orgId);
        if (!parentCa) {
          return res.status(404).json({
            error: {
              code: 'RESOURCE_NOT_FOUND',
              message: `Parent Certificate Authority '${parentAuthorityId}' not found in active organization.`,
            },
          });
        }
        if (parentCa.status !== 'ACTIVE') {
          return res.status(400).json({
            error: {
              code: 'INVALID_STATE_TRANSITION',
              message: `Parent Certificate Authority is ${parentCa.status}. Only ACTIVE CAs can sign intermediate authorities.`,
            },
          });
        }

        // Retrieve parent CA private key material
        const parentKeyVersions = await db.listKeyVersions(parentCa.keyReference);
        const parentKeyVer = parentKeyVersions.find((v) => v.status === 'ACTIVE') || parentKeyVersions[0];
        if (!parentKeyVer?.encryptedKeyMaterial) {
          return res.status(500).json({
            error: {
              code: 'KEY_NOT_FOUND',
              message: 'Parent CA private signing key could not be resolved.',
            },
          });
        }

        const intRes = await X509Engine.createIntermediateCertificate({
          subject,
          issuerCertificatePem: parentCa.certificatePem,
          issuerPrivateKeyPem: parentKeyVer.encryptedKeyMaterial,
          publicKeyPem: keypair.publicKeyPem,
          validityDays: validityDays || 1825,
          pathLenConstraint: pathLenConstraint ?? 0,
          crlDistributionPoint,
          ocspUrl,
        });

        certPem = intRes.certificatePem;
        serialNumber = intRes.serialNumber;
        fingerprint = intRes.fingerprint;
        notBefore = intRes.notBefore;
        notAfter = intRes.notAfter;
        issuerSubject = parentCa.subject;
      }

      const formattedSubject = X509Engine.formatSubject(subject);

      const caRecord = await db.createCertificateAuthority({
        name,
        description,
        organizationId: orgId,
        projectId,
        environmentId,
        type: caType,
        status: 'ACTIVE',
        subject: formattedSubject,
        issuer: issuerSubject,
        parentAuthorityId: parentAuthorityId || null,
        keyReference: caKey.id,
        keyAlgorithm,
        signatureAlgorithm: keyAlgorithm.startsWith('RSA') ? 'SHA256withRSA' : 'SHA256withECDSA',
        certificatePem: certPem,
        serialNumber,
        fingerprint,
        notBefore,
        notAfter,
        pathLenConstraint: pathLenConstraint ?? (caType === 'ROOT_CA' ? 1 : 0),
        crlDistributionPoint: crlDistributionPoint || null,
        ocspUrl: ocspUrl || null,
        metadata: {
          keyLengthBits: keyAlgorithm.includes('4096') ? 4096 : 2048,
        },
      });

      // Also register CA certificate in Certificate inventory
      await db.createCertificate({
        name: `${name} Certificate`,
        organizationId: orgId,
        projectId,
        environmentId,
        authorityId: caRecord.id,
        keyReference: caKey.id,
        subject: formattedSubject,
        issuer: issuerSubject,
        serialNumber,
        certificateType: caType,
        keyAlgorithm,
        signatureAlgorithm: caRecord.signatureAlgorithm,
        publicKeyAlgorithm: keyAlgorithm.split('-')[0],
        status: 'ACTIVE',
        notBefore,
        notAfter,
        fingerprint,
        certificatePem: certPem,
        chainPem: certPem,
        keyUsage: ['keyCertSign', 'cRLSign', 'digitalSignature'],
      });

      await recordPkiAudit(req, 'PKI_CA_CREATED', caRecord.id, {
        caType,
        keyAlgorithm,
        subject: formattedSubject,
        serialNumber,
      });

      res.status(201).json({
        data: sanitizeCa(caRecord),
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * GET /v1/organizations/:orgId/pki/certificate-authorities
 * List Certificate Authorities
 */
router.get(
  '/certificate-authorities',
  requireOrgPermission('pki:ca:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const { projectId, environmentId, status } = req.query;

      const list = await db.listCertificateAuthorities({
        organizationId: orgId,
        projectId: projectId as string,
        environmentId: environmentId as string,
        status: status as string,
      });

      res.json({
        data: list.map(sanitizeCa),
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * GET /v1/organizations/:orgId/pki/certificate-authorities/:id
 * Get Certificate Authority details
 */
router.get(
  '/certificate-authorities/:id',
  requireOrgPermission('pki:ca:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const ca = await db.getCertificateAuthority(req.params.id, orgId);

      if (!ca) {
        return res.status(404).json({
          error: {
            code: 'RESOURCE_NOT_FOUND',
            message: `Certificate Authority '${req.params.id}' not found.`,
          },
        });
      }

      res.json({
        data: sanitizeCa(ca),
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * POST /v1/organizations/:orgId/pki/certificate-authorities/:id/disable
 * Disable a Certificate Authority
 */
router.post(
  '/certificate-authorities/:id/disable',
  requireOrgPermission('pki:ca:disable'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const ca = await db.getCertificateAuthority(req.params.id, orgId);

      if (!ca) {
        return res.status(404).json({
          error: {
            code: 'RESOURCE_NOT_FOUND',
            message: `Certificate Authority '${req.params.id}' not found.`,
          },
        });
      }

      const updated = await db.updateCertificateAuthority(ca.id, {
        status: 'DISABLED',
      });

      await recordPkiAudit(req, 'PKI_CA_DISABLED', ca.id, {
        previousStatus: ca.status,
      });

      res.json({
        data: sanitizeCa(updated!),
      });
    } catch (err: any) {
      next(err);
    }
  }
);

const handleCrlRequest = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.params.orgId || (req as any).organizationId;
    const ca = await db.getCertificateAuthority(req.params.id, orgId);

    if (!ca) {
      return res.status(404).json({
        error: {
          code: 'RESOURCE_NOT_FOUND',
          message: `Certificate Authority '${req.params.id}' not found.`,
        },
      });
    }

    // Fetch revoked certificates issued by this CA
    const revocations = await db.listCertificateRevocations(orgId);
    const revokedCerts: { serialNumber: string; revocationDate: Date; reason?: RevocationReason }[] = [];

    for (const rev of revocations) {
      const cert = await db.getCertificate(rev.certificateId, orgId);
      if (cert && cert.authorityId === ca.id) {
        revokedCerts.push({
          serialNumber: cert.serialNumber,
          revocationDate: rev.revokedAt,
          reason: rev.reason as RevocationReason,
        });
      }
    }

    // Fetch CA private key
    const caKeyVersions = await db.listKeyVersions(ca.keyReference);
    const caKeyVer = caKeyVersions.find((v) => v.status === 'ACTIVE') || caKeyVersions[0];
    if (!caKeyVer?.encryptedKeyMaterial) {
      return res.status(500).json({
        error: {
          code: 'KEY_NOT_FOUND',
          message: 'CA private signing key could not be resolved to generate CRL.',
        },
      });
    }

    const nextUpdateDays = typeof req.body?.nextUpdateDays === 'number'
      ? req.body.nextUpdateDays
      : (req.query.nextUpdateDays ? parseInt(req.query.nextUpdateDays as string, 10) : 7);

    const crlResult = await RevocationService.generateCrl({
      issuerCertificatePem: ca.certificatePem,
      issuerPrivateKeyPem: caKeyVer.encryptedKeyMaterial,
      revokedEntries: revokedCerts,
      nextUpdateDays,
    });

    await recordPkiAudit(req, 'PKI_CRL_GENERATED', ca.id, {
      entriesCount: crlResult.entriesCount,
    });

    if (req.query.format === 'raw' || req.query.download === 'true') {
      res.setHeader('Content-Type', 'application/x-pkcs7-crl');
      res.setHeader('Content-Disposition', `attachment; filename="${ca.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}.crl"`);
      return res.send(crlResult.crlPem);
    }

    res.json({
      data: {
        authorityId: ca.id,
        issuer: ca.subject,
        crlPem: crlResult.crlPem,
        thisUpdate: crlResult.thisUpdate,
        nextUpdate: crlResult.nextUpdate,
        revokedCertificatesCount: crlResult.entriesCount,
      },
    });
  } catch (err: any) {
    next(err);
  }
};

router.get(
  '/certificate-authorities/:id/crl',
  requireOrgPermission('pki:crl:read'),
  handleCrlRequest
);

router.post(
  '/certificate-authorities/:id/crl',
  requireOrgPermission('pki:crl:read'),
  handleCrlRequest
);

// ============================================================================
// 2. CERTIFICATES ENDPOINTS
// ============================================================================

/**
 * POST /v1/organizations/:orgId/pki/certificates
 * Issue a new X.509 Certificate
 */
router.post(
  '/certificates',
  requireOrgPermission('pki:cert:issue'),
  requireOperationAllowance(1),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const {
        name,
        authorityId,
        projectId,
        environmentId,
        type = 'SERVER',
        subject,
        keyAlgorithm = 'RSA-2048',
        keyReference,
        validityDays = 397,
        san,
        keyUsage,
        extendedKeyUsage,
      } = req.body;

      if (!authorityId || !projectId || !environmentId || !subject) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: 'Missing required fields: authorityId, projectId, environmentId, subject.',
          },
        });
      }

      const certType = type.toUpperCase() as CertificateType;

      // Policy validation
      policyEngine.validateCertificateIssuance({
        certificateType: certType,
        keyAlgorithm,
        validityDays,
        san,
      });

      const ca = await db.getCertificateAuthority(authorityId, orgId);
      if (!ca) {
        return res.status(404).json({
          error: {
            code: 'RESOURCE_NOT_FOUND',
            message: `Issuing Certificate Authority '${authorityId}' not found.`,
          },
        });
      }

      if (ca.status !== 'ACTIVE') {
        return res.status(400).json({
          error: {
            code: 'INVALID_STATE_TRANSITION',
            message: `Certificate Authority '${ca.name}' is ${ca.status}. Only ACTIVE CAs can issue certificates.`,
          },
        });
      }

      // Resolve keypair for certificate
      let certPublicKeyPem = '';
      let certKeyRef = keyReference;

      if (certKeyRef) {
        const key = await db.getKey(certKeyRef, orgId);
        if (!key) {
          return res.status(404).json({
            error: {
              code: 'KEY_NOT_FOUND',
              message: `Referenced key '${certKeyRef}' not found in active organization.`,
            },
          });
        }
        const versions = await db.listKeyVersions(certKeyRef);
        const activeVer = versions.find((v) => v.status === 'ACTIVE') || versions[0];
        if (!activeVer?.publicKey) {
          return res.status(400).json({
            error: {
              code: 'INVALID_KEY',
              message: 'Referenced key does not contain a valid public key for certificate association.',
            },
          });
        }
        // Convert SPKI hex or PEM to PEM
        if (activeVer.publicKey.includes('BEGIN PUBLIC KEY')) {
          certPublicKeyPem = activeVer.publicKey;
        } else {
          const spkiBuf = Buffer.from(activeVer.publicKey, 'hex');
          certPublicKeyPem = crypto.createPublicKey({ key: spkiBuf, format: 'der', type: 'spki' }).export({ type: 'spki', format: 'pem' }) as string;
        }
      } else {
        // Generate new key for this certificate
        const kp = await X509Engine.generateKeypair(keyAlgorithm);
        certPublicKeyPem = kp.publicKeyPem;

        const newKey = await db.createKey({
          organizationId: orgId,
          projectId,
          environmentId,
          name: `cert-key-${(typeof subject === 'string' ? subject : subject.commonName).toLowerCase().replace(/[^a-z0-9]/g, '-')}-${Date.now()}`,
          description: `Key for certificate: ${typeof subject === 'string' ? subject : subject.commonName}`,
          algorithm: keyAlgorithm,
          purpose: 'SIGNING',
          provider: 'LOCAL_DEV',
        });

        await db.addKeyVersion({
          keyId: newKey.id,
          version: 1,
          providerKeyId: `local-${crypto.randomUUID()}`,
          publicKey: kp.publicKeySpkiHex,
          encryptedKeyMaterial: kp.privateKeyPem,
          keyFingerprint: crypto.createHash('sha256').update(kp.publicKeyPem).digest('hex').substring(0, 16),
        });

        certKeyRef = newKey.id;
      }

      // Fetch CA signing key
      const caKeyVersions = await db.listKeyVersions(ca.keyReference);
      const caKeyVer = caKeyVersions.find((v) => v.status === 'ACTIVE') || caKeyVersions[0];
      if (!caKeyVer?.encryptedKeyMaterial) {
        return res.status(500).json({
          error: {
            code: 'KEY_NOT_FOUND',
            message: 'CA private signing key could not be resolved.',
          },
        });
      }

      const issueRes = await X509Engine.issueEndEntityCertificate({
        subject,
        publicKeyPem: certPublicKeyPem,
        issuerCertificatePem: ca.certificatePem,
        signingPrivateKeyPem: caKeyVer.encryptedKeyMaterial,
        type: certType,
        validityDays,
        san,
        keyUsage,
        extendedKeyUsage,
        crlDistributionPoint: ca.crlDistributionPoint || undefined,
        ocspUrl: ca.ocspUrl || undefined,
      });

      const formattedSubject = X509Engine.formatSubject(subject);

      const certRecord = await db.createCertificate({
        name: name || formattedSubject,
        organizationId: orgId,
        projectId,
        environmentId,
        authorityId: ca.id,
        keyReference: certKeyRef,
        subject: formattedSubject,
        issuer: ca.subject,
        serialNumber: issueRes.serialNumber,
        certificateType: certType,
        keyAlgorithm,
        signatureAlgorithm: keyAlgorithm.startsWith('RSA') ? 'SHA256withRSA' : 'SHA256withECDSA',
        publicKeyAlgorithm: keyAlgorithm.split('-')[0],
        status: 'ACTIVE',
        notBefore: issueRes.notBefore,
        notAfter: issueRes.notAfter,
        fingerprint: issueRes.fingerprint,
        certificatePem: issueRes.certificatePem,
        chainPem: issueRes.chainPem,
        san: san || null,
        keyUsage: keyUsage || null,
        extendedKeyUsage: extendedKeyUsage || null,
      });

      await recordPkiAudit(req, 'PKI_CERTIFICATE_ISSUED', certRecord.id, {
        subject: formattedSubject,
        issuer: ca.subject,
        serialNumber: issueRes.serialNumber,
        certificateType: certType,
        keyAlgorithm,
      });

      // Authoritatively meter successful certificate issuance
      try {
        const operationId = (req.headers['idempotency-key'] as string) || (req as any).requestId;
        await usageMeter.recordOperation({
          organizationId: orgId,
          operationType: 'CERT_ISSUE',
          quantity: 1,
          operationId,
          projectId,
        });
      } catch (meterErr) {
        console.warn('[Usage Metering Warning] Could not record certificate issuance usage:', meterErr);
      }

      res.status(201).json({
        data: sanitizeCert(certRecord),
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * GET /v1/organizations/:orgId/pki/certificates
 * Inventory and list certificates with filtering
 */
router.get(
  '/certificates',
  requireOrgPermission('pki:cert:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const {
        projectId,
        environmentId,
        status,
        authorityId,
        certificateType,
        keyAlgorithm,
      } = req.query;

      const list = await db.listCertificates({
        organizationId: orgId,
        projectId: projectId as string,
        environmentId: environmentId as string,
        status: status as string,
        authorityId: authorityId as string,
        certificateType: certificateType as string,
        keyAlgorithm: keyAlgorithm as string,
      });

      res.json({
        data: list.map(sanitizeCert),
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * GET /v1/organizations/:orgId/pki/certificates/:id
 * Get certificate details by ID
 */
router.get(
  '/certificates/:id',
  requireOrgPermission('pki:cert:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const cert = await db.getCertificate(req.params.id, orgId);

      if (!cert) {
        return res.status(404).json({
          error: {
            code: 'RESOURCE_NOT_FOUND',
            message: `Certificate '${req.params.id}' not found.`,
          },
        });
      }

      res.json({
        data: sanitizeCert(cert),
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * POST /v1/organizations/:orgId/pki/certificates/:id/validate
 * Validate certificate structure, signatures, chain, validity, and revocation
 */
router.post(
  '/certificates/:id/validate',
  requireOrgPermission('pki:cert:validate'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const cert = await db.getCertificate(req.params.id, orgId);

      if (!cert) {
        return res.status(404).json({
          error: {
            code: 'RESOURCE_NOT_FOUND',
            message: `Certificate '${req.params.id}' not found.`,
          },
        });
      }

      // Fetch revoked certificates in organization
      const revocations = await db.listCertificateRevocations(orgId);
      const revokedSerials: string[] = [];
      for (const rev of revocations) {
        const c = await db.getCertificate(rev.certificateId, orgId);
        if (c) revokedSerials.push(c.serialNumber);
      }

      // Resolve trust anchor / CA certificate
      let trustAnchorPem: string | undefined;
      let intermediatePems: string[] = [];

      if (cert.authorityId) {
        const ca = await db.getCertificateAuthority(cert.authorityId, orgId);
        if (ca) {
          if (ca.type === 'ROOT_CA') {
            trustAnchorPem = ca.certificatePem;
          } else if (ca.type === 'INTERMEDIATE_CA' && ca.parentAuthorityId) {
            intermediatePems.push(ca.certificatePem);
            const parentCa = await db.getCertificateAuthority(ca.parentAuthorityId, orgId);
            if (parentCa) {
              trustAnchorPem = parentCa.certificatePem;
            }
          }
        }
      }

      const validationRes = await X509Engine.validateCertificate(cert.certificatePem, {
        trustAnchorPem,
        intermediatePems: intermediatePems.length > 0 ? intermediatePems : undefined,
        revokedSerialNumbers: revokedSerials,
      });

      // Chain validation if trust anchor available
      let chainResult;
      if (trustAnchorPem) {
        chainResult = await ChainValidator.validateChain({
          leafCertPem: cert.certificatePem,
          intermediatePems: intermediatePems.length > 0 ? intermediatePems : undefined,
          rootCertPem: trustAnchorPem,
          checkRevocation: true,
          revokedSerialNumbers: revokedSerials,
        });
      }

      await recordPkiAudit(req, 'PKI_CERTIFICATE_VALIDATED', cert.id, {
        valid: validationRes.valid,
        status: validationRes.status,
        chainValid: chainResult ? chainResult.valid : null,
      });

      res.json({
        data: {
          certificateId: cert.id,
          serialNumber: cert.serialNumber,
          validation: validationRes,
          chain: chainResult || null,
          isValid: validationRes.valid,
          chainValid: chainResult ? chainResult.valid : true,
          status: validationRes.status,
          revocationStatus: validationRes.revoked ? 'REVOKED' : 'GOOD',
        },
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * POST /v1/organizations/:orgId/pki/certificates/:id/renew
 * Renew an existing certificate (preserves lineage via renewalOfId)
 */
router.post(
  '/certificates/:id/renew',
  requireOrgPermission('pki:cert:renew'),
  selfHostGate(),
  selfHostMeterOnSuccess('CERT_RENEW'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const cert = await db.getCertificate(req.params.id, orgId);

      if (!cert) {
        return res.status(404).json({
          error: {
            code: 'RESOURCE_NOT_FOUND',
            message: `Certificate '${req.params.id}' not found.`,
          },
        });
      }

      if (cert.status === 'REVOKED') {
        return res.status(400).json({
          error: {
            code: 'KEY_REVOKED',
            message: 'Cannot renew a REVOKED certificate. Revoked certificates are permanently invalid; issue a new certificate instead.',
          },
        });
      }

      if (!cert.authorityId) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: 'Certificate has no associated Certificate Authority for renewal.',
          },
        });
      }

      const ca = await db.getCertificateAuthority(cert.authorityId, orgId);
      if (!ca || ca.status !== 'ACTIVE') {
        return res.status(400).json({
          error: {
            code: 'INVALID_STATE_TRANSITION',
            message: 'Issuing Certificate Authority is not ACTIVE.',
          },
        });
      }

      const { reuseKey = true, reuseExistingKey, validityDays = 397 } = req.body;
      const shouldReuse = reuseExistingKey !== undefined ? Boolean(reuseExistingKey) : Boolean(reuseKey);

      // Policy validation
      policyEngine.validateCertificateIssuance({
        certificateType: cert.certificateType as CertificateType,
        keyAlgorithm: cert.keyAlgorithm,
        validityDays,
        san: cert.san,
      });

      let certPublicKeyPem = '';
      let certKeyRef = cert.keyReference;

      if (shouldReuse) {
        // Reuse same key
        const versions = await db.listKeyVersions(certKeyRef);
        const activeVer = versions.find((v) => v.status === 'ACTIVE') || versions[0];
        if (activeVer?.publicKey?.includes('BEGIN PUBLIC KEY')) {
          certPublicKeyPem = activeVer.publicKey;
        } else if (activeVer?.publicKey) {
          const spkiBuf = Buffer.from(activeVer.publicKey, 'hex');
          certPublicKeyPem = crypto.createPublicKey({ key: spkiBuf, format: 'der', type: 'spki' }).export({ type: 'spki', format: 'pem' }) as string;
        }
      } else {
        // Generate new key
        const kp = await X509Engine.generateKeypair(cert.keyAlgorithm);
        certPublicKeyPem = kp.publicKeyPem;

        const newKey = await db.createKey({
          organizationId: orgId,
          projectId: cert.projectId,
          environmentId: cert.environmentId,
          name: `cert-key-renewed-${Date.now()}`,
          description: `Renewed key for certificate: ${cert.subject}`,
          algorithm: cert.keyAlgorithm,
          purpose: 'SIGNING',
          provider: 'LOCAL_DEV',
        });

        await db.addKeyVersion({
          keyId: newKey.id,
          version: 1,
          providerKeyId: `local-${crypto.randomUUID()}`,
          publicKey: kp.publicKeySpkiHex,
          encryptedKeyMaterial: kp.privateKeyPem,
          keyFingerprint: crypto.createHash('sha256').update(kp.publicKeyPem).digest('hex').substring(0, 16),
        });

        certKeyRef = newKey.id;
      }

      // Fetch CA signing key
      const caKeyVersions = await db.listKeyVersions(ca.keyReference);
      const caKeyVer = caKeyVersions.find((v) => v.status === 'ACTIVE') || caKeyVersions[0];
      if (!caKeyVer?.encryptedKeyMaterial) {
        return res.status(500).json({
          error: {
            code: 'KEY_NOT_FOUND',
            message: 'CA private signing key could not be resolved.',
          },
        });
      }

      const issueRes = await X509Engine.issueEndEntityCertificate({
        subject: cert.subject,
        publicKeyPem: certPublicKeyPem,
        issuerCertificatePem: ca.certificatePem,
        signingPrivateKeyPem: caKeyVer.encryptedKeyMaterial,
        type: cert.certificateType as CertificateType,
        validityDays,
        san: cert.san,
        keyUsage: cert.keyUsage,
        extendedKeyUsage: cert.extendedKeyUsage,
      });

      const renewedCert = await db.createCertificate({
        name: cert.name ? `${cert.name} (Renewed)` : `${cert.subject} (Renewed)`,
        organizationId: orgId,
        projectId: cert.projectId,
        environmentId: cert.environmentId,
        authorityId: ca.id,
        keyReference: certKeyRef,
        subject: cert.subject,
        issuer: ca.subject,
        serialNumber: issueRes.serialNumber,
        certificateType: cert.certificateType,
        keyAlgorithm: cert.keyAlgorithm,
        signatureAlgorithm: cert.signatureAlgorithm,
        publicKeyAlgorithm: cert.publicKeyAlgorithm,
        status: 'ACTIVE',
        notBefore: issueRes.notBefore,
        notAfter: issueRes.notAfter,
        fingerprint: issueRes.fingerprint,
        certificatePem: issueRes.certificatePem,
        chainPem: issueRes.chainPem,
        san: cert.san,
        keyUsage: cert.keyUsage,
        extendedKeyUsage: cert.extendedKeyUsage,
        renewalOfId: cert.id,
      });

      // Update old certificate with replacedById
      await db.updateCertificate(cert.id, {
        replacedById: renewedCert.id,
        status: 'REPLACED',
      });

      await recordPkiAudit(req, 'PKI_CERTIFICATE_RENEWED', renewedCert.id, {
        previousCertificateId: cert.id,
        reuseKey,
        serialNumber: issueRes.serialNumber,
      });

      res.status(200).json({
        data: sanitizeCert(renewedCert),
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * POST /v1/organizations/:orgId/pki/certificates/:id/revoke
 * Revoke a certificate with an RFC 5280 reason code
 */
router.post(
  '/certificates/:id/revoke',
  requireOrgPermission('pki:cert:revoke'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const cert = await db.getCertificate(req.params.id, orgId);

      if (!cert) {
        return res.status(404).json({
          error: {
            code: 'RESOURCE_NOT_FOUND',
            message: `Certificate '${req.params.id}' not found.`,
          },
        });
      }

      if (cert.status === 'REVOKED') {
        return res.status(400).json({
          error: {
            code: 'KEY_REVOKED',
            message: 'Certificate is already revoked.',
          },
        });
      }

      const { reason = 'UNSPECIFIED', comment, invalidityDate } = req.body;

      const validReasons: RevocationReason[] = [
        'UNSPECIFIED',
        'KEY_COMPROMISE',
        'CA_COMPROMISE',
        'AFFILIATION_CHANGED',
        'SUPERSEDED',
        'CESSATION_OF_OPERATION',
        'CERTIFICATE_HOLD',
        'PRIVILEGE_WITHDRAWN',
      ];

      const revReason = reason.toUpperCase() as RevocationReason;
      if (!validReasons.includes(revReason)) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: `Invalid revocation reason '${reason}'. Valid RFC 5280 reasons: ${validReasons.join(', ')}.`,
          },
        });
      }

      const revRecord = await db.createCertificateRevocation({
        certificateId: cert.id,
        organizationId: orgId,
        reason: revReason,
        revokedAt: new Date(),
        revokedBy: (req as any).user?.id || 'admin',
        invalidityDate: invalidityDate ? new Date(invalidityDate) : null,
        comment: comment || null,
      });

      const updatedCert = await db.updateCertificate(cert.id, {
        status: 'REVOKED',
      });

      await recordPkiAudit(req, 'PKI_CERTIFICATE_REVOKED', cert.id, {
        serialNumber: cert.serialNumber,
        reason: revReason,
        comment,
      });

      res.json({
        data: {
          ...sanitizeCert(updatedCert!),
          certificate: sanitizeCert(updatedCert!),
          revocation: revRecord,
        },
      });
    } catch (err: any) {
      next(err);
    }
  }
);

// ============================================================================
// 3. CERTIFICATE SIGNING REQUESTS (CSR) ENDPOINTS
// ============================================================================

/**
 * POST /v1/organizations/:orgId/pki/csrs
 * Generate a new PKCS#10 Certificate Signing Request
 */
router.post(
  '/csrs',
  requireOrgPermission('pki:csr:create'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const {
        projectId,
        environmentId,
        subject,
        keyAlgorithm = 'RSA-2048',
        keyReference,
        san,
        keyUsage,
        extendedKeyUsage,
      } = req.body;

      if (!projectId || !environmentId || !subject) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: 'Missing required fields: projectId, environmentId, subject.',
          },
        });
      }

      let publicKeyPem = '';
      let privateKeyPem = '';
      let certKeyRef = keyReference;

      if (certKeyRef) {
        const key = await db.getKey(certKeyRef, orgId);
        if (!key) {
          return res.status(404).json({
            error: {
              code: 'KEY_NOT_FOUND',
              message: `Referenced key '${certKeyRef}' not found.`,
            },
          });
        }
        const versions = await db.listKeyVersions(certKeyRef);
        const activeVer = versions.find((v) => v.status === 'ACTIVE') || versions[0];
        if (!activeVer?.encryptedKeyMaterial) {
          return res.status(400).json({
            error: {
              code: 'INVALID_KEY',
              message: 'Referenced key has no accessible private key for CSR signing.',
            },
          });
        }
        privateKeyPem = activeVer.encryptedKeyMaterial;
        const pubObj = crypto.createPrivateKey(privateKeyPem);
        publicKeyPem = crypto.createPublicKey(pubObj).export({ type: 'spki', format: 'pem' }) as string;
      } else {
        const kp = await X509Engine.generateKeypair(keyAlgorithm);
        publicKeyPem = kp.publicKeyPem;
        privateKeyPem = kp.privateKeyPem;

        const newKey = await db.createKey({
          organizationId: orgId,
          projectId,
          environmentId,
          name: `csr-key-${Date.now()}`,
          algorithm: keyAlgorithm,
          purpose: 'SIGNING',
          provider: 'LOCAL_DEV',
        });

        await db.addKeyVersion({
          keyId: newKey.id,
          version: 1,
          providerKeyId: `local-${crypto.randomUUID()}`,
          publicKey: kp.publicKeySpkiHex,
          encryptedKeyMaterial: kp.privateKeyPem,
          keyFingerprint: crypto.createHash('sha256').update(kp.publicKeyPem).digest('hex').substring(0, 16),
        });

        certKeyRef = newKey.id;
      }

      const csrRes = await CsrEngine.createCsr({
        subject,
        publicKeyPem,
        privateKeyPem,
        san,
        keyUsage,
        extendedKeyUsage,
      });

      const formattedSubject = X509Engine.formatSubject(subject);

      const csrRecord = await db.createCertificateRequest({
        organizationId: orgId,
        projectId,
        environmentId,
        keyReference: certKeyRef,
        subject: formattedSubject,
        csrPem: csrRes.csrPem,
        publicKey: publicKeyPem,
        keyAlgorithm,
        signatureAlgorithm: keyAlgorithm.startsWith('RSA') ? 'SHA256withRSA' : 'SHA256withECDSA',
        status: 'PENDING',
        san: san || null,
        keyUsage: keyUsage || null,
        extendedKeyUsage: extendedKeyUsage || null,
      });

      await recordPkiAudit(req, 'PKI_CSR_CREATED', csrRecord.id, {
        subject: formattedSubject,
        keyAlgorithm,
      });

      res.status(201).json({
        data: csrRecord,
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * GET /v1/organizations/:orgId/pki/csrs
 * List all CSRs for an organization
 */
router.get(
  '/csrs',
  requireOrgPermission('pki:csr:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const { projectId, environmentId, status } = req.query;

      const csrs = await db.listCertificateRequests({
        organizationId: orgId,
        projectId: projectId as string,
        environmentId: environmentId as string,
        status: status as string,
      });

      res.json({
        data: csrs,
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * GET /v1/organizations/:orgId/pki/csrs/:id
 * Get single CSR by ID
 */
router.get(
  '/csrs/:id',
  requireOrgPermission('pki:csr:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const csr = await db.getCertificateRequest(req.params.id, orgId);

      if (!csr) {
        return res.status(404).json({
          error: {
            code: 'RESOURCE_NOT_FOUND',
            message: `Certificate Request '${req.params.id}' not found.`,
          },
        });
      }

      res.json({
        data: csr,
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * POST /v1/organizations/:orgId/pki/csrs/upload
 * Securely uploads a PKCS#10 CSR file, validates type/size/magic bytes,
 * stores in non-executable storage, and parses certificate request info.
 */
router.post(
  '/csrs/upload',
  requireOrgPermission('pki:csr:validate'),
  createSecureUploadMiddleware({
    fieldName: 'csrFile',
    maxSize: CERT_MAX_FILE_SIZE,
    allowedExtensions: new Set(['.csr', '.pem', '.txt']),
  }),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const secureFile = (req as SecureUploadRequest).secureFile;
      if (!secureFile) {
        return res.status(400).json({
          error: {
            code: 'MISSING_FILE',
            message: 'No CSR file provided or file failed security validation.',
          },
        });
      }

      // Read file content from secure non-executable storage
      const rawPem = secureStorage.readFile(secureFile.storageName).toString('utf-8');
      const parsed = await CsrEngine.parseAndValidateCsr(rawPem);

      await recordPkiAudit(req, 'PKI_CSR_FILE_UPLOADED', secureFile.fileId, {
        fileName: secureFile.sanitizedName,
        sha256: secureFile.sha256,
        subject: parsed.subject,
        signatureValid: parsed.signatureValid,
      });

      res.status(201).json({
        data: {
          fileId: secureFile.fileId,
          fileName: secureFile.sanitizedName,
          size: secureFile.size,
          sha256: secureFile.sha256,
          ...parsed,
          isValid: parsed.signatureValid,
        },
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * POST /v1/organizations/:orgId/pki/csrs/validate
 * Parse and validate an uploaded or generated PKCS#10 CSR
 */
router.post(
  '/csrs/validate',
  requireOrgPermission('pki:csr:validate'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { csrPem } = req.body;
      if (!csrPem || typeof csrPem !== 'string') {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: "Missing 'csrPem' field.",
          },
        });
      }

      const parsed = await CsrEngine.parseAndValidateCsr(csrPem);

      await recordPkiAudit(req, 'PKI_CSR_VALIDATED', 'csr-input', {
        subject: parsed.subject,
        signatureValid: parsed.signatureValid,
      });

      res.json({
        data: {
          ...parsed,
          isValid: parsed.signatureValid,
        },
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * POST /v1/organizations/:orgId/pki/csrs/:id/sign
 * Sign a validated CSR using an issuing CA and issue certificate
 */
router.post(
  '/csrs/:id/sign',
  requireOrgPermission('pki:cert:issue'),
  selfHostGate(),
  selfHostMeterOnSuccess('CERT_ISSUE'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const csr = await db.getCertificateRequest(req.params.id, orgId);

      if (!csr) {
        return res.status(404).json({
          error: {
            code: 'RESOURCE_NOT_FOUND',
            message: `Certificate Request '${req.params.id}' not found.`,
          },
        });
      }

      const { authorityId, type = 'SERVER', validityDays = 397 } = req.body;

      if (!authorityId) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: "Missing 'authorityId' field.",
          },
        });
      }

      const ca = await db.getCertificateAuthority(authorityId, orgId);
      if (!ca || ca.status !== 'ACTIVE') {
        return res.status(400).json({
          error: {
            code: 'INVALID_STATE_TRANSITION',
            message: 'Certificate Authority is not ACTIVE.',
          },
        });
      }

      const parsedCsr = await CsrEngine.parseAndValidateCsr(csr.csrPem);
      if (!parsedCsr.signatureValid) {
        return res.status(400).json({
          error: {
            code: 'SIGNATURE_INVALID',
            message: 'CSR cryptographic signature verification failed.',
          },
        });
      }

      // Fetch CA signing key
      const caKeyVersions = await db.listKeyVersions(ca.keyReference);
      const caKeyVer = caKeyVersions.find((v) => v.status === 'ACTIVE') || caKeyVersions[0];
      if (!caKeyVer?.encryptedKeyMaterial) {
        return res.status(500).json({
          error: {
            code: 'KEY_NOT_FOUND',
            message: 'CA private signing key could not be resolved.',
          },
        });
      }

      const certType = type.toUpperCase() as CertificateType;

      const issueRes = await X509Engine.issueEndEntityCertificate({
        subject: parsedCsr.subject,
        publicKeyPem: parsedCsr.publicKeyPem,
        issuerCertificatePem: ca.certificatePem,
        signingPrivateKeyPem: caKeyVer.encryptedKeyMaterial,
        type: certType,
        validityDays,
        san: parsedCsr.san,
        keyUsage: parsedCsr.keyUsage,
        extendedKeyUsage: parsedCsr.extendedKeyUsage,
      });

      const certRecord = await db.createCertificate({
        name: `Cert for ${parsedCsr.subject}`,
        organizationId: orgId,
        projectId: csr.projectId,
        environmentId: csr.environmentId,
        authorityId: ca.id,
        keyReference: csr.keyReference || `external-key-${Date.now()}`,
        subject: parsedCsr.subject,
        issuer: ca.subject,
        serialNumber: issueRes.serialNumber,
        certificateType: certType,
        keyAlgorithm: parsedCsr.publicKeyAlgorithm,
        signatureAlgorithm: parsedCsr.signatureAlgorithm,
        publicKeyAlgorithm: parsedCsr.publicKeyAlgorithm.split('-')[0],
        status: 'ACTIVE',
        notBefore: issueRes.notBefore,
        notAfter: issueRes.notAfter,
        fingerprint: issueRes.fingerprint,
        certificatePem: issueRes.certificatePem,
        chainPem: issueRes.chainPem,
        san: parsedCsr.san,
        keyUsage: parsedCsr.keyUsage,
        extendedKeyUsage: parsedCsr.extendedKeyUsage,
      });

      await db.updateCertificateRequest(csr.id, {
        status: 'ISSUED',
        certificateId: certRecord.id,
      });

      await recordPkiAudit(req, 'PKI_CERTIFICATE_ISSUED', certRecord.id, {
        csrId: csr.id,
        serialNumber: issueRes.serialNumber,
      });

      res.status(201).json({
        data: sanitizeCert(certRecord),
      });
    } catch (err: any) {
      next(err);
    }
  }
);

// ============================================================================
// 4. OCSP REVOCATION CHECK ENDPOINT
// ============================================================================

/**
 * GET /v1/organizations/:orgId/pki/ocsp/:certId
 * Check OCSP revocation status for a certificate
 */
router.get(
  '/ocsp/:certId',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId || (req as any).organizationId;
      const cert = await db.getCertificate(req.params.certId, orgId);

      if (!cert) {
        return res.status(404).json({
          error: {
            code: 'RESOURCE_NOT_FOUND',
            message: `Certificate '${req.params.certId}' not found.`,
          },
        });
      }

      const revocations = await db.listCertificateRevocations(orgId);
      const matched = revocations.find((r) => r.certificateId === cert.id);

      const ocspRes = RevocationService.checkRevocationStatus({
        certificateId: cert.id,
        serialNumber: cert.serialNumber,
        issuerSubject: cert.issuer,
        revocations: matched
          ? [
              {
                certificateId: cert.id,
                reason: matched.reason as RevocationReason,
                revokedAt: matched.revokedAt,
              },
            ]
          : [],
      });

      res.json({
        data: {
          ...ocspRes,
          revoked: ocspRes.status === 'REVOKED',
        },
      });
    } catch (err: any) {
      next(err);
    }
  }
);

export default router;
