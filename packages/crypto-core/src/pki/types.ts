export type CertificateType =
  | 'ROOT_CA'
  | 'INTERMEDIATE_CA'
  | 'SERVER'
  | 'CLIENT'
  | 'CODE_SIGNING'
  | 'EMAIL'
  | 'DEVICE'
  | 'CUSTOM';

export type CertificateStatus =
  | 'REQUESTED'
  | 'ISSUED'
  | 'ACTIVE'
  | 'EXPIRING'
  | 'EXPIRED'
  | 'REVOKED'
  | 'SUSPENDED'
  | 'REPLACED'
  | 'FAILED';

export type RevocationReason =
  | 'UNSPECIFIED'
  | 'KEY_COMPROMISE'
  | 'CA_COMPROMISE'
  | 'AFFILIATION_CHANGED'
  | 'SUPERSEDED'
  | 'CESSATION_OF_OPERATION'
  | 'CERTIFICATE_HOLD'
  | 'PRIVILEGE_WITHDRAWN';

export interface SubjectAlternativeNames {
  dns?: string[];
  ip?: string[];
  uri?: string[];
  email?: string[];
}

export type KeyUsageType =
  | 'digitalSignature'
  | 'nonRepudiation'
  | 'keyEncipherment'
  | 'dataEncipherment'
  | 'keyAgreement'
  | 'keyCertSign'
  | 'cRLSign'
  | 'encipherOnly'
  | 'decipherOnly';

export type ExtendedKeyUsageType =
  | 'serverAuth'
  | 'clientAuth'
  | 'codeSigning'
  | 'emailProtection'
  | 'timeStamping'
  | 'OCSPSigning';

export interface SubjectNameParams {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  stateOrProvince?: string;
  locality?: string;
}

export interface IssueCertificateParams {
  subject: SubjectNameParams | string;
  publicKeyPem: string;
  signingPrivateKeyPem?: string; // Private key PEM for local signing
  issuerCertificatePem?: string; // Issuing CA certificate PEM (null for self-signed Root CA)
  type: CertificateType;
  validityDays?: number;
  serialNumber?: string;
  san?: SubjectAlternativeNames;
  keyUsage?: KeyUsageType[];
  extendedKeyUsage?: ExtendedKeyUsageType[];
  pathLenConstraint?: number;
  crlDistributionPoint?: string;
  ocspUrl?: string;
}

export interface CertificateValidationResult {
  valid: boolean;
  status: CertificateStatus;
  subject: string;
  issuer: string;
  serialNumber: string;
  fingerprint: string;
  fingerprintSha1?: string;
  notBefore: Date;
  notAfter: Date;
  daysRemaining: number;
  isCa: boolean;
  pathLenConstraint?: number | null;
  keyUsage: string[];
  extendedKeyUsage: string[];
  san: SubjectAlternativeNames;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeySizeBits?: number;
  chainValid?: boolean;
  revoked?: boolean;
  revocationReason?: RevocationReason | null;
  revokedAt?: Date | null;
  errors: string[];
  warnings: string[];
}

export interface ChainValidationResult {
  valid: boolean;
  chainLength: number;
  certificates: {
    subject: string;
    issuer: string;
    serialNumber: string;
    isCa: boolean;
    fingerprint: string;
  }[];
  trustAnchor?: string;
  errors: string[];
}

export interface ParsedCsr {
  subject: string;
  publicKeyPem: string;
  publicKeyAlgorithm: string;
  signatureAlgorithm: string;
  signatureValid: boolean;
  san: SubjectAlternativeNames;
  keyUsage: KeyUsageType[];
  extendedKeyUsage: ExtendedKeyUsageType[];
  rawPem: string;
}
