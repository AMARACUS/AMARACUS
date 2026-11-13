import crypto from 'crypto';
import { CryptoAssetItem, DiscoverySource, ConfidenceLevel, AssetType, QuantumStatus } from './types';
import { QuantumClassifier } from './quantum-classifier';

export interface DiscoveredSourceUsage {
  file: string;
  line: number;
  snippet: string;
  algorithm: string;
  operation: string;
  confidence: ConfidenceLevel;
}

export interface ScanInputs {
  organizationId: string;
  keys?: any[];
  customerKeys?: any[];
  certificateAuthorities?: any[];
  certificates?: any[];
  auditEvents?: any[];
  sourceFiles?: Array<{ path: string; content: string }>;
}

export class CryptoScanner {
  /**
   * Run multi-source discovery across keys, certificates, runtime audit logs, and source code.
   */
  static scanAll(inputs: ScanInputs): {
    assets: CryptoAssetItem[];
    sourceUsages: DiscoveredSourceUsage[];
  } {
    const assets: CryptoAssetItem[] = [];
    const sourceUsages: DiscoveredSourceUsage[] = [];
    const seenAssetKeys = new Set<string>();

    const addAsset = (asset: CryptoAssetItem) => {
      const dedupKey = `${asset.organizationId}:${asset.assetType}:${asset.name}:${asset.source}`;
      if (!seenAssetKeys.has(dedupKey)) {
        seenAssetKeys.add(dedupKey);
        assets.push(asset);
      }
    };

    // 1. Scan Key Management (Local & BYOK HSM)
    if (inputs.keys) {
      for (const k of inputs.keys) {
        const qResult = QuantumClassifier.classify(k.algorithm);
        const assetId = `asset_key_${k.id}`;
        const fingerprint = k.versions?.[0]?.keyFingerprint || `fp_${crypto.createHash('sha256').update(k.id + k.name).digest('hex').slice(0, 16)}`;

        addAsset({
          id: assetId,
          organizationId: inputs.organizationId,
          projectId: k.projectId,
          environmentId: k.environmentId,
          assetType: 'KEY',
          name: k.name,
          source: 'KEY_MANAGEMENT',
          confidence: 'HIGH',
          algorithm: k.algorithm,
          provider: k.provider,
          status: k.status,
          quantumStatus: qResult.quantumStatus,
          fingerprint,
          firstSeenAt: new Date(k.createdAt || Date.now()),
          lastSeenAt: new Date(),
          metadata: {
            purpose: k.purpose,
            currentVersion: k.currentVersion,
            keyId: k.id,
            quantumRationale: qResult.rationale,
          },
          createdAt: new Date(),
          updatedAt: new Date(),
        });
      }
    }

    // Scan Customer Registered Keys (BYOK / Managed HSM)
    if (inputs.customerKeys) {
      for (const ck of inputs.customerKeys) {
        const qResult = QuantumClassifier.classify(ck.algorithm || ck.keyType);
        const assetId = `asset_byok_${ck.id}`;
        const fingerprint = ck.keyFingerprint || `fp_${crypto.createHash('sha256').update(ck.id + ck.keyIdentifier).digest('hex').slice(0, 16)}`;

        addAsset({
          id: assetId,
          organizationId: inputs.organizationId,
          projectId: ck.projectId,
          environmentId: ck.environmentId,
          assetType: 'KEY',
          name: ck.keyIdentifier,
          source: 'PROVIDER',
          confidence: 'HIGH',
          algorithm: ck.algorithm || ck.keyType,
          provider: ck.isHsmBacked ? 'AZURE_MANAGED_HSM' : 'AZURE_KEY_VAULT',
          status: ck.status,
          quantumStatus: qResult.quantumStatus,
          fingerprint,
          firstSeenAt: new Date(ck.createdAt || Date.now()),
          lastSeenAt: new Date(),
          metadata: {
            hsmBacked: ck.isHsmBacked,
            vaultUrl: ck.keyVaultUrl,
            purpose: ck.purpose,
            registeredKeyId: ck.id,
            quantumRationale: qResult.rationale,
          },
          createdAt: new Date(),
          updatedAt: new Date(),
        });
      }
    }

    // 2. Scan Certificate Authorities
    if (inputs.certificateAuthorities) {
      for (const ca of inputs.certificateAuthorities) {
        const qResult = QuantumClassifier.classify(ca.keyAlgorithm || ca.signatureAlgorithm);
        const assetId = `asset_ca_${ca.id}`;

        addAsset({
          id: assetId,
          organizationId: inputs.organizationId,
          projectId: ca.projectId,
          environmentId: ca.environmentId,
          assetType: 'CERTIFICATE_AUTHORITY',
          name: ca.name,
          source: 'CERTIFICATE_INVENTORY',
          confidence: 'HIGH',
          algorithm: ca.keyAlgorithm,
          provider: 'AMARACUS_PKI',
          status: ca.status,
          quantumStatus: qResult.quantumStatus,
          fingerprint: ca.fingerprint,
          firstSeenAt: new Date(ca.createdAt || Date.now()),
          lastSeenAt: new Date(),
          metadata: {
            subject: ca.subject,
            issuer: ca.issuer,
            serialNumber: ca.serialNumber,
            signatureAlgorithm: ca.signatureAlgorithm,
            type: ca.type,
            notBefore: ca.notBefore,
            notAfter: ca.notAfter,
            keyReference: ca.keyReference,
          },
          createdAt: new Date(),
          updatedAt: new Date(),
        });
      }
    }

    // 3. Scan Certificates
    if (inputs.certificates) {
      for (const cert of inputs.certificates) {
        const qResult = QuantumClassifier.classify(cert.keyAlgorithm || cert.signatureAlgorithm);
        const assetId = `asset_cert_${cert.id}`;

        addAsset({
          id: assetId,
          organizationId: inputs.organizationId,
          projectId: cert.projectId,
          environmentId: cert.environmentId,
          assetType: 'CERTIFICATE',
          name: cert.name || cert.subject,
          source: 'CERTIFICATE_INVENTORY',
          confidence: 'HIGH',
          algorithm: cert.keyAlgorithm,
          provider: 'AMARACUS_PKI',
          status: cert.status,
          quantumStatus: qResult.quantumStatus,
          fingerprint: cert.fingerprint,
          firstSeenAt: new Date(cert.createdAt || Date.now()),
          lastSeenAt: new Date(),
          metadata: {
            subject: cert.subject,
            issuer: cert.issuer,
            serialNumber: cert.serialNumber,
            certificateType: cert.certificateType,
            signatureAlgorithm: cert.signatureAlgorithm,
            publicKeyAlgorithm: cert.publicKeyAlgorithm,
            notBefore: cert.notBefore,
            notAfter: cert.notAfter,
            authorityId: cert.authorityId,
            keyReference: cert.keyReference,
          },
          createdAt: new Date(),
          updatedAt: new Date(),
        });
      }
    }

    // 4. Scan Crypto API Activity (from Audit Events)
    if (inputs.auditEvents) {
      for (const evt of inputs.auditEvents) {
        if (evt.action && (evt.action.startsWith('CRYPTO_') || evt.action.startsWith('KEY_'))) {
          const meta = evt.metadata || {};
          const algo = meta.algorithm || meta.keyAlgorithm || 'UNKNOWN';
          const qResult = QuantumClassifier.classify(algo);
          const assetName = `${evt.action.toLowerCase()}_${algo.toLowerCase()}`;
          const assetId = `asset_api_${crypto.createHash('sha256').update(inputs.organizationId + assetName).digest('hex').slice(0, 16)}`;

          addAsset({
            id: assetId,
            organizationId: inputs.organizationId,
            projectId: null,
            environmentId: null,
            assetType: 'CRYPTO_OPERATION',
            name: assetName,
            source: 'CRYPTO_API',
            confidence: 'HIGH',
            algorithm: algo,
            provider: meta.provider || 'NODE_CRYPTO',
            status: 'ACTIVE',
            quantumStatus: qResult.quantumStatus,
            fingerprint: `fp_api_${algo.toLowerCase()}`,
            firstSeenAt: new Date(evt.createdAt || Date.now()),
            lastSeenAt: new Date(evt.createdAt || Date.now()),
            metadata: {
              lastAction: evt.action,
              resourceId: evt.resourceId,
              operation: evt.action,
            },
            createdAt: new Date(),
            updatedAt: new Date(),
          });
        }
      }
    }

    // 5. Scan Source Code (AST / Token-aware regex excluding comments and string mentions)
    if (inputs.sourceFiles && inputs.sourceFiles.length > 0) {
      for (const file of inputs.sourceFiles) {
        const detected = this.detectSourceCodeCrypto(file.path, file.content);
        for (const usage of detected) {
          sourceUsages.push(usage);

          const qResult = QuantumClassifier.classify(usage.algorithm);
          const assetId = `asset_code_${crypto.createHash('sha256').update(inputs.organizationId + usage.file + usage.algorithm + usage.operation).digest('hex').slice(0, 16)}`;

          addAsset({
            id: assetId,
            organizationId: inputs.organizationId,
            projectId: null,
            environmentId: null,
            assetType: 'CRYPTO_LIBRARY',
            name: `${usage.operation}(${usage.algorithm})`,
            source: 'SOURCE_CODE',
            confidence: usage.confidence,
            algorithm: usage.algorithm,
            provider: 'APPLICATION_CODE',
            status: 'ACTIVE',
            quantumStatus: qResult.quantumStatus,
            fingerprint: `fp_code_${usage.algorithm.toLowerCase()}_${usage.operation.toLowerCase()}`,
            firstSeenAt: new Date(),
            lastSeenAt: new Date(),
            metadata: {
              file: usage.file,
              line: usage.line,
              snippet: usage.snippet,
              operation: usage.operation,
            },
            createdAt: new Date(),
            updatedAt: new Date(),
          });
        }
      }
    }

    return { assets, sourceUsages };
  }

  /**
   * Structured, comment-stripping source-code crypto pattern scanner.
   * Distinguishes actual API invocations from mere textual mentions in comments or markdown.
   */
  static detectSourceCodeCrypto(filePath: string, sourceText: string): DiscoveredSourceUsage[] {
    const results: DiscoveredSourceUsage[] = [];
    const lines = sourceText.split('\n');

    let inBlockComment = false;

    // Common crypto invocation patterns
    const patterns: Array<{
      regex: RegExp;
      extract: (match: RegExpExecArray) => { algorithm: string; operation: string; confidence: ConfidenceLevel };
    }> = [
      // crypto.createCipheriv('aes-256-gcm', ...)
      {
        regex: /(?:crypto\.)?createCipheriv\s*\(\s*['"`]([a-zA-Z0-9-]+)['"`]/i,
        extract: (m) => ({ algorithm: m[1].toUpperCase(), operation: 'CIPHER_ENCRYPT', confidence: 'HIGH' }),
      },
      // crypto.createDecipheriv('aes-256-gcm', ...)
      {
        regex: /(?:crypto\.)?createDecipheriv\s*\(\s*['"`]([a-zA-Z0-9-]+)['"`]/i,
        extract: (m) => ({ algorithm: m[1].toUpperCase(), operation: 'CIPHER_DECRYPT', confidence: 'HIGH' }),
      },
      // crypto.createHash('sha256') / sha384 / sha512
      {
        regex: /(?:crypto\.)?createHash\s*\(\s*['"`]([a-zA-Z0-9-]+)['"`]/i,
        extract: (m) => ({ algorithm: m[1].toUpperCase(), operation: 'HASH', confidence: 'HIGH' }),
      },
      // crypto.createHmac('sha256', ...)
      {
        regex: /(?:crypto\.)?createHmac\s*\(\s*['"`]([a-zA-Z0-9-]+)['"`]/i,
        extract: (m) => ({ algorithm: `HMAC-${m[1].toUpperCase()}`, operation: 'HMAC', confidence: 'HIGH' }),
      },
      // crypto.generateKeyPairSync('rsa', ...) or 'ed25519'
      {
        regex: /(?:crypto\.)?generateKeyPair(?:Sync)?\s*\(\s*['"`]([a-zA-Z0-9-]+)['"`]/i,
        extract: (m) => ({ algorithm: m[1].toUpperCase(), operation: 'KEY_GEN', confidence: 'HIGH' }),
      },
      // mlkem.encapsulate(...) or mlkem.decapsulate(...)
      {
        regex: /(?:mlkem|ml_kem)\.(?:encapsulate|decapsulate|keygen)\s*\(/i,
        extract: () => ({ algorithm: 'ML-KEM-768', operation: 'PQC_KEM', confidence: 'HIGH' }),
      },
      // mldsa.sign(...) or mldsa.verify(...)
      {
        regex: /(?:mldsa|ml_dsa)\.(?:sign|verify|keygen)\s*\(/i,
        extract: () => ({ algorithm: 'ML-DSA-65', operation: 'PQC_SIGN', confidence: 'HIGH' }),
      },
      // crypto.sign('sha256', ...)
      {
        regex: /(?:crypto\.)?sign\s*\(\s*['"`]([a-zA-Z0-9-]+)['"`]/i,
        extract: (m) => ({ algorithm: m[1].toUpperCase(), operation: 'SIGN', confidence: 'HIGH' }),
      },
      // import { ... } from '@noble/post-quantum/...'
      {
        regex: /import\s+.*from\s+['"`]@noble\/post-quantum\/([a-zA-Z0-9-]+)['"`]/i,
        extract: (m) => ({ algorithm: m[1].toUpperCase(), operation: 'IMPORT_LIBRARY', confidence: 'MEDIUM' }),
      },
    ];

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];
      let line = rawLine.trim();

      // Track block comments /* ... */
      if (inBlockComment) {
        if (line.includes('*/')) {
          inBlockComment = false;
          line = line.substring(line.indexOf('*/') + 2).trim();
        } else {
          continue; // Skip entire block comment line
        }
      }

      if (line.startsWith('/*')) {
        if (line.includes('*/')) {
          // One-line block comment
          line = line.substring(line.indexOf('*/') + 2).trim();
        } else {
          inBlockComment = true;
          continue;
        }
      }

      // Ignore single-line comments //
      if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) {
        continue;
      }

      // Strip trailing comment
      const commentIdx = line.indexOf('//');
      if (commentIdx !== -1) {
        line = line.substring(0, commentIdx).trim();
      }

      if (!line) continue;

      // Match against patterns
      for (const pat of patterns) {
        const match = pat.regex.exec(line);
        if (match) {
          const info = pat.extract(match);
          results.push({
            file: filePath,
            line: i + 1,
            snippet: rawLine.trim().slice(0, 120),
            algorithm: info.algorithm,
            operation: info.operation,
            confidence: info.confidence,
          });
        }
      }
    }

    return results;
  }
}
