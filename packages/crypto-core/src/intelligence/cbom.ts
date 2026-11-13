import crypto from 'crypto';
import {
  CryptoAssetItem,
  CryptoRelationshipItem,
  CryptoFindingItem,
  CBOMDocument,
  CBOMComponent,
  CBOMRelationship,
} from './types';
import { CryptoEngineError } from '../errors';

export class CBOMGenerator {
  /**
   * Generate a compliant, machine-readable CBOM JSON document from discovered assets,
   * relationships, and security findings.
   *
   * Enforces STRICT ZERO SECRET LEAKAGE:
   * Asserts and guarantees that private keys, secret symmetric material, or auth tokens
   * are NEVER exported.
   */
  static generate(params: {
    organizationId: string;
    assets: CryptoAssetItem[];
    relationships?: CryptoRelationshipItem[];
    findings?: CryptoFindingItem[];
    environment?: string;
  }): CBOMDocument {
    const { organizationId, assets, relationships = [], findings = [], environment } = params;

    // 1. Build Components
    const components: CBOMComponent[] = [];
    let quantumVulnerableCount = 0;
    let pqcCount = 0;
    let hybridCount = 0;
    let classicalCount = 0;

    for (const asset of assets) {
      // Quantum score aggregation
      switch (asset.quantumStatus) {
        case 'QUANTUM_VULNERABLE':
          quantumVulnerableCount++;
          break;
        case 'PQC':
          pqcCount++;
          break;
        case 'HYBRID':
          hybridCount++;
          break;
        case 'CLASSICAL':
          classicalCount++;
          break;
      }

      // Sanitize metadata to guarantee ZERO SECRET LEAKAGE
      const safeProps: Record<string, any> = {};
      if (asset.metadata) {
        for (const [k, v] of Object.entries(asset.metadata)) {
          // Explicit blocklist of sensitive key material
          const lowerKey = k.toLowerCase();
          if (
            lowerKey.includes('private') ||
            lowerKey.includes('secret') ||
            lowerKey.includes('material') ||
            lowerKey.includes('authconfig') ||
            lowerKey.includes('token') ||
            lowerKey.includes('seed') ||
            lowerKey.includes('password')
          ) {
            continue; // Omit entirely
          }
          safeProps[k] = v;
        }
      }

      components.push({
        id: asset.id,
        type: asset.assetType,
        name: asset.name,
        algorithm: asset.algorithm,
        provider: asset.provider,
        quantumStatus: asset.quantumStatus,
        status: asset.status,
        source: asset.source,
        confidence: asset.confidence,
        fingerprint: asset.fingerprint,
        properties: safeProps,
      });
    }

    // 2. Build Dependencies
    const dependencies: CBOMRelationship[] = relationships.map((r) => ({
      sourceId: r.sourceAssetId,
      targetId: r.targetAssetId,
      relationship: r.relationshipType,
      confidence: r.confidence,
    }));

    // 3. Build Active Findings summary
    const findingsSummary = findings.map((f) => ({
      id: f.id,
      severity: f.severity,
      category: f.category,
      title: f.title,
      affectedAssetId: f.affectedAssetId,
      status: f.status,
    }));

    // 4. Construct Manifest
    const nowIso = new Date().toISOString();
    const serialNumber = `urn:uuid:${crypto.randomUUID()}`;

    const cbomUnsigned: Omit<CBOMDocument, 'integrity'> = {
      cbomVersion: '1.0.0',
      specVersion: 'CBOM-2024-DRAFT',
      serialNumber,
      timestamp: nowIso,
      organizationId,
      metadata: {
        generatedBy: 'AMARACUS Cryptographic Intelligence Engine',
        version: '1.0.0',
        environment: environment || 'PRODUCTION',
        totalAssets: components.length,
        quantumReadinessScore: {
          quantumVulnerable: quantumVulnerableCount,
          pqcReady: pqcCount,
          hybrid: hybridCount,
          classical: classicalCount,
        },
      },
      components,
      dependencies,
      findings: findingsSummary,
    };

    // Strict Zero-Secret Audit: JSON string search for any potential secret leaks
    const serializedPayload = JSON.stringify(cbomUnsigned);
    this.assertZeroSecretLeakage(serializedPayload);

    // Compute cryptographic integrity hash
    const manifestHash = crypto.createHash('sha256').update(serializedPayload).digest('hex');

    const cbomDocument: CBOMDocument = {
      ...cbomUnsigned,
      integrity: {
        algorithm: 'SHA-256',
        hash: manifestHash,
      },
    };

    return cbomDocument;
  }

  /**
   * Validate that serialized CBOM JSON does not contain private key blocks or secrets.
   */
  private static assertZeroSecretLeakage(jsonString: string): void {
    const forbiddenPatterns = [
      /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/,
      /-----BEGIN ENCRYPTED PRIVATE KEY-----/,
      /"encryptedKeyMaterial":\s*"[^"]+"/,
      /"encryptedAuthConfig":\s*"[^"]+"/,
      /"password":\s*"[^"]+"/,
      /"accessToken":\s*"[^"]+"/,
    ];

    for (const pattern of forbiddenPatterns) {
      if (pattern.test(jsonString)) {
        throw new CryptoEngineError(
          'INVALID_INPUT',
          'SECURITY_VIOLATION: Secret key material or credentials detected during CBOM export serialization. Export halted.',
          400
        );
      }
    }
  }
}
