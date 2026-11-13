/**
 * @file packages/crypto-core/src/assurance/evidence-collector.ts
 * Verifiable Evidence Collection, Sanitization, Digest Integrity & Chain of Custody (Phase 22)
 */

import crypto from 'crypto';
import { EvidenceArtifact, EvidenceType, EvidenceFreshness, ChainOfCustody } from './types';

export interface RawEvidenceInput {
  type: EvidenceType;
  source: string;
  title: string;
  properties: Record<string, any>;
  ttlHours?: number;
}

export class EvidenceCollector {
  private static readonly DISALLOWED_PROPERTY_KEYS = [
    'privatekey',
    'secretkey',
    'secret',
    'rawkey',
    'seed',
    'plaintext',
    'password',
    'token',
    'credential',
    'sessiontoken',
    'dek',
    'kek_raw',
  ];

  /**
   * Sanitizes evidence properties to ensure no raw private keys, plaintexts,
   * or confidential secrets can ever leak into evidence stores.
   */
  public static sanitizeProperties(raw: Record<string, any>): Record<string, any> {
    const sanitized: Record<string, any> = {};

    for (const [key, val] of Object.entries(raw)) {
      const lowerKey = key.toLowerCase().replace(/[^a-z0-9]/g, '');

      // Check if property key contains any disallowed sensitive term
      const isDisallowed = this.DISALLOWED_PROPERTY_KEYS.some((bad) => lowerKey.includes(bad));

      if (isDisallowed) {
        // Redact or omit sensitive value
        sanitized[key] = '[REDACTED_CONFIDENTIAL_KEY_MATERIAL]';
      } else if (val && typeof val === 'object' && !Array.isArray(val)) {
        sanitized[key] = this.sanitizeProperties(val);
      } else {
        sanitized[key] = val;
      }
    }

    return sanitized;
  }

  /**
   * Deterministically canonicalizes an object to produce reproducible JSON strings
   * for cryptographic digest verification.
   */
  public static canonicalize(obj: any): string {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
      return '[' + obj.map((item) => this.canonicalize(item)).join(',') + ']';
    }
    const sortedKeys = Object.keys(obj).sort();
    const pairs = sortedKeys.map((k) => `${JSON.stringify(k)}:${this.canonicalize(obj[k])}`);
    return '{' + pairs.join(',') + '}';
  }

  /**
   * Computes SHA-256 cryptographic digest of canonicalized object.
   */
  public static computeDigest(obj: any): string {
    const canonical = this.canonicalize(obj);
    return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
  }

  /**
   * Evaluates evidence freshness based on collection timestamp and TTL.
   */
  public static evaluateFreshness(collectedAt: string, expiresAt: string): EvidenceFreshness {
    const now = Date.now();
    const expiry = new Date(expiresAt).getTime();
    const collected = new Date(collectedAt).getTime();

    if (now > expiry) {
      return 'EXPIRED';
    }

    const age = now - collected;
    const ttl = expiry - collected;

    // If more than 75% through its validity window, mark as stale
    if (age > ttl * 0.75) {
      return 'STALE';
    }

    return 'VALID';
  }

  /**
   * Creates a verifiable, tamper-evident EvidenceArtifact with SHA-256 digest
   * and chain-of-custody tracking.
   */
  public static createArtifact(orgId: string, input: RawEvidenceInput): EvidenceArtifact {
    const sanitizedProps = this.sanitizeProperties(input.properties);
    const digest = this.computeDigest(sanitizedProps);

    const now = new Date();
    const ttlHours = input.ttlHours || 24;
    const expiry = new Date(now.getTime() + ttlHours * 60 * 60 * 1000);

    const collectedAt = now.toISOString();
    const expiresAt = expiry.toISOString();

    const id = `evi_${input.type.toLowerCase()}_${digest.slice(0, 12)}`;

    const chainOfCustody: ChainOfCustody = {
      collector: 'amaracus-assurance-agent',
      sourceHost: 'amaracus-control-plane',
      timestamp: collectedAt,
      digestAlgorithm: 'SHA-256',
    };

    const freshness = this.evaluateFreshness(collectedAt, expiresAt);

    return {
      id,
      orgId,
      type: input.type,
      source: input.source,
      title: input.title,
      collectedAt,
      expiresAt,
      digest,
      freshness,
      properties: sanitizedProps,
      chainOfCustody,
    };
  }

  /**
   * Verifies the cryptographic integrity of an EvidenceArtifact.
   * Returns true if the stored digest matches the recalculated digest.
   */
  public static verifyIntegrity(artifact: EvidenceArtifact): boolean {
    const recalculated = this.computeDigest(artifact.properties);
    return recalculated === artifact.digest;
  }
}
