/**
 * AMARACUS Cryptographic Infrastructure — Global Mandatory Safety Policy
 *
 * Immutable security floor established by AMARACUS root governance.
 * Under no circumstances can a tenant, project, or environment policy weaken
 * or override these restrictions.
 */

import { PolicyDocument } from './types';

export const GLOBAL_AMARACUS_SAFETY_POLICY: PolicyDocument = {
  id: 'AMARACUS_GLOBAL_SAFETY_BASELINE',
  name: 'AMARACUS Global Cryptographic Safety Baseline',
  version: '1.0.0',
  scope: 'GLOBAL',
  scopeId: null,
  description: 'Global immutable security floor prohibiting broken legacy cryptography and insecure parameters.',
  isActive: true,
  enforcementMode: 'ENFORCE',
  rules: [
    {
      id: 'RULE_PROHIBIT_BROKEN_HASHES',
      category: 'ALGORITHM_POLICY',
      name: 'Prohibit Cryptographically Broken Hashes',
      description: 'MD5 and SHA-1 are cryptographically broken with practical collision attacks.',
      effect: 'DENY',
      requirementType: 'DENY',
      priority: 1000,
      condition: {
        prohibitedAlgorithms: ['MD5', 'SHA-1', 'SHA1'],
      },
      remediation: 'Migrate immediately to SHA-256, SHA-384, SHA-512, or SHA3-256.',
    },
    {
      id: 'RULE_PROHIBIT_INSECURE_CIPHERS',
      category: 'ALGORITHM_POLICY',
      name: 'Prohibit Insecure Legacy Ciphers',
      description: 'DES, 3DES, and RC4 are fundamentally broken and vulnerable to plaintext recovery.',
      effect: 'DENY',
      requirementType: 'DENY',
      priority: 1000,
      condition: {
        prohibitedAlgorithms: ['DES', '3DES', 'TRIPLE-DES', 'RC4', 'ARCFOUR'],
      },
      remediation: 'Migrate immediately to authenticated encryption using AES-256-GCM or ChaCha20-Poly1305.',
    },
    {
      id: 'RULE_PROHIBIT_WEAK_ASYMMETRIC_KEYS',
      category: 'ALGORITHM_POLICY',
      name: 'Prohibit Sub-Standard Asymmetric Key Sizes',
      description: 'RSA keys under 2048 bits and ECC keys under 256 bits are vulnerable to factorization and discrete log attacks.',
      effect: 'DENY',
      requirementType: 'DENY',
      priority: 1000,
      condition: {
        prohibitedAlgorithms: ['RSA-512', 'RSA-1024', 'ECDSA-P192', 'EC-192'],
        minRsaBits: 2048,
        minEccBits: 256,
      },
      remediation: 'Use RSA with at least 2048 bits (3072/4096 recommended) or Ed25519 / ECDSA-P256.',
    },
    {
      id: 'RULE_PROHIBIT_DISABLED_KEYS',
      category: 'KEY_POLICY',
      name: 'Prohibit Operations on Inactive Keys',
      description: 'Cryptographic operations on disabled, revoked, or destroyed keys are strictly rejected.',
      effect: 'DENY',
      requirementType: 'DENY',
      priority: 1000,
      condition: {},
      remediation: 'Activate an authorized key or rotate to a newly provisioned key version.',
    },
  ],
};
