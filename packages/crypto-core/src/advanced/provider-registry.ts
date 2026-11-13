/**
 * AMARACUS — Phase 9: Advanced Crypto Provider Registry
 * Catalogs providers, supported schemes, operations, and readiness statuses.
 * Strictly avoids advertising unsupported or unverified capabilities.
 */

import { AdvancedProviderCapability } from './types';

export class AdvancedCryptoProviderRegistry {
  private static providers: AdvancedProviderCapability[] = [
    {
      family: 'ZK',
      providerId: 'zk-noble-schnorr-nizk',
      name: 'Noble Poseidon/Schnorr NIZK Provider',
      implementation: '@noble/curves (Ed25519 & BN254) + SHA-256 / Poseidon',
      supportedSchemes: ['NIZK_SCHNORR_PEDERSEN'],
      supportedOperations: ['PROVE', 'VERIFY'],
      status: 'SUPPORTED',
      version: '1.0.0',
      description: 'Non-interactive zero-knowledge proofs of discrete logarithm and commitment preimages using Fiat-Shamir transformation.',
      limitations: {
        maxConstraintCount: 1000,
        maxStatementSizeKB: 64,
        supportsGeneralR1cs: false
      }
    },
    {
      family: 'ZK',
      providerId: 'zk-groth16-snark',
      name: 'R1CS Groth16 zk-SNARK Engine',
      implementation: 'Generic R1CS Constraint Evaluator',
      supportedSchemes: ['GROTH16_R1CS'],
      supportedOperations: ['VERIFY'],
      status: 'EXPERIMENTAL',
      version: '0.9.0',
      description: 'Experimental constraint system verification for general arithmetic circuits.',
      limitations: {
        trustedSetupRequired: true,
        proverServerSide: false
      }
    },
    {
      family: 'FHE',
      providerId: 'fhe-microsoft-seal',
      name: 'Microsoft SEAL Homomorphic Encryption Provider',
      implementation: 'node-seal (Microsoft SEAL 4.x/3.x WebAssembly)',
      supportedSchemes: ['BFV'],
      supportedOperations: ['ADD', 'SUBTRACT', 'MULTIPLY', 'NEGATE'],
      status: 'SUPPORTED',
      version: '6.0.3',
      description: 'Brakerski/Fan-Vercauteren (BFV) lattice-based exact integer homomorphic encryption with batch encoding.',
      limitations: {
        maxPolyModulusDegree: 8192,
        maxMultiplicationDepth: 4,
        noiseBudgetEnforced: true,
        supportsRealNumbers: false // BFV is exact integer only
      }
    },
    {
      family: 'FHE',
      providerId: 'fhe-seal-ckks',
      name: 'Microsoft SEAL CKKS Approximate Provider',
      implementation: 'node-seal CKKS scheme',
      supportedSchemes: ['CKKS'],
      supportedOperations: ['ADD', 'MULTIPLY'],
      status: 'EXPERIMENTAL',
      version: '6.0.3',
      description: 'Cheon-Kim-Kim-Song (CKKS) approximate real-number homomorphic arithmetic.',
      limitations: {
        approximateOnly: true,
        precisionLossOnMultiply: true
      }
    },
    {
      family: 'MPC',
      providerId: 'mpc-additive-sharing',
      name: 'Additive Secret Sharing Multi-Party Protocol',
      implementation: 'Native AMARACUS Cryptographic Core over Z_p',
      supportedSchemes: ['ADDITIVE_SECRET_SHARING'],
      supportedOperations: ['SECURE_SUM', 'SECURE_AVERAGE', 'SECURE_COUNT'],
      status: 'SUPPORTED',
      version: '1.0.0',
      description: 'Secure multi-party aggregation protocol where each party partitions secret inputs into blinded shares.',
      limitations: {
        maxParties: 20,
        operationType: 'AGGREGATION_ONLY',
        requiresAllPartiesForRound: true
      }
    },
    {
      family: 'THRESHOLD',
      providerId: 'threshold-shamir-gf256',
      name: 'Shamir Secret Sharing GF(2^8) Provider',
      implementation: 'shamir-secret-sharing',
      supportedSchemes: ['SHAMIR_M_OF_N'],
      supportedOperations: ['THRESHOLD_AUTHORIZATION', 'THRESHOLD_DECRYPT'],
      status: 'SUPPORTED',
      version: '0.0.4',
      description: 'Independently audited Galois field polynomial secret sharing for M-of-N key recovery.',
      limitations: {
        minThreshold: 2,
        maxParticipants: 255
      }
    },
    {
      family: 'THRESHOLD',
      providerId: 'threshold-frost-ed25519',
      name: 'FROST / Threshold Schnorr Signing Provider',
      implementation: '@noble/curves (Ed25519) + Lagrange Polynomial Interpolation',
      supportedSchemes: ['ED25519_FROST'],
      supportedOperations: ['THRESHOLD_SIGN'],
      status: 'SUPPORTED',
      version: '1.0.0',
      description: 'Distributed threshold digital signatures without central reconstruction of the private key.',
      limitations: {
        minThreshold: 2,
        maxParticipants: 20
      }
    }
  ];

  public static listProviders(): AdvancedProviderCapability[] {
    return [...this.providers];
  }

  public static getProvider(providerId: string): AdvancedProviderCapability | undefined {
    return this.providers.find(p => p.providerId === providerId);
  }

  public static getProvidersByFamily(family: string): AdvancedProviderCapability[] {
    return this.providers.filter(p => p.family === family);
  }
}
