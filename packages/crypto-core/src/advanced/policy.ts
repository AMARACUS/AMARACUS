/**
 * AMARACUS — Phase 9: Advanced Crypto Policy Engine
 * Validates advanced cryptographic operations against organization policy.
 */

import { AdvancedCryptoPolicyConfig, FheScheme, MpcProtocol, ZkProvingSystem } from './types';
import { CryptoEngineError } from '../errors';

export class AdvancedCryptoPolicyEngine {
  public static readonly DEFAULT_POLICY: AdvancedCryptoPolicyConfig = {
    allowedZkSystems: ['NIZK_SCHNORR_PEDERSEN'],
    allowedFheSchemes: ['BFV'],
    allowedMpcProtocols: ['ADDITIVE_SECRET_SHARING'],
    minThresholdParticipants: 2,
    maxThresholdParticipants: 30,
    allowExperimental: false,
    maxFhePolyModulusDegree: 8192
  };

  /**
   * Validate ZK circuit proving system against policy
   */
  public static validateZkSystem(system: ZkProvingSystem, config: AdvancedCryptoPolicyConfig = this.DEFAULT_POLICY): void {
    if (!config.allowedZkSystems.includes(system)) {
      throw new CryptoEngineError(
        'POLICY_VIOLATION',
        `ZK proving system '${system}' is not permitted by active organization policy. Allowed: ${config.allowedZkSystems.join(', ')}`,
        403
      );
    }
  }

  /**
   * Validate FHE scheme and polynomial modulus against policy
   */
  public static validateFheScheme(scheme: FheScheme, polyModulus: number, config: AdvancedCryptoPolicyConfig = this.DEFAULT_POLICY): void {
    if (!config.allowedFheSchemes.includes(scheme)) {
      throw new CryptoEngineError(
        'POLICY_VIOLATION',
        `FHE scheme '${scheme}' is not permitted by policy. Allowed schemes: ${config.allowedFheSchemes.join(', ')}`,
        403
      );
    }
    if (polyModulus > config.maxFhePolyModulusDegree) {
      throw new CryptoEngineError(
        'POLICY_VIOLATION',
        `FHE polynomial modulus degree ${polyModulus} exceeds maximum allowed (${config.maxFhePolyModulusDegree})`,
        403
      );
    }
  }

  /**
   * Validate MPC protocol against policy
   */
  public static validateMpcProtocol(protocol: MpcProtocol, config: AdvancedCryptoPolicyConfig = this.DEFAULT_POLICY): void {
    if (!config.allowedMpcProtocols.includes(protocol)) {
      throw new CryptoEngineError(
        'POLICY_VIOLATION',
        `MPC protocol '${protocol}' is not permitted by active organization policy.`,
        403
      );
    }
  }

  /**
   * Validate threshold quorum against policy
   */
  public static validateThreshold(threshold: number, total: number, config: AdvancedCryptoPolicyConfig = this.DEFAULT_POLICY): void {
    if (threshold < config.minThresholdParticipants) {
      throw new CryptoEngineError(
        'POLICY_VIOLATION',
        `Threshold of ${threshold} is below the policy minimum of ${config.minThresholdParticipants}`,
        403
      );
    }
    if (total > config.maxThresholdParticipants) {
      throw new CryptoEngineError(
        'POLICY_VIOLATION',
        `Total participants (${total}) exceeds policy maximum of ${config.maxThresholdParticipants}`,
        403
      );
    }
  }
}
