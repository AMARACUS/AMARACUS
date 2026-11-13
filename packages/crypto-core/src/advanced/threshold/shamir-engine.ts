/**
 * AMARACUS — Phase 9: Shamir Secret Sharing Engine for Threshold Cryptography
 * Uses audited Galois field GF(2^8) polynomial secret sharing.
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { split, combine } = require('shamir-secret-sharing');

export class ShamirEngine {
  /**
   * Split a secret into N shares with threshold M
   */
  public static async split(
    secret: Uint8Array,
    shares: number,
    threshold: number
  ): Promise<Uint8Array[]> {
    if (threshold > shares) {
      throw new Error(`Threshold (${threshold}) cannot exceed total shares (${shares})`);
    }
    if (threshold < 2) {
      throw new Error('Threshold must be at least 2');
    }
    return split(secret, shares, threshold);
  }

  /**
   * Recombine M shares to reconstruct original secret
   */
  public static async combine(shares: Uint8Array[]): Promise<Uint8Array> {
    if (!shares || shares.length < 2) {
      throw new Error('At least 2 shares are required to reconstruct secret');
    }
    return combine(shares);
  }
}
