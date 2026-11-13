/**
 * AMARACUS — Phase 9: Additive Secret Sharing Engine for MPC
 * Implements standard additive secret sharing over prime field Z_p.
 * Enables secure multi-party aggregation without revealing individual raw inputs.
 */

import * as crypto from 'crypto';

export class AdditiveSharing {
  // 64-bit safe prime modulus for secret sharing computations
  public static readonly FIELD_MODULUS = 2147483647n; // 2^31 - 1 (Mersenne prime)

  /**
   * Split a private integer secret into N additive shares
   * x_1 + x_2 + ... + x_N == secret (mod p)
   */
  public static split(secret: number, numParties: number): bigint[] {
    if (numParties < 2) {
      throw new Error('Number of parties must be at least 2');
    }

    const p = this.FIELD_MODULUS;
    const secBig = ((BigInt(secret) % p) + p) % p;
    const shares: bigint[] = [];
    let sumRandom = 0n;

    for (let i = 0; i < numParties - 1; i++) {
      const randBytes = crypto.randomBytes(4);
      const randVal = (BigInt('0x' + randBytes.toString('hex')) % p + p) % p;
      shares.push(randVal);
      sumRandom = (sumRandom + randVal) % p;
    }

    // Last share completes the sum: share_N = secret - sum(shares_1..N-1) mod p
    const lastShare = ((secBig - sumRandom) % p + p) % p;
    shares.push(lastShare);

    return shares;
  }

  /**
   * Recombine party aggregated shares into the final sum
   */
  public static recombine(partySums: bigint[]): number {
    const p = this.FIELD_MODULUS;
    let total = 0n;
    for (const share of partySums) {
      total = (total + share) % p;
    }
    return Number(total);
  }
}
