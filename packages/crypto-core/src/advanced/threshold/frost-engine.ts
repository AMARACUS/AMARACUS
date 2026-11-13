/**
 * AMARACUS — Phase 9: FROST / Threshold Signature Engine
 * Implements threshold Schnorr/Ed25519 signatures where M-of-N participants
 * cooperatively sign without reconstructing the master private key on a central server.
 */

import * as crypto from 'crypto';
import { ed25519 } from '@noble/curves/ed25519.js';

export class FrostEngine {
  /**
   * Generates polynomial shares for M-of-N threshold Ed25519 key setup
   * f(x) = a0 + a1*x + ... + a_{m-1}*x^{m-1} mod l
   */
  public static generateThresholdKeyShares(
    threshold: number,
    totalParticipants: number
  ): {
    groupPublicKey: string;
    participantKeyShares: Array<{
      index: number;
      privateShareScalar: bigint;
      publicKeyShare: string;
    }>;
  } {
    const G = ed25519.Point.BASE;
    const l = ed25519.Point.Fn.ORDER;

    // Secret master scalar a0 in [1, l - 1]
    const masterSecretBytes = crypto.randomBytes(32);
    const a0 = (BigInt('0x' + masterSecretBytes.toString('hex')) % (l - 1n)) + 1n;
    const groupPublicKeyPoint = G.multiply(a0);

    // Polynomial coefficients: a1, a2, ..., a_{t-1}
    const coefficients: bigint[] = [a0];
    for (let i = 1; i < threshold; i++) {
      const randBytes = crypto.randomBytes(32);
      const coeff = (BigInt('0x' + randBytes.toString('hex')) % (l - 1n)) + 1n;
      coefficients.push(coeff);
    }

    // Evaluate polynomial for each participant: x = 1, 2, ..., N
    const participantKeyShares = [];
    for (let i = 1; i <= totalParticipants; i++) {
      const x = BigInt(i);
      let share = 0n;
      let xPower = 1n;

      for (let deg = 0; deg < threshold; deg++) {
        const term = (coefficients[deg] * xPower) % l;
        share = (share + term) % l;
        xPower = (xPower * x) % l;
      }

      const pubPoint = G.multiply(share);
      participantKeyShares.push({
        index: i,
        privateShareScalar: share,
        publicKeyShare: pubPoint.toHex()
      });
    }

    return {
      groupPublicKey: groupPublicKeyPoint.toHex(),
      participantKeyShares
    };
  }

  /**
   * Compute Lagrange interpolation coefficient lambda_i for participant in set S
   * lambda_i = product_{j in S, j != i} (-j) / (i - j) mod l
   */
  public static computeLagrangeCoefficient(
    participantIndex: number,
    participatingIndices: number[]
  ): bigint {
    const l = ed25519.Point.Fn.ORDER;
    let num = 1n;
    let den = 1n;

    const xi = BigInt(participantIndex);

    for (const j of participatingIndices) {
      if (j === participantIndex) continue;
      const xj = BigInt(j);
      // num = num * (-xj) mod l
      num = (num * ((l - xj) % l)) % l;
      // den = den * (xi - xj) mod l
      const diff = ((xi - xj) % l + l) % l;
      den = (den * diff) % l;
    }

    // Fermat's little theorem for modular inverse: den^(l - 2) mod l
    const denInv = this.modPow(den, l - 2n, l);
    return (num * denInv) % l;
  }

  /**
   * Generates a partial signature share from a participant
   */
  public static generatePartialSignature(
    message: Uint8Array,
    privateShare: bigint,
    participantIndex: number,
    participatingIndices: number[],
    ephemeralNonceR: bigint
  ): bigint {
    const l = ed25519.Point.Fn.ORDER;
    const G = ed25519.Point.BASE;

    // Ephemeral public commitment point
    const R_point = G.multiply(ephemeralNonceR);

    // Fiat-Shamir challenge e = H(R || message) mod l
    const hash = crypto.createHash('sha256').update(R_point.toHex()).update(message).digest('hex');
    const e = BigInt('0x' + hash) % l;

    // Lagrange coefficient for this participant
    const lambda = this.computeLagrangeCoefficient(participantIndex, participatingIndices);

    // s_i = (k_i + e * lambda_i * x_i) mod l
    const s_i = (ephemeralNonceR + (e * lambda * privateShare)) % l;
    return s_i;
  }

  /**
   * Combine partial signatures into a full threshold signature
   */
  public static combinePartialSignatures(
    partialSignatures: bigint[]
  ): bigint {
    const l = ed25519.Point.Fn.ORDER;
    let s_total = 0n;
    for (const s_i of partialSignatures) {
      s_total = (s_total + s_i) % l;
    }
    return s_total;
  }

  private static modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let res = 1n;
    let b = base % mod;
    let e = exp;
    while (e > 0n) {
      if (e % 2n === 1n) res = (res * b) % mod;
      b = (b * b) % mod;
      e /= 2n;
    }
    return res;
  }
}
