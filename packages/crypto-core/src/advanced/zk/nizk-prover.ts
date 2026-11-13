/**
 * AMARACUS — Phase 9: ZK Prover
 * Generates Non-Interactive Zero-Knowledge (NIZK) Proofs via Fiat-Shamir
 * transformed Schnorr/Pedersen commitments without revealing the private witness.
 */

import * as crypto from 'crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ZkCircuitDefinition, ZkProof, ZkStatement, ZkWitness } from '../types';
import { CryptoEngineError } from '../../errors';

export class ZkNizkProver {
  /**
   * Prove knowledge of secret satisfying a public commitment
   * Private witness: { secretValue: string }
   * Public statement: { commitment: string }
   */
  public static prove(
    circuit: ZkCircuitDefinition,
    statement: ZkStatement,
    witness: ZkWitness
  ): ZkProof {
    // 1. Validate circuit ID and version match
    if (statement.circuitId !== circuit.id || statement.version !== circuit.version) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        `Statement circuit ID or version mismatch: statement expects ${statement.circuitId}:${statement.version}, circuit is ${circuit.id}:${circuit.version}`,
        400
      );
    }

    // 2. Validate witness has required private inputs
    const secretStr = witness.privateInputs?.secretValue;
    if (!secretStr) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        "Missing required private witness field 'secretValue'",
        400
      );
    }

    const commitmentHex = statement.publicInputs?.commitment;
    if (!commitmentHex) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        "Missing required public input 'commitment'",
        400
      );
    }

    const G = ed25519.Point.BASE;
    const l = ed25519.Point.Fn.ORDER;

    // 3. Parse witness scalar x
    let x: bigint;
    try {
      if (secretStr.startsWith('0x')) {
        x = BigInt(secretStr) % l;
      } else {
        x = BigInt(secretStr) % l;
      }
      if (x <= 0n) x += l;
    } catch {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        "Invalid witness 'secretValue': must be a valid numeric or hex string",
        400
      );
    }

    // 4. Verify witness satisfies public commitment: C == x * G
    let C_expected: any;
    try {
      C_expected = G.multiply(x);
    } catch (err: any) {
      throw new CryptoEngineError('INTERNAL_ERROR', `Curve multiplication failed: ${err.message}`, 500);
    }

    let C_actual: any;
    try {
      C_actual = ed25519.Point.fromHex(commitmentHex);
    } catch {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        "Invalid public input 'commitment': not a valid curve point hex",
        400
      );
    }

    if (!C_expected.equals(C_actual)) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        'Witness does not satisfy the public commitment statement',
        400
      );
    }

    // 5. Generate ephemeral random scalar v in [1, l - 1]
    const randomBytes = crypto.randomBytes(32);
    let v = BigInt('0x' + randomBytes.toString('hex')) % l;
    if (v <= 0n) v = 1n;

    // 6. Compute commitment point A = v * G
    const A = G.multiply(v);
    const A_hex = A.toHex();

    // 7. Compute Fiat-Shamir non-interactive challenge:
    // c = H("AMARACUS-NIZK-v1" || circuitId || version || C || A || publicInputs) mod l
    const challengeData = `AMARACUS-NIZK-v1:${circuit.id}:${circuit.version}:${commitmentHex}:${A_hex}:${JSON.stringify(statement.publicInputs)}`;
    const hashHex = crypto.createHash('sha256').update(challengeData).digest('hex');
    const c = BigInt('0x' + hashHex) % l;

    // 8. Compute response scalar: s = (v + c * x) mod l
    const s = (v + (c * x)) % l;

    // 9. Return Zero-Knowledge Proof (Zero secret witness exposure!)
    return {
      circuitId: circuit.id,
      version: circuit.version,
      provingSystem: circuit.provingSystem,
      publicInputs: statement.publicInputs,
      proofData: {
        commitmentPointA: A_hex,
        responseScalarS: s.toString(16),
        auxiliaryData: challengeData
      },
      timestamp: new Date().toISOString()
    };
  }
}
