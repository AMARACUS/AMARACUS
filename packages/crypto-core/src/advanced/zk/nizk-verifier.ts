/**
 * AMARACUS — Phase 9: ZK Verifier
 * Verifies Non-Interactive Zero-Knowledge (NIZK) proofs without receiving the private witness.
 * Enforces circuit ID and version boundaries.
 */

import * as crypto from 'crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ZkCircuitDefinition, ZkProof, ZkStatement, ZkVerifyResult } from '../types';

export class ZkNizkVerifier {
  /**
   * Verify proof against circuit definition and public statement
   * The verifier does NOT receive or require the private witness.
   */
  public static verify(
    circuit: ZkCircuitDefinition,
    statement: ZkStatement,
    proof: ZkProof
  ): ZkVerifyResult {
    const startTime = Date.now();

    // 1. Boundary check: Proof circuit ID and version must strictly match
    if (proof.circuitId !== circuit.id) {
      return {
        valid: false,
        circuitId: circuit.id,
        version: circuit.version,
        error: `Proof circuit ID '${proof.circuitId}' does not match circuit definition '${circuit.id}'`,
        verifiedAt: new Date().toISOString(),
        durationMs: Date.now() - startTime
      };
    }

    if (proof.version !== circuit.version) {
      return {
        valid: false,
        circuitId: circuit.id,
        version: circuit.version,
        error: `Proof circuit version '${proof.version}' does not match circuit version '${circuit.version}'`,
        verifiedAt: new Date().toISOString(),
        durationMs: Date.now() - startTime
      };
    }

    // 2. Boundary check: Statement must match proof public inputs
    const statementCommitment = statement.publicInputs?.commitment;
    const proofCommitment = proof.publicInputs?.commitment;

    if (!statementCommitment || !proofCommitment) {
      return {
        valid: false,
        circuitId: circuit.id,
        version: circuit.version,
        error: "Missing required 'commitment' public input in statement or proof",
        verifiedAt: new Date().toISOString(),
        durationMs: Date.now() - startTime
      };
    }

    if (statementCommitment !== proofCommitment) {
      return {
        valid: false,
        circuitId: circuit.id,
        version: circuit.version,
        error: "Statement commitment does not match proof public input commitment",
        verifiedAt: new Date().toISOString(),
        durationMs: Date.now() - startTime
      };
    }

    // 3. Parse curve points and scalars
    const G = ed25519.Point.BASE;
    const l = ed25519.Point.Fn.ORDER;

    let C: any;
    let A: any;
    let s: bigint;

    try {
      C = ed25519.Point.fromHex(proofCommitment);
    } catch {
      return {
        valid: false,
        circuitId: circuit.id,
        version: circuit.version,
        error: "Invalid commitment curve point",
        verifiedAt: new Date().toISOString(),
        durationMs: Date.now() - startTime
      };
    }

    try {
      const A_hex = proof.proofData?.commitmentPointA;
      if (!A_hex) throw new Error("Missing commitmentPointA");
      A = ed25519.Point.fromHex(A_hex);
    } catch {
      return {
        valid: false,
        circuitId: circuit.id,
        version: circuit.version,
        error: "Invalid proof commitment point A",
        verifiedAt: new Date().toISOString(),
        durationMs: Date.now() - startTime
      };
    }

    try {
      const s_hex = proof.proofData?.responseScalarS;
      if (!s_hex) throw new Error("Missing responseScalarS");
      s = BigInt('0x' + s_hex) % l;
    } catch {
      return {
        valid: false,
        circuitId: circuit.id,
        version: circuit.version,
        error: "Invalid response scalar s",
        verifiedAt: new Date().toISOString(),
        durationMs: Date.now() - startTime
      };
    }

    // 4. Reconstruct Fiat-Shamir non-interactive challenge:
    // c = H("AMARACUS-NIZK-v1" || circuitId || version || C || A || publicInputs) mod l
    const A_hex = proof.proofData.commitmentPointA;
    const challengeData = `AMARACUS-NIZK-v1:${circuit.id}:${circuit.version}:${proofCommitment}:${A_hex}:${JSON.stringify(proof.publicInputs)}`;
    const hashHex = crypto.createHash('sha256').update(challengeData).digest('hex');
    const c = BigInt('0x' + hashHex) % l;

    // 5. Verification equation: s * G == A + c * C
    try {
      const left = G.multiply(s);
      const right = A.add(C.multiply(c));
      const valid = left.equals(right);

      return {
        valid,
        circuitId: circuit.id,
        version: circuit.version,
        error: valid ? undefined : 'Proof mathematical verification equation s*G == A + c*C failed',
        verifiedAt: new Date().toISOString(),
        durationMs: Date.now() - startTime
      };
    } catch (err: any) {
      return {
        valid: false,
        circuitId: circuit.id,
        version: circuit.version,
        error: `Verification error: ${err.message}`,
        verifiedAt: new Date().toISOString(),
        durationMs: Date.now() - startTime
      };
    }
  }
}
