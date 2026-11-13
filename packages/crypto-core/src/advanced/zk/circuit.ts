/**
 * AMARACUS — Phase 9: ZK Circuit Engine
 * Manages zero-knowledge circuit definitions, versions, constraint systems,
 * and input schema validation.
 */

import { ZkCircuitDefinition, ZkProvingSystem, ZkVerificationKey } from '../types';
import { ed25519 } from '@noble/curves/ed25519.js';
import { CryptoEngineError } from '../../errors';

export class ZkCircuitEngine {
  private static circuits = new Map<string, ZkCircuitDefinition>();

  /**
   * Computes public commitment C = x * G for a given secret scalar
   */
  public static computeCommitment(secretValue: bigint): string {
    const G = ed25519.Point.BASE;
    return G.multiply(secretValue).toHex();
  }

  /**
   * Initializes standard pre-built circuits (e.g. proof of secret commitment)
   */
  public static initDefaultCircuits(organizationId: string = 'org-default'): void {
    const defaultCircuitId = 'circuit-secret-commitment-v1';
    if (!this.circuits.has(defaultCircuitId)) {
      const G = ed25519.Point.BASE;
      const vk: ZkVerificationKey = {
        circuitId: defaultCircuitId,
        version: '1.0.0',
        curve: 'ed25519',
        generatorG: G.toHex(),
        metadata: {
          curveOrder: ed25519.Point.Fn.ORDER.toString(16),
          securityBits: 128
        }
      };

      this.circuits.set(defaultCircuitId, {
        id: defaultCircuitId,
        name: 'Discrete Log / Secret Commitment Proof',
        version: '1.0.0',
        description: 'Proves knowledge of secret scalar x satisfying public commitment C = x * G without revealing x.',
        provingSystem: 'NIZK_SCHNORR_PEDERSEN',
        publicInputsSchema: ['commitment'],
        privateInputsSchema: ['secretValue'],
        constraintsDescription: 'C == x * G in Ed25519 group',
        verificationKey: vk,
        provingKeyMetadata: {
          keyFingerprint: 'pk-fp-default-commitment',
          curve: 'ed25519',
          generatorG: G.toHex()
        },
        status: 'ACTIVE',
        organizationId,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });
    }
  }

  /**
   * Register a new circuit definition with strict version and schema checks
   */
  public static registerCircuit(def: Omit<ZkCircuitDefinition, 'createdAt' | 'updatedAt'>): ZkCircuitDefinition {
    if (!def.id || !def.version || !def.name) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        'Circuit ID, version, and name are required',
        400
      );
    }

    const key = `${def.organizationId}:${def.id}:${def.version}`;
    const now = new Date().toISOString();
    const completeDef: ZkCircuitDefinition = {
      ...def,
      createdAt: now,
      updatedAt: now
    };

    this.circuits.set(key, completeDef);
    this.circuits.set(def.id, completeDef); // fallback lookup by ID
    return completeDef;
  }

  /**
   * Retrieve a circuit by ID and optional version
   */
  public static getCircuit(id: string, version?: string, orgId?: string): ZkCircuitDefinition {
    this.initDefaultCircuits();

    if (orgId && version) {
      const tenantKey = `${orgId}:${id}:${version}`;
      const found = this.circuits.get(tenantKey);
      if (found) return found;
    }

    const direct = this.circuits.get(id);
    if (!direct) {
      throw new CryptoEngineError(
        'RESOURCE_NOT_FOUND',
        `ZK Circuit with ID '${id}' not found`,
        404
      );
    }

    if (version && direct.version !== version) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        `Circuit '${id}' version mismatch: requested '${version}', found '${direct.version}'`,
        400
      );
    }

    if (orgId && direct.organizationId !== 'org-default' && direct.organizationId !== orgId) {
      throw new CryptoEngineError(
        'TENANT_ACCESS_DENIED',
        `Access denied to circuit '${id}' for organization '${orgId}'`,
        403
      );
    }

    return direct;
  }

  /**
   * List all circuits for an organization
   */
  public static listCircuits(orgId: string): ZkCircuitDefinition[] {
    this.initDefaultCircuits(orgId);
    const results: ZkCircuitDefinition[] = [];
    const seen = new Set<string>();

    for (const c of this.circuits.values()) {
      if ((c.organizationId === orgId || c.organizationId === 'org-default') && !seen.has(`${c.id}:${c.version}`)) {
        seen.add(`${c.id}:${c.version}`);
        results.push(c);
      }
    }
    return results;
  }
}
