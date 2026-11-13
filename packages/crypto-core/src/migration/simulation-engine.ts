/**
 * AMARACUS Cryptographic Migration Platform — Non-Destructive Simulation Engine
 *
 * Evaluates migration plans in a simulated sandbox environment without modifying
 * production keys, mutating policies, revoking certificates, or altering live applications.
 *
 * Workflow:
 * Draft Plan -> Dependency Analysis -> Compatibility Checks -> Phase 15 Policy Evaluation -> Impact Report
 */

import crypto from 'crypto';
import {
  MigrationPlan,
  MigrationSimulationReport,
} from './types';
import { MigrationCompatibilityChecker } from './compatibility-checker';
import { MigrationDependencyGraphBuilder, GraphAssetInput } from './dependency-graph';
import { PolicyDocument } from '../policy-engine/types';

export interface SimulationContext {
  activePolicyDocument?: PolicyDocument | null;
  knownAssets?: GraphAssetInput[];
}

export class MigrationSimulationEngine {
  /**
   * Run a completely non-destructive simulation for a migration plan.
   */
  public static simulate(
    plan: MigrationPlan,
    context: SimulationContext = {}
  ): MigrationSimulationReport {
    const simulationId = `sim_${crypto.randomUUID()}`;
    const simulatedAt = new Date().toISOString();

    // 1. Compatibility & Policy Check
    const compatibility = MigrationCompatibilityChecker.check({
      targetAlgorithm: plan.targetAlgorithm,
      sourceAlgorithm: plan.sourceAlgorithm,
      targetProvider: plan.targetProvider || 'software',
      sourceProvider: plan.sourceProvider || 'software',
      organizationId: plan.organizationId,
      projectId: plan.projectId || undefined,
      environmentType: 'PRODUCTION',
      activePolicyDocument: context.activePolicyDocument,
    });

    // 2. Dependency Analysis
    const sourceAsset: GraphAssetInput = {
      id: plan.sourceResourceId,
      name: plan.name,
      assetType: plan.migrationType === 'CERTIFICATE_REPLACEMENT' ? 'CERTIFICATE' : 'KEY',
      algorithm: plan.sourceAlgorithm,
      provider: plan.sourceProvider || undefined,
    };

    const depGraph = MigrationDependencyGraphBuilder.buildGraph(
      sourceAsset,
      context.knownAssets || []
    );

    const impactedAssets = depGraph.nodes.map((n) => n.name);
    const dependencyImpact = depGraph.edges.map(
      (e) => `${e.from} --[${e.relationship}]--> ${e.to}`
    );

    // 3. Rollback Feasibility Assessment
    let rollbackAvailable = true;
    let rollbackType: 'AUTOMATIC_REVERSIBLE' | 'MANUAL_RESTORE' | 'IRREVERSIBLE' =
      'AUTOMATIC_REVERSIBLE';

    if (plan.migrationType === 'DATA_RE_ENCRYPTION') {
      rollbackType = 'MANUAL_RESTORE';
      rollbackAvailable = true; // Rollback possible from pre-migration backup/checkpoint
    } else if (plan.category === 'CATEGORY_C_APPLICATION_MANAGED') {
      rollbackType = 'MANUAL_RESTORE';
      rollbackAvailable = true; // Requires application git revert
    } else {
      rollbackType = 'AUTOMATIC_REVERSIBLE';
      rollbackAvailable = true; // AMARACUS can atomically swap active key pointers back
    }

    // 4. Commercial & Resource Estimation
    let estimatedBillableOps = 1;
    let estimatedDataBytes = 0;
    let estimatedExecutionDurationMs = 250;

    if (plan.migrationType === 'DATA_RE_ENCRYPTION') {
      estimatedBillableOps = 100; // Estimated chunked operations
      estimatedDataBytes = 10 * 1024 * 1024; // 10MB nominal estimate
      estimatedExecutionDurationMs = 5000;
    } else if (plan.migrationType === 'POST_QUANTUM_MIGRATION') {
      estimatedExecutionDurationMs = 450;
    }

    // 5. Build Recommendations
    const recommendations: string[] = [];
    if (compatibility.warnings.length > 0) {
      recommendations.push(...compatibility.warnings);
    }
    if (depGraph.isIncomplete) {
      recommendations.push(
        'Dependency graph is incomplete. Verify all downstream microservices support target algorithm before production execution.'
      );
    }
    if (rollbackType === 'MANUAL_RESTORE') {
      recommendations.push(
        'Data transformation is non-atomic. Ensure database snapshots or envelope checkpoints are verified prior to execution.'
      );
    }
    if (compatibility.compatible) {
      recommendations.push('Plan satisfies all pre-flight compatibility and policy constraints. Ready for authorized review.');
    } else {
      recommendations.push('Plan has blocking compatibility issues. Review blocking issues before requesting approval.');
    }

    const overallSafe = compatibility.compatible && !compatibility.blockingIssues.length;

    return {
      simulationId,
      planId: plan.id,
      simulatedAt,
      overallSafe,
      compatibility,
      impactedAssets,
      dependencyImpact,
      estimatedExecutionDurationMs,
      rollbackAvailable,
      rollbackType,
      commercialImpact: {
        estimatedBillableOps,
        estimatedDataBytes,
      },
      recommendations,
    };
  }
}
