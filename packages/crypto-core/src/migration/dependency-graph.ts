/**
 * AMARACUS Cryptographic Migration Platform — Dependency Graph & Impact Analysis
 *
 * Models and traces relationships: Application -> SDK -> Library -> Algorithm -> Key -> Provider
 * Marks incomplete graphs explicitly: Absence of evidence is NOT evidence of absence.
 */

import {
  MigrationDependencyGraph,
  MigrationDependencyNode,
  MigrationDependencyEdge,
} from './types';

export interface GraphAssetInput {
  id: string;
  name: string;
  assetType: 'KEY' | 'CERTIFICATE' | 'ALGORITHM' | 'LIBRARY' | 'APPLICATION' | 'PROVIDER';
  algorithm?: string;
  provider?: string;
  applications?: string[];
  libraries?: string[];
  metadata?: Record<string, any>;
}

export class MigrationDependencyGraphBuilder {
  /**
   * Constructs a typed dependency graph for a target asset.
   */
  public static buildGraph(
    targetAsset: GraphAssetInput,
    allAssets: GraphAssetInput[] = []
  ): MigrationDependencyGraph {
    const nodes: MigrationDependencyNode[] = [];
    const edges: MigrationDependencyEdge[] = [];
    const incompletenessReasons: string[] = [];

    // 1. Add target asset node
    const targetNode: MigrationDependencyNode = {
      id: targetAsset.id,
      type: targetAsset.assetType as any,
      name: targetAsset.name,
    };
    nodes.push(targetNode);

    // 2. Add Algorithm node
    if (targetAsset.algorithm) {
      const algId = `alg_${targetAsset.algorithm.toLowerCase().replace(/[^a-z0-9]/g, '_')}`;
      nodes.push({
        id: algId,
        type: 'ALGORITHM',
        name: targetAsset.algorithm,
      });
      edges.push({
        from: targetAsset.id,
        to: algId,
        relationship: 'USES_ALGORITHM',
      });
    } else {
      incompletenessReasons.push(`Algorithm parameter unspecified for asset '${targetAsset.name}'.`);
    }

    // 3. Add Provider node
    if (targetAsset.provider) {
      const provId = `prov_${targetAsset.provider.toLowerCase().replace(/[^a-z0-9]/g, '_')}`;
      nodes.push({
        id: provId,
        type: 'PROVIDER',
        name: targetAsset.provider,
      });
      edges.push({
        from: targetAsset.id,
        to: provId,
        relationship: 'BACKED_BY_PROVIDER',
      });
    } else {
      incompletenessReasons.push(`Upstream cryptographic provider not registered or unobserved for '${targetAsset.name}'.`);
    }

    // 4. Trace consuming applications & SDKs
    let hasKnownApplications = false;
    if (targetAsset.applications && targetAsset.applications.length > 0) {
      hasKnownApplications = true;
      for (const app of targetAsset.applications) {
        const appId = `app_${app.toLowerCase().replace(/[^a-z0-9]/g, '_')}`;
        nodes.push({
          id: appId,
          type: 'APPLICATION',
          name: app,
        });
        edges.push({
          from: appId,
          to: targetAsset.id,
          relationship: 'CONSUMES_KEY',
        });
      }
    }

    // Check relationship graph in allAssets
    for (const other of allAssets) {
      if (other.id === targetAsset.id) continue;

      if (
        other.metadata?.targetKeyId === targetAsset.id ||
        other.metadata?.keyId === targetAsset.id
      ) {
        hasKnownApplications = true;
        const otherNode: MigrationDependencyNode = {
          id: other.id,
          type: other.assetType as any,
          name: other.name,
        };
        nodes.push(otherNode);
        edges.push({
          from: other.id,
          to: targetAsset.id,
          relationship: 'DEPENDS_ON',
        });
      }
    }

    if (!hasKnownApplications) {
      incompletenessReasons.push(
        `No static or runtime application consumers were detected for asset '${targetAsset.name}'. ` +
        `Application call graph may be incomplete. Do not assume no external services rely on this resource.`
      );
    }

    const isIncomplete = incompletenessReasons.length > 0;

    return {
      nodes,
      edges,
      isIncomplete,
      incompletenessReasons,
    };
  }
}
