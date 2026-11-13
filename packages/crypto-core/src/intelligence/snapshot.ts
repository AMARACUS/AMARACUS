import crypto from 'crypto';
import {
  CryptoAssetItem,
  CryptoFindingItem,
  CryptoInventorySnapshotItem,
} from './types';

export interface SnapshotDriftResult {
  newAssets: CryptoAssetItem[];
  changedAssets: Array<{ asset: CryptoAssetItem; changeDescription: string }>;
  removedAssets: string[]; // Names / IDs of previously seen assets now missing
  unchangedAssets: CryptoAssetItem[];
}

export class SnapshotManager {
  /**
   * Compare current discovered assets with a previous snapshot's fingerprints to compute drift.
   */
  static computeDrift(
    currentAssets: CryptoAssetItem[],
    previousSnapshot?: CryptoInventorySnapshotItem | null
  ): SnapshotDriftResult {
    const newAssets: CryptoAssetItem[] = [];
    const changedAssets: Array<{ asset: CryptoAssetItem; changeDescription: string }> = [];
    const unchangedAssets: CryptoAssetItem[] = [];

    if (!previousSnapshot || !previousSnapshot.assetFingerprints) {
      // First scan: everything is new
      return {
        newAssets: currentAssets,
        changedAssets: [],
        removedAssets: [],
        unchangedAssets: [],
      };
    }

    const previousFingerprints = previousSnapshot.assetFingerprints;
    const currentAssetIds = new Set<string>();

    for (const asset of currentAssets) {
      currentAssetIds.add(asset.id);
      const prevFp = previousFingerprints[asset.id];

      if (!prevFp) {
        newAssets.push(asset);
      } else if (prevFp !== (asset.fingerprint || asset.algorithm)) {
        changedAssets.push({
          asset,
          changeDescription: `Fingerprint changed from ${prevFp} to ${asset.fingerprint || asset.algorithm}`,
        });
      } else {
        unchangedAssets.push(asset);
      }
    }

    // Identify removed assets (present in previous snapshot, missing from current scan)
    const removedAssets: string[] = [];
    for (const prevId of Object.keys(previousFingerprints)) {
      if (!currentAssetIds.has(prevId)) {
        removedAssets.push(prevId);
      }
    }

    return {
      newAssets,
      changedAssets,
      removedAssets,
      unchangedAssets,
    };
  }

  /**
   * Construct a persistable CryptoInventorySnapshotItem.
   */
  static createSnapshot(params: {
    organizationId: string;
    assets: CryptoAssetItem[];
    findings?: CryptoFindingItem[];
    previousSnapshot?: CryptoInventorySnapshotItem | null;
  }): CryptoInventorySnapshotItem {
    const { organizationId, assets, findings = [], previousSnapshot } = params;
    const now = new Date();
    const id = `snap_${crypto.randomUUID()}`;

    // Compute metrics
    const assetsByType: Record<string, number> = {};
    const quantumStatusSummary: Record<string, number> = {
      QUANTUM_VULNERABLE: 0,
      PQC: 0,
      HYBRID: 0,
      CLASSICAL: 0,
      UNKNOWN: 0,
    };
    const assetFingerprints: Record<string, string> = {};

    for (const a of assets) {
      assetsByType[a.assetType] = (assetsByType[a.assetType] || 0) + 1;
      quantumStatusSummary[a.quantumStatus] = (quantumStatusSummary[a.quantumStatus] || 0) + 1;
      assetFingerprints[a.id] = a.fingerprint || a.algorithm || 'unknown';
    }

    const findingsBySeverity: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    for (const f of findings) {
      findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] || 0) + 1;
    }

    // Compute drift
    const drift = this.computeDrift(assets, previousSnapshot);

    return {
      id,
      organizationId,
      snapshotDate: now,
      totalAssets: assets.length,
      assetsByType,
      findingsBySeverity,
      quantumStatusSummary,
      assetFingerprints,
      drift: {
        newAssets: drift.newAssets.map((a) => a.id),
        changedAssets: drift.changedAssets.map((c) => c.asset.id),
        removedAssets: drift.removedAssets,
        unchangedAssets: drift.unchangedAssets.map((a) => a.id),
      },
      metadata: {
        newCount: drift.newAssets.length,
        changedCount: drift.changedAssets.length,
        removedCount: drift.removedAssets.length,
        unchangedCount: drift.unchangedAssets.length,
      },
      createdAt: now,
    };
  }
}
