import crypto from 'crypto';
import {
  CryptoAssetItem,
  CryptoRelationshipItem,
  RelationshipType,
  DownstreamImpactResult,
  AssetType,
} from './types';

export class CryptoRelationshipGraph {
  private assets: Map<string, CryptoAssetItem> = new Map();
  // adjacency lists: source -> [{ targetId, type, relId }]
  private outgoing: Map<string, Array<{ targetId: string; type: RelationshipType; relId: string }>> = new Map();
  // reverse adjacency lists: target -> [{ sourceId, type, relId }]
  private incoming: Map<string, Array<{ sourceId: string; type: RelationshipType; relId: string }>> = new Map();

  constructor(assets: CryptoAssetItem[] = [], relationships: CryptoRelationshipItem[] = []) {
    for (const a of assets) {
      this.assets.set(a.id, a);
      this.outgoing.set(a.id, []);
      this.incoming.set(a.id, []);
    }
    for (const r of relationships) {
      this.addRelationship(r);
    }
  }

  addRelationship(r: CryptoRelationshipItem) {
    if (!this.outgoing.has(r.sourceAssetId)) {
      this.outgoing.set(r.sourceAssetId, []);
    }
    if (!this.incoming.has(r.targetAssetId)) {
      this.incoming.set(r.targetAssetId, []);
    }
    this.outgoing.get(r.sourceAssetId)!.push({ targetId: r.targetAssetId, type: r.relationshipType, relId: r.id });
    this.incoming.get(r.targetAssetId)!.push({ sourceId: r.sourceAssetId, type: r.relationshipType, relId: r.id });
  }

  /**
   * Automatically infer and synthesize canonical cryptographic relationships from asset metadata.
   */
  static inferRelationships(assets: CryptoAssetItem[], orgId: string): CryptoRelationshipItem[] {
    const relationships: CryptoRelationshipItem[] = [];
    const seen = new Set<string>();

    const addRel = (sourceId: string, targetId: string, type: RelationshipType) => {
      const key = `${sourceId}:${targetId}:${type}`;
      if (!seen.has(key) && sourceId !== targetId) {
        seen.add(key);
        relationships.push({
          id: `rel_${crypto.createHash('sha256').update(orgId + key).digest('hex').slice(0, 16)}`,
          organizationId: orgId,
          sourceAssetId: sourceId,
          targetAssetId: targetId,
          relationshipType: type,
          confidence: 'HIGH',
          createdAt: new Date(),
        });
      }
    };

    // Index assets for fast matching
    const assetsById = new Map<string, CryptoAssetItem>();
    const keysByRef = new Map<string, CryptoAssetItem>();
    const casById = new Map<string, CryptoAssetItem>();
    const algoAssets = new Map<string, CryptoAssetItem>();
    const providerAssets = new Map<string, CryptoAssetItem>();

    for (const a of assets) {
      assetsById.set(a.id, a);
      if (a.assetType === 'KEY') {
        const rawKeyId = a.metadata?.keyId || a.metadata?.registeredKeyId || a.id.replace(/^asset_key_/, '').replace(/^asset_byok_/, '');
        keysByRef.set(rawKeyId, a);
        keysByRef.set(a.id, a);
      } else if (a.assetType === 'CERTIFICATE_AUTHORITY') {
        const rawCaId = a.id.replace(/^asset_ca_/, '');
        casById.set(rawCaId, a);
        casById.set(a.id, a);
      } else if (a.assetType === 'ALGORITHM') {
        algoAssets.set(a.name.toUpperCase(), a);
      } else if (a.assetType === 'CRYPTO_PROVIDER') {
        providerAssets.set(a.name.toUpperCase(), a);
      }
    }

    // 1. Synthesize explicit Algorithm & Provider nodes if not already present
    const algorithmsToCreate = new Set<string>();
    const providersToCreate = new Set<string>();

    for (const a of assets) {
      if (a.algorithm) algorithmsToCreate.add(a.algorithm.toUpperCase());
      if (a.provider) providersToCreate.add(a.provider.toUpperCase());
    }

    // Connect assets
    for (const a of assets) {
      // Connect to Key Reference
      if (a.metadata?.keyReference) {
        const targetKey = keysByRef.get(a.metadata.keyReference);
        if (targetKey) {
          addRel(a.id, targetKey.id, 'ASSOCIATED_WITH');
        }
      }

      // Connect Certificate to CA
      if (a.assetType === 'CERTIFICATE' && a.metadata?.authorityId) {
        const targetCa = casById.get(a.metadata.authorityId);
        if (targetCa) {
          addRel(a.id, targetCa.id, 'ISSUED_BY');
        }
      }

      // Connect CA to Parent CA
      if (a.assetType === 'CERTIFICATE_AUTHORITY' && a.metadata?.parentAuthorityId) {
        const parentCa = casById.get(a.metadata.parentAuthorityId);
        if (parentCa) {
          addRel(a.id, parentCa.id, 'SIGNED_BY');
        }
      }
    }

    return relationships;
  }

  /**
   * Perform recursive downstream impact analysis.
   * "If this asset/algorithm/key is deprecated, revoked, or compromised, what is affected?"
   */
  getDownstreamImpact(assetId: string): DownstreamImpactResult {
    const targetAsset = this.assets.get(assetId);
    const affectedKeys = new Map<string, CryptoAssetItem>();
    const affectedCertificates = new Map<string, CryptoAssetItem>();
    const affectedApplications = new Map<string, CryptoAssetItem>();
    const affectedProviders = new Map<string, CryptoAssetItem>();
    const affectedEnvironments = new Set<string>();
    const visited = new Set<string>();
    const dependencyPath: string[] = [];

    if (!targetAsset) {
      return {
        assetId,
        assetName: 'Unknown',
        assetType: 'ALGORITHM',
        affectedKeys: [],
        affectedCertificates: [],
        affectedApplications: [],
        affectedProviders: [],
        affectedEnvironments: [],
        totalAffected: 0,
        dependencyPath: [],
      };
    }

    // If targetAsset is an algorithm, direct matches across all assets that use this algorithm
    if (targetAsset.assetType === 'ALGORITHM' || targetAsset.algorithm) {
      const algoName = (targetAsset.algorithm || targetAsset.name).toUpperCase();
      this.assets.forEach((a, id) => {
        if (id !== assetId && a.algorithm && a.algorithm.toUpperCase() === algoName) {
          this.categorizeAsset(a, affectedKeys, affectedCertificates, affectedApplications, affectedProviders, affectedEnvironments);
        }
      });
    }

    // Recursive traversal: search incoming edges (assets that DEPEND ON or USE this asset)
    const queue = [assetId];
    visited.add(assetId);

    while (queue.length > 0) {
      const currentId = queue.shift()!;
      const currentAsset = this.assets.get(currentId);
      if (currentAsset) {
        dependencyPath.push(`${currentAsset.assetType}:${currentAsset.name}`);
      }

      // 1. Assets pointing to currentId (incoming)
      const incomingEdges = this.incoming.get(currentId) || [];
      for (const edge of incomingEdges) {
        if (!visited.has(edge.sourceId)) {
          visited.add(edge.sourceId);
          queue.push(edge.sourceId);
          const childAsset = this.assets.get(edge.sourceId);
          if (childAsset) {
            this.categorizeAsset(childAsset, affectedKeys, affectedCertificates, affectedApplications, affectedProviders, affectedEnvironments);
          }
        }
      }

      // 2. If currentId is a Key, any certificate referencing this key
      if (currentAsset?.assetType === 'KEY') {
        const rawKeyId = currentAsset.metadata?.keyId || currentAsset.id.replace(/^asset_key_/, '');
        this.assets.forEach((other) => {
          if (other.metadata?.keyReference === rawKeyId || other.metadata?.keyReference === currentAsset.id) {
            if (!visited.has(other.id)) {
              visited.add(other.id);
              queue.push(other.id);
              this.categorizeAsset(other, affectedKeys, affectedCertificates, affectedApplications, affectedProviders, affectedEnvironments);
            }
          }
        });
      }

      // 3. If currentId is a CertificateAuthority, any certificate issued by it
      if (currentAsset?.assetType === 'CERTIFICATE_AUTHORITY') {
        const rawCaId = currentAsset.id.replace(/^asset_ca_/, '');
        this.assets.forEach((other) => {
          if (other.metadata?.authorityId === rawCaId || other.metadata?.authorityId === currentAsset.id) {
            if (!visited.has(other.id)) {
              visited.add(other.id);
              queue.push(other.id);
              this.categorizeAsset(other, affectedKeys, affectedCertificates, affectedApplications, affectedProviders, affectedEnvironments);
            }
          }
        });
      }
    }

    const keyList = Array.from(affectedKeys.values());
    const certList = Array.from(affectedCertificates.values());
    const appList = Array.from(affectedApplications.values());
    const provList = Array.from(affectedProviders.values());

    return {
      assetId,
      assetName: targetAsset.name,
      assetType: targetAsset.assetType,
      algorithm: targetAsset.algorithm,
      affectedKeys: keyList,
      affectedCertificates: certList,
      affectedApplications: appList,
      affectedProviders: provList,
      affectedEnvironments: Array.from(affectedEnvironments),
      totalAffected: keyList.length + certList.length + appList.length + provList.length,
      dependencyPath,
    };
  }

  private categorizeAsset(
    asset: CryptoAssetItem,
    keys: Map<string, CryptoAssetItem>,
    certs: Map<string, CryptoAssetItem>,
    apps: Map<string, CryptoAssetItem>,
    providers: Map<string, CryptoAssetItem>,
    environments: Set<string>
  ) {
    if (asset.environmentId) environments.add(asset.environmentId);

    switch (asset.assetType) {
      case 'KEY':
        keys.set(asset.id, asset);
        break;
      case 'CERTIFICATE':
      case 'CERTIFICATE_AUTHORITY':
        certs.set(asset.id, asset);
        break;
      case 'CRYPTO_LIBRARY':
      case 'CRYPTO_OPERATION':
      case 'CRYPTO_ENDPOINT':
        apps.set(asset.id, asset);
        break;
      case 'CRYPTO_PROVIDER':
        providers.set(asset.id, asset);
        break;
      default:
        apps.set(asset.id, asset);
        break;
    }
  }

  /**
   * Get upstream dependencies (what does this asset rely upon).
   */
  getUpstreamDependencies(assetId: string): CryptoAssetItem[] {
    const dependencies: CryptoAssetItem[] = [];
    const visited = new Set<string>();
    const queue = [assetId];
    visited.add(assetId);

    while (queue.length > 0) {
      const currentId = queue.shift()!;
      const outgoingEdges = this.outgoing.get(currentId) || [];
      for (const edge of outgoingEdges) {
        if (!visited.has(edge.targetId)) {
          visited.add(edge.targetId);
          queue.push(edge.targetId);
          const parent = this.assets.get(edge.targetId);
          if (parent) {
            dependencies.push(parent);
          }
        }
      }
    }

    return dependencies;
  }
}
