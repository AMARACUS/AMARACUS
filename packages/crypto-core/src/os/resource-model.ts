/**
 * @file packages/crypto-core/src/os/resource-model.ts
 * Unified Cryptographic Resource Model & Lifecycle Transition Rules (Phase 20)
 */

import { CryptoResourceType, ResourceLifecycleStage, UnifiedResource } from './types';

/**
 * Permitted lifecycle stages per cryptographic resource type.
 */
export const RESOURCE_LIFECYCLE_STAGES: Record<CryptoResourceType, ResourceLifecycleStage[]> = {
  KEY: [
    'DISCOVERY',
    'CONFIGURATION',
    'ACTIVATION',
    'MONITORING',
    'ROTATION',
    'MIGRATION',
    'DEACTIVATION',
    'RETIREMENT',
  ],
  KEY_VERSION: ['ACTIVATION', 'MONITORING', 'DEACTIVATION', 'RETIREMENT'],
  CERTIFICATE: [
    'DISCOVERY',
    'CONFIGURATION',
    'ACTIVATION',
    'MONITORING',
    'ROTATION',
    'RETIREMENT',
  ],
  POLICY: ['CONFIGURATION', 'APPROVAL', 'ACTIVATION', 'MONITORING', 'RETIREMENT'],
  PROVIDER: ['CONFIGURATION', 'ACTIVATION', 'MONITORING', 'DEACTIVATION'],
  ALGORITHM: ['DISCOVERY', 'ASSESSMENT', 'ACTIVATION', 'DEACTIVATION', 'RETIREMENT'],
  MIGRATION: ['ASSESSMENT', 'CONFIGURATION', 'APPROVAL', 'ACTIVATION', 'MONITORING', 'RETIREMENT'],
  OPERATION: ['ACTIVATION', 'MONITORING', 'RETIREMENT'],
  CBOM_ASSET: ['DISCOVERY', 'ASSESSMENT', 'MONITORING'],
  APPLICATION: ['DISCOVERY', 'CONFIGURATION', 'MONITORING'],
  SERVICE_IDENTITY: ['CONFIGURATION', 'ACTIVATION', 'DEACTIVATION', 'RETIREMENT'],
  API_CREDENTIAL: ['CONFIGURATION', 'ACTIVATION', 'ROTATION', 'DEACTIVATION', 'RETIREMENT'],
  ORGANIZATION: ['CONFIGURATION', 'ACTIVATION', 'MONITORING'],
  PROJECT: ['CONFIGURATION', 'ACTIVATION', 'MONITORING'],
  ENVIRONMENT: ['CONFIGURATION', 'ACTIVATION', 'MONITORING'],
};

/**
 * Validates whether a resource can transition between two lifecycle stages.
 */
export function canTransitionLifecycle(
  resourceType: CryptoResourceType,
  fromStage: ResourceLifecycleStage,
  toStage: ResourceLifecycleStage
): { allowed: boolean; reason?: string } {
  const allowedStages = RESOURCE_LIFECYCLE_STAGES[resourceType] || [];

  if (!allowedStages.includes(fromStage)) {
    return {
      allowed: false,
      reason: `Stage ${fromStage} is not valid for resource type ${resourceType}`,
    };
  }

  if (!allowedStages.includes(toStage)) {
    return {
      allowed: false,
      reason: `Target stage ${toStage} is not valid for resource type ${resourceType}`,
    };
  }

  // Common invalid state transitions:
  // Cannot transition out of RETIREMENT (terminal state)
  if (fromStage === 'RETIREMENT' && toStage !== 'RETIREMENT') {
    return {
      allowed: false,
      reason: `Cannot transition out of terminal state RETIREMENT. A new resource must be provisioned.`,
    };
  }

  // Keys cannot be directly ACTIVATED from RETIREMENT or DEACTIVATION without re-configuration
  if (resourceType === 'KEY' && fromStage === 'DEACTIVATION' && toStage === 'ACTIVATION') {
    return {
      allowed: false,
      reason: `Deactivated keys require administrative re-approval and configuration before reactivation.`,
    };
  }

  return { allowed: true };
}

/**
 * Validates resource relationship boundaries (tenant isolation & hierarchy).
 */
export function validateResourceRelationships(
  parent: { orgId: string; projectId?: string; envId?: string },
  child: { orgId: string; projectId?: string; envId?: string }
): { valid: boolean; reason?: string } {
  if (parent.orgId !== child.orgId) {
    return {
      valid: false,
      reason: `Cross-organization boundary violation: parent org (${parent.orgId}) !== child org (${child.orgId})`,
    };
  }

  if (parent.projectId && child.projectId && parent.projectId !== child.projectId) {
    return {
      valid: false,
      reason: `Cross-project boundary violation: parent project (${parent.projectId}) !== child project (${child.projectId})`,
    };
  }

  if (parent.envId && child.envId && parent.envId !== child.envId) {
    return {
      valid: false,
      reason: `Cross-environment boundary violation: parent env (${parent.envId}) !== child env (${child.envId})`,
    };
  }

  return { valid: true };
}
