import { Request, Response, NextFunction } from 'express';
import { db } from './data-store';

export type PlanTier = 'FREE' | 'DEVELOPER' | 'BUSINESS' | 'ENTERPRISE' | 'PAY_AS_YOU_GO';

export type EntitlementKey = 'BYOK_AVAILABLE' | 'BYOK_HSM_AVAILABLE' | 'MAX_BYOK_PROVIDERS';

export interface PlanEntitlements {
  tier: PlanTier;
  byokAvailable: boolean;
  byokHsmAvailable: boolean;
  maxByokProviders: number;
}

export const PLAN_ENTITLEMENTS: Record<PlanTier, PlanEntitlements> = {
  FREE: {
    tier: 'FREE',
    byokAvailable: false,
    byokHsmAvailable: false,
    maxByokProviders: 0,
  },
  DEVELOPER: {
    tier: 'DEVELOPER',
    byokAvailable: false,
    byokHsmAvailable: false,
    maxByokProviders: 0,
  },
  PAY_AS_YOU_GO: {
    tier: 'PAY_AS_YOU_GO',
    byokAvailable: true,
    byokHsmAvailable: true,
    maxByokProviders: 5,
  },
  BUSINESS: {
    tier: 'BUSINESS',
    byokAvailable: true,
    byokHsmAvailable: true,
    maxByokProviders: 10,
  },
  ENTERPRISE: {
    tier: 'ENTERPRISE',
    byokAvailable: true,
    byokHsmAvailable: true,
    maxByokProviders: 100,
  },
};

import { entitlementEngine } from './entitlement-engine';

/**
 * Resolves an organization's plan tier authoritatively via the Phase 11 Entitlement Engine.
 */
export async function getOrganizationPlan(orgId: string): Promise<PlanEntitlements> {
  const plan = await entitlementEngine.getOrganizationPlan(orgId);

  if (plan.id === 'SELF_HOSTED') {
    // A self-hosted installation is not limited by Cloud plan tiers.
    return PLAN_ENTITLEMENTS.ENTERPRISE;
  }
  if (plan.id === 'BUSINESS') {
    return PLAN_ENTITLEMENTS.BUSINESS;
  }
  if (plan.id === 'PAYG') {
    return PLAN_ENTITLEMENTS.PAY_AS_YOU_GO;
  }
  if (plan.id === 'PRO' || plan.id === 'STARTER') {
    return PLAN_ENTITLEMENTS.DEVELOPER; // Starter and Pro do not include BYOK
  }

  // The billing subscription is the only source of paid entitlements.
  return PLAN_ENTITLEMENTS.FREE;
}

/**
 * Express middleware to enforce BYOK entitlement on routes.
 */
export function requireByokEntitlement() {
  return async (req: Request, res: Response, next: NextFunction) => {
    const orgId = req.params.orgId || (req as any).organizationId;
    if (!orgId) {
      return res.status(400).json({
        error: { code: 'MISSING_ORG_ID', message: 'Organization ID is required to check entitlements.' },
      });
    }

    const entitlements = await getOrganizationPlan(orgId);
    if (!entitlements.byokAvailable) {
      return res.status(403).json({
        error: {
          code: 'BYOK_ENTITLEMENT_REQUIRED',
          message: 'Bring Your Own Key (BYOK) is an enterprise feature available on Business and Pay-As-You-Go plans. Upgrade your plan to connect customer-owned Azure Key Vault or Managed HSM infrastructure.',
          currentTier: entitlements.tier,
        },
      });
    }

    next();
  };
}

const PLATFORM_VAULT_PROVIDERS = new Set(['AZURE_KEY_VAULT', 'AZURE_MANAGED_HSM']);

/**
 * Checks the `provider` requested for a new managed key. LOCAL_DEV is open to every plan;
 * keys in AMARACUS's Azure Key Vault / Managed HSM need the platformVaultKeys entitlement.
 * Returns null when allowed, otherwise the error to send.
 */
export async function checkManagedKeyProvider(
  orgId: string,
  provider: unknown
): Promise<{ status: number; code: string; message: string } | null> {
  if (provider === undefined || provider === null || provider === 'LOCAL_DEV') return null;
  if (typeof provider !== 'string' || !PLATFORM_VAULT_PROVIDERS.has(provider)) {
    return {
      status: 400,
      code: 'INVALID_INPUT',
      message: 'provider must be LOCAL_DEV, AZURE_KEY_VAULT or AZURE_MANAGED_HSM. Customer vaults are connected through BYOK.',
    };
  }
  const plan = await entitlementEngine.getOrganizationPlan(orgId);
  if (!plan.features.platformVaultKeys) {
    return {
      status: 403,
      code: 'PLATFORM_VAULT_ENTITLEMENT_REQUIRED',
      message: `Keys held in AMARACUS's Azure Key Vault or Managed HSM are available on the Business and Pay-As-You-Go plans.`,
    };
  }
  return null;
}
