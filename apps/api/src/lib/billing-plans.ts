/**
 * Phase 11 — Authoritative Billing Plan Definitions & Capabilities
 *
 * This file serves as the single backend source of truth for:
 * - Pricing tiers (STARTER, PRO, BUSINESS, PAYG, FREE)
 * - Monthly base fees & unit economics
 * - Resource limits (projects, keys, members)
 * - Cryptographic operation allowances
 * - Feature entitlements (BYOK, HSM, PQC, FHE, ZK)
 */

import { resolvePolarProduct } from './billing-catalog';

/** The four AMARACUS Cloud plans, plus FREE (no active plan). */
export type CloudPlanId = 'FREE' | 'STARTER' | 'PRO' | 'BUSINESS' | 'PAYG';
/** SELF_HOSTED is the single "plan" of a self-hosted installation; it is never sold on Cloud. */
export type PlanId = CloudPlanId | 'SELF_HOSTED';

/**
 * AMARACUS Cloud's own Polar product IDs are defaults of the hosted service, so they live in
 * the Cloud-only module. The public source tree does not contain it: there every ID comes
 * from the environment or is absent.
 */
function cloudPolarDefault(name: string): string | undefined {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require('../cloud/polar-product-defaults').CLOUD_POLAR_DEFAULTS[name] || undefined;
  } catch {
    return undefined;
  }
}

function polarIdFromEnv(name: string): string | undefined {
  return process.env[name] || cloudPolarDefault(name);
}

export interface PlanFeatureEntitlements {
  byok: boolean;
  customerManagedHsm: boolean;
  /**
   * May create managed keys in AMARACUS's own Azure Key Vault / Managed HSM (provider
   * AZURE_KEY_VAULT or AZURE_MANAGED_HSM), when those are configured. Keys on the default
   * LOCAL_DEV provider are not HSM-backed on any plan.
   */
  platformVaultKeys: boolean;
  advancedCryptography: boolean; // PQC, FHE, ZK
  auditLogs: boolean;
  webhooks: boolean;
  developerApi: boolean;
}

export interface PlanLimits {
  maxProjects: number;
  maxKeys: number;
  maxMembers: number;
  includedMonthlyOperations: number; // 0 for pure PAYG
}

export interface PlanDefinition {
  id: PlanId;
  name: string;
  description: string;
  monthlyBasePriceCents: number;
  costPer1kOpsCents: number;
  limits: PlanLimits;
  features: PlanFeatureEntitlements;
  polarProductId?: string;
  polarPriceId?: string;
  polarMeterId?: string;
  /**
   * Overage authorized by default when this plan is bought, in cents per month: operations past
   * the allowance continue at costPer1kOpsCents until this much extra has been used. The customer
   * can lower it to 0 (fail closed) or raise it in the console. 0 = fail closed by default.
   */
  defaultOverageCapCents: number;
  /** v1 or v2 price list (lib/billing-catalog.ts). Absent on plans with a single price list. */
  pricingVersion?: 'v1' | 'v2';
  badge?: string;
  isPopular?: boolean;
}

export function isPaidAndActive(sub: { plan?: string; status?: string } | null | undefined): boolean {
  if (!sub || !sub.plan || sub.plan === 'FREE') return false;
  const status = (sub.status || '').toUpperCase();
  return status === 'ACTIVE' || status === 'TRIALING';
}

export const BILLING_PLANS: Record<CloudPlanId, PlanDefinition> = {
  FREE: {
    id: 'FREE',
    // AMARACUS has no free tier (since November 2026). FREE is the state of an organization with
    // no active paid plan: the account, keys and data are kept, but no API operations run and no
    // keys can be created until a plan is bought (billing-guard returns 402 PAYMENT_REQUIRED).
    name: 'No active plan',
    description: 'Account only. Choose a paid plan to use the API.',
    monthlyBasePriceCents: 0,
    costPer1kOpsCents: 0,
    defaultOverageCapCents: 0,
    limits: {
      maxProjects: 1,
      maxKeys: 5,
      maxMembers: 1,
      includedMonthlyOperations: 0,
    },
    features: {
      byok: false,
      customerManagedHsm: false,
      platformVaultKeys: false,
      advancedCryptography: false,
      auditLogs: true,
      webhooks: true,
      developerApi: true,
    },
  },
  STARTER: {
    id: 'STARTER',
    name: 'Starter',
    description: 'For individual developers and students shipping their first production workloads',
    monthlyBasePriceCents: 900, // $9.00 / mo, or $90 / yr
    costPer1kOpsCents: 12, // overage: $0.12 / 1,000 ops past the allowance
    defaultOverageCapCents: 900, // at most one more month's price in overage by default
    pricingVersion: 'v2',
    limits: {
      maxProjects: 2,
      maxKeys: 20,
      maxMembers: 1,
      includedMonthlyOperations: 50000,
    },
    features: {
      byok: false,
      customerManagedHsm: false,
      platformVaultKeys: false,
      // PQC / FHE / ZK cost far more compute per operation than a $2 plan covers.
      advancedCryptography: false,
      auditLogs: true,
      webhooks: true,
      developerApi: true,
    },
    // The monthly v2 product. lib/billing-catalog.ts has the yearly and the v1 products.
    polarProductId: polarIdFromEnv('POLAR_PRODUCT_ID_STARTER_MONTHLY'),
  },
  PRO: {
    id: 'PRO',
    name: 'Pro',
    description: 'For growing teams requiring robust cryptographic throughput and security',
    monthlyBasePriceCents: 4900, // $49.00 / mo, or $490 / yr
    costPer1kOpsCents: 12, // overage: $0.12 / 1,000 ops past the allowance
    defaultOverageCapCents: 4900,
    pricingVersion: 'v2',
    limits: {
      maxProjects: 10,
      maxKeys: 100,
      maxMembers: 5,
      includedMonthlyOperations: 500000,
    },
    features: {
      byok: false,
      customerManagedHsm: false,
      platformVaultKeys: false,
      advancedCryptography: true,
      auditLogs: true,
      webhooks: true,
      developerApi: true,
    },
    polarProductId: polarIdFromEnv('POLAR_PRODUCT_ID_PRO_MONTHLY'),
    badge: 'Popular',
    isPopular: true,
  },
  BUSINESS: {
    id: 'BUSINESS',
    name: 'Business',
    description: 'For high-scale enterprises requiring BYOK and dedicated HSM governance',
    monthlyBasePriceCents: 29900, // $299.00 / mo, or $2,990 / yr
    costPer1kOpsCents: 12, // overage: $0.12 / 1,000 ops past the allowance
    defaultOverageCapCents: 29900,
    pricingVersion: 'v2',
    limits: {
      maxProjects: 50,
      maxKeys: 500,
      maxMembers: 25,
      includedMonthlyOperations: 3000000,
    },
    features: {
      byok: true, // Full BYOK + Customer Managed HSM
      customerManagedHsm: true,
      platformVaultKeys: true,
      advancedCryptography: true,
      auditLogs: true,
      webhooks: true,
      developerApi: true,
    },
    polarProductId: polarIdFromEnv('POLAR_PRODUCT_ID_BUSINESS_MONTHLY'),
  },
  PAYG: {
    id: 'PAYG',
    name: 'Pay As You Go',
    description: 'Continuous metering with zero base fee and predictable per-operation unit pricing',
    monthlyBasePriceCents: 0, // $0 base fee
    costPer1kOpsCents: 15, // $0.15 / 1,000 ops ($150 per 1M)
    defaultOverageCapCents: 0, // PAYG has its own spending limit (paygSpendingLimitCents)
    limits: {
      maxProjects: 1000, // Platform safety limits
      maxKeys: 10000,
      maxMembers: 100,
      includedMonthlyOperations: 0, // Continuous metering
    },
    features: {
      byok: true,
      customerManagedHsm: true,
      platformVaultKeys: true,
      advancedCryptography: true,
      auditLogs: true,
      webhooks: true,
      developerApi: true,
    },
    polarProductId: process.env.POLAR_PRODUCT_ID_PAYG || cloudPolarDefault('POLAR_PRODUCT_ID_PAYG'),
    polarPriceId: process.env.POLAR_PRICE_ID_PAYG || cloudPolarDefault('POLAR_PRICE_ID_PAYG'),
    polarMeterId: process.env.POLAR_METER_ID_CRYPTO_OPERATIONS || cloudPolarDefault('POLAR_METER_ID_CRYPTO_OPERATIONS'),
  },
};

/**
 * The plan of every organization on a self-hosted installation: all features, no monthly
 * allowance and no Cloud subscription. What limits a self-hosted installation is the lifetime
 * free allowance and licence keys (lib/selfhost-license.ts), not this definition.
 */
export const SELF_HOSTED_PLAN: PlanDefinition = {
  id: 'SELF_HOSTED',
  name: 'Self-hosted',
  description: 'Self-hosted AMARACUS under PolyForm Shield 1.0.0 and the AMARACUS Additional Commercial Terms',
  monthlyBasePriceCents: 0,
  costPer1kOpsCents: 15, // the Pay As You Go rate, past the lifetime free allowance
  defaultOverageCapCents: 0,
  limits: {
    maxProjects: 1000000,
    maxKeys: 1000000,
    maxMembers: 1000000,
    includedMonthlyOperations: 0,
  },
  features: {
    byok: true,
    customerManagedHsm: true,
    platformVaultKeys: true,
    advancedCryptography: true,
    auditLogs: true,
    webhooks: true,
    developerApi: true,
  },
};

/**
 * Retrieve plan definition by identifier, falling back safely to FREE.
 */
export function getPlanDefinition(planId?: string | null): PlanDefinition {
  if (!planId) return BILLING_PLANS.FREE;
  const upper = planId.toUpperCase();
  if (upper === 'SELF_HOSTED') return SELF_HOSTED_PLAN;
  return BILLING_PLANS[upper as CloudPlanId] || BILLING_PLANS.FREE;
}

/**
 * The v1 price list (sold until 2026-11-28). Subscribers who bought it keep these prices,
 * allowances and its fail-closed default; everything else is as in BILLING_PLANS.
 */
export const LEGACY_V1_TERMS: Record<'STARTER' | 'PRO' | 'BUSINESS', { monthlyBasePriceCents: number; costPer1kOpsCents: number; includedMonthlyOperations: number }> = {
  STARTER: { monthlyBasePriceCents: 200, costPer1kOpsCents: 14, includedMonthlyOperations: 15000 },
  PRO: { monthlyBasePriceCents: 2000, costPer1kOpsCents: 14, includedMonthlyOperations: 150000 },
  BUSINESS: { monthlyBasePriceCents: 9900, costPer1kOpsCents: 10, includedMonthlyOperations: 1000000 },
};

/** The plan as a subscriber on the given price list has it. */
export function applyPricingVersion(plan: PlanDefinition, version: 'v1' | 'v2'): PlanDefinition {
  const legacy = LEGACY_V1_TERMS[plan.id as keyof typeof LEGACY_V1_TERMS];
  if (version !== 'v1' || !legacy) return plan;
  return {
    ...plan,
    monthlyBasePriceCents: legacy.monthlyBasePriceCents,
    costPer1kOpsCents: legacy.costPer1kOpsCents,
    defaultOverageCapCents: 0,
    pricingVersion: 'v1',
    limits: { ...plan.limits, includedMonthlyOperations: legacy.includedMonthlyOperations },
  };
}

/**
 * Retrieve plan definition matching a Polar product or price identifier, from either price list
 * and either billing interval.
 */
export function getPolarPlanByProductId(productIdOrPriceId?: string | null): PlanDefinition | null {
  if (!productIdOrPriceId) return null;
  const entry = resolvePolarProduct(productIdOrPriceId);
  if (entry) return BILLING_PLANS[entry.planId as CloudPlanId] || null;
  const match = Object.values(BILLING_PLANS).find(
    (p) => p.polarProductId === productIdOrPriceId || p.polarPriceId === productIdOrPriceId
  );
  return match || null;
}

/**
 * Check if a plan is paid.
 */
export function isPaidPlan(planId: string): boolean {
  return planId === 'STARTER' || planId === 'PRO' || planId === 'BUSINESS' || planId === 'PAYG';
}

/**
 * Commercial Overage Policies:
 * - HARD_STOP (Default): Once included monthly allowance is exhausted, operations fail closed (HTTP 402).
 * - AUTHORIZED_OVERAGE: Customer has explicitly authorized paid overage up to an authorized spending cap.
 * - ENTERPRISE_CUSTOM: Custom enterprise contract with negotiated volume terms.
 */
export type OveragePolicy = 'HARD_STOP' | 'AUTHORIZED_OVERAGE' | 'ENTERPRISE_CUSTOM';

export interface CommercialSpendingBoundary {
  planId: PlanId;
  includedOperations: number;
  authorizedOverageSpendingLimitCents: number;
  authorizedOverageOperations: number;
  maximumAuthorizedOperations: number;
  overagePolicy: OveragePolicy;
  maxFinancialLiabilityCents: number;
}

/**
 * Authoritatively calculate the commercial spending boundary for an organization.
 * Strictly enforces that included usage does NOT automatically become unlimited liability.
 */
export function calculateCommercialSpendingBoundary(
  plan: PlanDefinition,
  safetyState?: {
    overagePolicy?: string;
    authorizedOverageSpendingLimitCents?: number;
    paygSpendingLimitCents?: number;
  } | null
): CommercialSpendingBoundary {
  const overagePolicy = ((safetyState?.overagePolicy as OveragePolicy) || 'HARD_STOP');

  // PAYG: No included allowance; continuous metering strictly capped by paygSpendingLimitCents
  if (plan.id === 'PAYG') {
    const spendingLimitCents = safetyState?.paygSpendingLimitCents || 25000; // $250 default
    const costPer1k = plan.costPer1kOpsCents || 15;
    const maxOps = Math.floor((spendingLimitCents / costPer1k) * 1000);
    return {
      planId: 'PAYG',
      includedOperations: 0,
      authorizedOverageSpendingLimitCents: spendingLimitCents,
      authorizedOverageOperations: maxOps,
      maximumAuthorizedOperations: maxOps,
      overagePolicy: 'AUTHORIZED_OVERAGE',
      maxFinancialLiabilityCents: spendingLimitCents,
    };
  }

  // Fixed plans (FREE, PRO, BUSINESS)
  const includedOperations = plan.limits.includedMonthlyOperations;
  let authorizedOverageOperations = 0;
  let authorizedOverageSpendingLimitCents = 0;

  if (overagePolicy === 'AUTHORIZED_OVERAGE') {
    authorizedOverageSpendingLimitCents = safetyState?.authorizedOverageSpendingLimitCents || 0;
    if (authorizedOverageSpendingLimitCents > 0) {
      const costPer1k = plan.costPer1kOpsCents || 15;
      authorizedOverageOperations = Math.floor((authorizedOverageSpendingLimitCents / costPer1k) * 1000);
    }
  }

  return {
    planId: plan.id,
    includedOperations,
    authorizedOverageSpendingLimitCents,
    authorizedOverageOperations,
    maximumAuthorizedOperations: includedOperations + authorizedOverageOperations,
    overagePolicy,
    maxFinancialLiabilityCents: plan.monthlyBasePriceCents + authorizedOverageSpendingLimitCents,
  };
}

