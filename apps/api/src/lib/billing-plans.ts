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
    monthlyBasePriceCents: 200, // $2.00 / mo
    costPer1kOpsCents: 14, // ~$0.133 / 1k ops included, the same rate as Pro
    limits: {
      maxProjects: 2,
      maxKeys: 20,
      maxMembers: 1,
      // A tenth of Pro. Below ~13,334 ops, PAYG at $0.15 / 1k would cost less than $2.
      includedMonthlyOperations: 15000,
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
    // No fallback IDs: until the Starter product exists in Polar, checkout returns 503.
    polarProductId: process.env.POLAR_PRODUCT_ID_STARTER || undefined,
    polarPriceId: process.env.POLAR_PRICE_ID_STARTER || undefined,
  },
  PRO: {
    id: 'PRO',
    name: 'Pro',
    description: 'For growing teams requiring robust cryptographic throughput and security',
    monthlyBasePriceCents: 2000, // $20.00 / mo
    costPer1kOpsCents: 14, // ~$0.133 / 1k ops included
    limits: {
      maxProjects: 10,
      maxKeys: 100,
      maxMembers: 5,
      includedMonthlyOperations: 150000,
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
    polarProductId: process.env.POLAR_PRODUCT_ID_PRO || cloudPolarDefault('POLAR_PRODUCT_ID_PRO'),
    polarPriceId: process.env.POLAR_PRICE_ID_PRO || cloudPolarDefault('POLAR_PRICE_ID_PRO'),
    badge: 'Popular',
    isPopular: true,
  },
  BUSINESS: {
    id: 'BUSINESS',
    name: 'Business',
    description: 'For high-scale enterprises requiring BYOK and dedicated HSM governance',
    monthlyBasePriceCents: 9900, // $99.00 / mo
    costPer1kOpsCents: 10, // ~$0.099 / 1k ops included
    limits: {
      maxProjects: 50,
      maxKeys: 500,
      maxMembers: 25,
      includedMonthlyOperations: 1000000,
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
    polarProductId: process.env.POLAR_PRODUCT_ID_BUSINESS || cloudPolarDefault('POLAR_PRODUCT_ID_BUSINESS'),
    polarPriceId: process.env.POLAR_PRICE_ID_BUSINESS || cloudPolarDefault('POLAR_PRICE_ID_BUSINESS'),
  },
  PAYG: {
    id: 'PAYG',
    name: 'Pay As You Go',
    description: 'Continuous metering with zero base fee and predictable per-operation unit pricing',
    monthlyBasePriceCents: 0, // $0 base fee
    costPer1kOpsCents: 15, // $0.15 / 1,000 ops ($150 per 1M)
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
  costPer1kOpsCents: 15, // the Pay As You Go rate, from lifetime operation 1,001
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
 * Retrieve plan definition matching a Polar product or price identifier.
 */
export function getPolarPlanByProductId(productIdOrPriceId?: string | null): PlanDefinition | null {
  if (!productIdOrPriceId) return null;
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

