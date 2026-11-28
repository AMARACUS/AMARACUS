/**
 * Which payment-processor product or plan sells which AMARACUS plan, at which price list and
 * billing interval.
 *
 * Price lists:
 * - v2 (from 2026-11-28): Starter $9 / 50,000 ops, Pro $49 / 500,000 ops, Business $299 / 3M ops,
 *   monthly or yearly (two months free), with capped overage at $0.12 per 1,000 operations.
 * - v1 (before): Starter $2 / 15,000, Pro $20 / 150,000, Business $99 / 1M, monthly, fail-closed.
 *   No longer sold; subscribers who bought it keep its price and allowance.
 *
 * IDs come from the environment. On AMARACUS Cloud the Cloud-only module supplies defaults; the
 * public source tree has none, so there every ID must be configured.
 */
import type { PlanId } from './billing-plans';

export type BillingInterval = 'month' | 'year';
export type PricingVersion = 'v1' | 'v2';

/** Subscriptions created before this instant without any product record are on the v1 list. */
export const PRICING_V2_EFFECTIVE = new Date('2026-11-28T00:00:00Z');

export const SUBSCRIPTION_PLAN_IDS = ['STARTER', 'PRO', 'BUSINESS'] as const;
export type SubscriptionPlanId = (typeof SUBSCRIPTION_PLAN_IDS)[number];

export interface CatalogEntry {
  planId: PlanId;
  interval: BillingInterval;
  version: PricingVersion;
}

function cloudDefault(table: 'CLOUD_POLAR_DEFAULTS' | 'CLOUD_RAZORPAY_DEFAULTS', name: string): string | undefined {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require('../cloud/polar-product-defaults')[table]?.[name] || undefined;
  } catch {
    return undefined;
  }
}

function polarId(name: string): string | undefined {
  return process.env[name] || cloudDefault('CLOUD_POLAR_DEFAULTS', name);
}

/**
 * The Cloud defaults are live-mode Razorpay plans, so they apply only with live keys. Test-mode
 * keys see only what the environment configures.
 */
function razorpayId(name: string): string | undefined {
  if (process.env[name]) return process.env[name];
  if (!String(process.env.RAZORPAY_KEY_ID || '').startsWith('rzp_live_')) return undefined;
  return cloudDefault('CLOUD_RAZORPAY_DEFAULTS', name);
}

function suffix(interval: BillingInterval): string {
  return interval === 'year' ? 'YEARLY' : 'MONTHLY';
}

/** The Polar product a new checkout for this plan and interval uses (always the v2 list). */
export function polarProductIdFor(planId: PlanId, interval: BillingInterval = 'month'): string | undefined {
  if (planId === 'PAYG') return polarId('POLAR_PRODUCT_ID_PAYG');
  if (!(SUBSCRIPTION_PLAN_IDS as readonly string[]).includes(planId)) return undefined;
  return polarId(`POLAR_PRODUCT_ID_${planId}_${suffix(interval)}`);
}

/** The Razorpay plan a new INR subscription for this plan and interval uses (always the v2 list). */
export function razorpayPlanIdFor(planId: PlanId, interval: BillingInterval = 'month'): string | undefined {
  if (!(SUBSCRIPTION_PLAN_IDS as readonly string[]).includes(planId)) return undefined;
  return razorpayId(`RAZORPAY_PLAN_ID_${planId}_${suffix(interval)}`);
}

function polarCatalog(): Map<string, CatalogEntry> {
  const map = new Map<string, CatalogEntry>();
  const add = (id: string | undefined, entry: CatalogEntry) => {
    if (id && !map.has(id)) map.set(id, entry);
  };
  for (const planId of SUBSCRIPTION_PLAN_IDS) {
    for (const interval of ['month', 'year'] as const) {
      add(polarId(`POLAR_PRODUCT_ID_${planId}_${suffix(interval)}`), { planId, interval, version: 'v2' });
    }
    add(polarId(`POLAR_PRODUCT_ID_${planId}`), { planId, interval: 'month', version: 'v1' });
    add(polarId(`POLAR_PRICE_ID_${planId}`), { planId, interval: 'month', version: 'v1' });
  }
  add(polarId('POLAR_PRODUCT_ID_PAYG'), { planId: 'PAYG', interval: 'month', version: 'v2' });
  add(polarId('POLAR_PRICE_ID_PAYG'), { planId: 'PAYG', interval: 'month', version: 'v2' });
  return map;
}

function razorpayCatalog(): Map<string, CatalogEntry> {
  const map = new Map<string, CatalogEntry>();
  for (const planId of SUBSCRIPTION_PLAN_IDS) {
    for (const interval of ['month', 'year'] as const) {
      const id = razorpayId(`RAZORPAY_PLAN_ID_${planId}_${suffix(interval)}`);
      if (id && !map.has(id)) map.set(id, { planId, interval, version: 'v2' });
    }
    const legacy = razorpayId(`RAZORPAY_PLAN_ID_${planId}`);
    if (legacy && !map.has(legacy)) map.set(legacy, { planId, interval: 'month', version: 'v1' });
  }
  return map;
}

/** The plan behind a Polar product or price ID, from either price list. */
export function resolvePolarProduct(productOrPriceId?: string | null): CatalogEntry | null {
  if (!productOrPriceId) return null;
  return polarCatalog().get(productOrPriceId) || null;
}

/** The plan behind a Razorpay plan ID, from either price list. */
export function resolveRazorpayPlan(razorpayPlanId?: string | null): CatalogEntry | null {
  if (!razorpayPlanId) return null;
  return razorpayCatalog().get(razorpayPlanId) || null;
}

/** Every Razorpay plan ID this deployment sells or still bills. */
export function knownRazorpayPlanIds(): string[] {
  return [...razorpayCatalog().keys()];
}

export function parseBillingInterval(value: unknown): BillingInterval | null {
  if (value === undefined || value === null || value === '') return 'month';
  const v = String(value).toLowerCase();
  if (v === 'month' || v === 'monthly') return 'month';
  if (v === 'year' || v === 'yearly' || v === 'annual') return 'year';
  return null;
}

/**
 * The price list of a billing subscription record. An explicit `pricingVersion` in its metadata
 * wins; otherwise the product or plan it was bought with decides; records with neither that
 * predate the v2 list are v1.
 */
export function pricingVersionOf(
  subscription: { metadata?: unknown; createdAt?: Date | string | null } | null | undefined
): PricingVersion {
  if (!subscription) return 'v2';
  const meta = (subscription.metadata || {}) as Record<string, any>;
  if (meta.pricingVersion === 'v1' || meta.pricingVersion === 'v2') return meta.pricingVersion;

  const polarProduct = resolvePolarProduct(meta.product_id || meta.product?.id || meta.price?.product_id);
  if (polarProduct) return polarProduct.version;

  const razorpayPlan = resolveRazorpayPlan(meta.razorpayPlanId);
  if (razorpayPlan) return razorpayPlan.version;
  // Razorpay records written before the v2 list did not store their plan ID.
  if (meta.razorpaySubscriptionId) return 'v1';

  const created = subscription.createdAt ? new Date(subscription.createdAt) : null;
  return created && created.getTime() < PRICING_V2_EFFECTIVE.getTime() ? 'v1' : 'v2';
}

/** The billing interval of a subscription record, from its metadata or the length of its period. */
export function billingIntervalOf(
  subscription: { metadata?: unknown; currentPeriodStart?: Date | string | null; currentPeriodEnd?: Date | string | null } | null | undefined
): BillingInterval {
  const meta = ((subscription && subscription.metadata) || {}) as Record<string, any>;
  if (meta.billingInterval === 'year' || meta.billingInterval === 'month') return meta.billingInterval;
  if (subscription?.currentPeriodStart && subscription.currentPeriodEnd) {
    const days = (new Date(subscription.currentPeriodEnd).getTime() - new Date(subscription.currentPeriodStart).getTime()) / 86_400_000;
    if (days > 40) return 'year';
  }
  return 'month';
}

/**
 * The most overage, in cents per month, a subscription can authorize: what its processor will
 * actually bill. The v2 Polar products cap metered overage at one month's plan price, and the
 * Razorpay overage add-on uses the same cap. v1 products have no overage price at all, and a
 * yearly Razorpay subscription is invoiced once a year, so neither can carry overage.
 */
export function maxOverageCapCents(
  plan: { id: string; defaultOverageCapCents: number },
  terms: { version: PricingVersion; interval: BillingInterval; processor?: string | null }
): number {
  if (plan.id === 'PAYG' || plan.id === 'FREE' || plan.id === 'SELF_HOSTED') return 0;
  if (terms.version === 'v1') return 0;
  if (terms.processor === 'razorpay' && terms.interval === 'year') return 0;
  return Math.max(0, plan.defaultOverageCapCents || 0);
}

/** The processor that bills a subscription record. */
export function paymentProcessorOf(subscription: { polarSubscriptionId?: string | null; metadata?: unknown } | null | undefined): string | null {
  if (!subscription) return null;
  if (subscription.polarSubscriptionId) return 'polar';
  const meta = (subscription.metadata || {}) as Record<string, any>;
  if (meta.paymentProcessor === 'razorpay' || meta.razorpaySubscriptionId) return 'razorpay';
  return meta.paymentProcessor || null;
}
