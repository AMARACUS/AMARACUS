import { db } from './data-store';
import {
  BILLING_PLANS,
  getPlanDefinition,
  PlanDefinition,
  PlanFeatureEntitlements,
  PlanId,
  calculateCommercialSpendingBoundary,
  OveragePolicy,
} from './billing-plans';
import { isTestEnv } from './runtime-config';
import { isSelfHosted } from './edition';
import { SELF_HOSTED_PLAN, applyPricingVersion } from './billing-plans';
import { pricingVersionOf } from './billing-catalog';
import { getSelfHostUsage, isActivated, selfHostGateEnforced } from './selfhost-license';

export interface ResourceLimitCheckResult {
  allowed: boolean;
  resourceType: 'projects' | 'keys' | 'members';
  currentCount: number;
  maxLimit: number;
  planId: PlanId;
  reason?: string;
}

export interface OperationAllowanceCheckResult {
  allowed: boolean;
  planId: PlanId;
  currentUsage: number;
  includedAllowance: number;
  authorizedOverageAllowance: number;
  maximumAuthorizedOperations: number;
  remainingAllowance: number;
  isPayg: boolean;
  overagePolicy: string;
  reason?: string;
}

export class EntitlementEngine {
  /**
   * Determine the authoritative plan for an organization.
   * If subscription is missing, inactive, canceled or past due, falls back to FREE.
   */
  async getOrganizationPlan(organizationId: string): Promise<PlanDefinition> {
    // A self-hosted installation has no Cloud subscriptions: every organization is on the
    // one self-hosted plan.
    if (isSelfHosted()) return SELF_HOSTED_PLAN;

    const subscription = await db.getBillingSubscription(organizationId);

    if (!subscription) {
      // Only the billing subscription grants paid plans. Test fixtures may set a plan through
      // org metadata or AMARACUS_TEST_DEFAULT_PLAN; both are ignored outside the test runner.
      if (isTestEnv()) {
        const fixturePlan = await this.getTestFixturePlan(organizationId);
        if (fixturePlan) return fixturePlan;
      }
      return BILLING_PLANS.FREE;
    }

    const status = subscription.status.toUpperCase();
    const validStatuses = ['ACTIVE', 'TRIALING'];
    if (!validStatuses.includes(status)) {
      // Inactive, past due, unpaid, or canceled subscriptions default to FREE tier
      return BILLING_PLANS.FREE;
    }

    // Distinguish cancellation requested from subscription actually ended:
    // If the customer requested cancellation at the end of the billing period,
    // they retain paid entitlements until the period end date has passed.
    if (subscription.cancelAtPeriodEnd && subscription.currentPeriodEnd) {
      if (new Date() > new Date(subscription.currentPeriodEnd)) {
        // Billing period has completed; paid access is revoked
        return BILLING_PLANS.FREE;
      }
    }

    // Subscribers on the v1 price list keep its price and allowance.
    return applyPricingVersion(getPlanDefinition(subscription.plan), pricingVersionOf(subscription));
  }

  private async getTestFixturePlan(organizationId: string): Promise<PlanDefinition | null> {
    const toPlan = (value: unknown): PlanDefinition | null => {
      const key = String(value || '').toUpperCase();
      if (key === 'BUSINESS') return BILLING_PLANS.BUSINESS;
      if (key === 'STARTER') return BILLING_PLANS.STARTER;
      if (key === 'PRO' || key === 'DEVELOPER') return BILLING_PLANS.PRO;
      if (key === 'PAYG' || key === 'PAY_AS_YOU_GO') return BILLING_PLANS.PAYG;
      if (key === 'FREE') return BILLING_PLANS.FREE;
      return null;
    };
    const org = await db.findOrgById(organizationId);
    if (org?.metadata) {
      try {
        const meta = typeof org.metadata === 'string' ? JSON.parse(org.metadata) : org.metadata;
        const fromMeta = toPlan(meta.plan);
        if (fromMeta) return fromMeta;
      } catch {}
    }
    return toPlan(process.env.AMARACUS_TEST_DEFAULT_PLAN);
  }

  /**
   * Retrieve active feature entitlements for an organization.
   */
  async getOrganizationEntitlements(organizationId: string): Promise<PlanFeatureEntitlements> {
    const plan = await this.getOrganizationPlan(organizationId);
    return plan.features;
  }

  /**
   * Check if an organization is entitled to a specific feature.
   */
  async hasEntitlement(organizationId: string, feature: keyof PlanFeatureEntitlements): Promise<boolean> {
    const entitlements = await this.getOrganizationEntitlements(organizationId);
    return !!entitlements[feature];
  }

  /**
   * Check whether creating an additional resource is permitted under current plan limits.
   * Safe downgrade guarantee: Existing resources are NEVER deleted upon downgrade,
   * but new resource creation is blocked if current count >= new limit.
   */
  async checkResourceLimit(
    organizationId: string,
    resourceType: 'projects' | 'keys' | 'members',
    currentCountOverride?: number
  ): Promise<ResourceLimitCheckResult> {
    const plan = await this.getOrganizationPlan(organizationId);
    let currentCount = 0;

    if (currentCountOverride !== undefined) {
      currentCount = currentCountOverride;
    } else {
      if (resourceType === 'projects') {
        const projects = await db.getProjectsByOrg(organizationId);
        currentCount = projects.length;
      } else if (resourceType === 'keys') {
        const keys = await db.listKeys({ organizationId });
        currentCount = keys.length;
      } else if (resourceType === 'members') {
        const members = await db.getOrgMembers(organizationId);
        currentCount = members.length;
      }
    }

    let maxLimit = 1;
    if (resourceType === 'projects') {
      maxLimit = plan.limits.maxProjects;
    } else if (resourceType === 'keys') {
      maxLimit = plan.limits.maxKeys;
    } else if (resourceType === 'members') {
      maxLimit = plan.limits.maxMembers;
    }

    if (currentCount >= maxLimit) {
      const label = resourceType === 'projects' ? 'Project' : resourceType === 'keys' ? 'Key' : 'Member';
      return {
        allowed: false,
        resourceType,
        currentCount,
        maxLimit,
        planId: plan.id,
        reason: `${label} limit reached (${currentCount}/${maxLimit}) for the ${plan.name} plan. Upgrade your plan to create more ${resourceType}.`,
      };
    }

    return {
      allowed: true,
      resourceType,
      currentCount,
      maxLimit,
      planId: plan.id,
    };
  }

  /**
   * Check operation allowance before executing cryptographic operations.
   * Strictly enforces:
   * 1. Included plan allowance (FREE, PRO, BUSINESS)
   * 2. Commercial overage policy (HARD_STOP by default; prevents runaway charges)
   * 3. Explicit authorized overage boundary (maximum authorized operations cap)
   * 4. PAYG monthly spending cap (bounded continuous metering)
   *
   * A $99 Business subscription with 1,000,000 included ops NEVER exposes AMARACUS
   * to unlimited financial liability (e.g. 10M+ operations).
   */
  async checkOperationAllowance(organizationId: string, requestedQuantity: number = 1): Promise<OperationAllowanceCheckResult> {
    if (isSelfHosted()) return this.checkSelfHostedAllowance(requestedQuantity);

    const plan = await this.getOrganizationPlan(organizationId);
    const usage = await db.getCurrentBillingUsage(organizationId);
    const safetyState = await db.getBillingSafetyState(organizationId);
    const boundary = calculateCommercialSpendingBoundary(plan, safetyState);

    // 0.25. If billing safety circuit breaker is SUSPENDED, fail closed across all plans
    if (safetyState.circuitBreakerStatus === 'SUSPENDED') {
      return {
        allowed: false,
        planId: plan.id,
        currentUsage: usage.operationCount,
        includedAllowance: boundary.includedOperations,
        authorizedOverageAllowance: boundary.authorizedOverageOperations,
        maximumAuthorizedOperations: boundary.maximumAuthorizedOperations,
        remainingAllowance: 0,
        isPayg: plan.id === 'PAYG',
        overagePolicy: boundary.overagePolicy,
        reason: safetyState.suspensionReason || 'Emergency circuit breaker tripped: Operations suspended by billing safety engine.',
      };
    }

    // Plans change only through Polar (checkout or webhook). An exhausted allowance fails
    // closed below; nothing here upgrades the plan without a payment.

    // 1. Pay-As-You-Go Plan
    if (plan.id === 'PAYG') {
      const costPer1k = plan.costPer1kOpsCents || 15;
      const spendingLimit = safetyState.paygSpendingLimitCents; // Default $250.00
      const currentCost = usage.estimatedCostCents;
      const projectedCost = currentCost + Math.round((requestedQuantity / 1000) * costPer1k);

      if (safetyState.autoHaltEnabled && (currentCost >= spendingLimit || projectedCost >= spendingLimit)) {
        return {
          allowed: false,
          planId: 'PAYG',
          currentUsage: usage.operationCount,
          includedAllowance: 0,
          authorizedOverageAllowance: boundary.maximumAuthorizedOperations,
          maximumAuthorizedOperations: boundary.maximumAuthorizedOperations,
          remainingAllowance: 0,
          isPayg: true,
          overagePolicy: 'AUTHORIZED_OVERAGE',
          reason: `Pay As You Go monthly spending limit reached ($${(spendingLimit / 100).toFixed(2)}). Operations halted for financial protection. Increase your spending limit in the console to authorize additional operations.`,
        };
      }

      return {
        allowed: true,
        planId: 'PAYG',
        currentUsage: usage.operationCount,
        includedAllowance: 0,
        authorizedOverageAllowance: boundary.maximumAuthorizedOperations,
        maximumAuthorizedOperations: boundary.maximumAuthorizedOperations,
        remainingAllowance: Math.max(0, boundary.maximumAuthorizedOperations - usage.operationCount),
        isPayg: true,
        overagePolicy: 'AUTHORIZED_OVERAGE',
      };
    }

    // 2. Fixed Subscription Plans (FREE, PRO, BUSINESS)
    const maximumAuthorized = boundary.maximumAuthorizedOperations;
    const remaining = Math.max(0, maximumAuthorized - usage.operationCount);

    if (usage.operationCount + requestedQuantity > maximumAuthorized) {
      const isOverageAttempt = usage.operationCount >= boundary.includedOperations;
      let reason: string;

      if (isOverageAttempt && boundary.overagePolicy === 'AUTHORIZED_OVERAGE') {
        reason = `Authorized overage spending limit reached (${usage.operationCount.toLocaleString()} / ${maximumAuthorized.toLocaleString()} operations used). To prevent uncontrolled financial exposure, operations are suspended. Adjust your authorized overage limit or contact enterprise support.`;
      } else {
        reason = `Monthly cryptographic operation allowance exhausted (${usage.operationCount.toLocaleString()} / ${boundary.includedOperations.toLocaleString()} operations used). In accordance with fail-safe billing policy, operations are blocked to prevent unexpected charges. Upgrade your subscription or explicitly authorize paid overage to continue.`;
      }

      return {
        allowed: false,
        planId: plan.id,
        currentUsage: usage.operationCount,
        includedAllowance: boundary.includedOperations,
        authorizedOverageAllowance: boundary.authorizedOverageOperations,
        maximumAuthorizedOperations: maximumAuthorized,
        remainingAllowance: remaining,
        isPayg: false,
        overagePolicy: boundary.overagePolicy,
        reason,
      };
    }

    return {
      allowed: true,
      planId: plan.id,
      currentUsage: usage.operationCount,
      includedAllowance: boundary.includedOperations,
      authorizedOverageAllowance: boundary.authorizedOverageOperations,
      maximumAuthorizedOperations: maximumAuthorized,
      remainingAllowance: remaining,
      isPayg: false,
      overagePolicy: boundary.overagePolicy,
    };
  }

  /**
   * Self-hosted: allowed while the installation's lifetime total stays within the free
   * allowance plus the operations bought with licence keys. Callers that serve decrypt,
   * unwrap or verify do not use this result to block (see billing-guard).
   */
  async checkSelfHostedAllowance(requestedQuantity: number = 1): Promise<OperationAllowanceCheckResult> {
    const base = {
      planId: 'SELF_HOSTED' as PlanId,
      isPayg: false,
      overagePolicy: 'HARD_STOP',
      authorizedOverageAllowance: 0,
    };
    if (!selfHostGateEnforced()) {
      return {
        ...base,
        allowed: true,
        currentUsage: 0,
        includedAllowance: Number.MAX_SAFE_INTEGER,
        maximumAuthorizedOperations: Number.MAX_SAFE_INTEGER,
        remainingAllowance: Number.MAX_SAFE_INTEGER,
      };
    }
    const usage = await getSelfHostUsage();
    const result = {
      ...base,
      currentUsage: usage.lifetimeOperations,
      includedAllowance: usage.freeAllowance,
      authorizedOverageAllowance: usage.licensedOperations,
      maximumAuthorizedOperations: usage.totalAllowance,
      remainingAllowance: usage.remaining,
    };
    if (!(await isActivated())) {
      return {
        ...result,
        allowed: false,
        reason:
          'The licences for this self-hosted installation have not been accepted yet. Sign in to the console and accept them to activate it.',
      };
    }
    if (usage.lifetimeOperations + requestedQuantity > usage.totalAllowance) {
      const n = (v: number) => v.toLocaleString('en-US');
      return {
        ...result,
        allowed: false,
        reason: `This installation has used ${n(usage.lifetimeOperations)} of its ${n(usage.totalAllowance)} licensed lifetime operations (${n(usage.freeAllowance)} free). Add a licence key in the console (Billing) to continue. Decrypt, unwrap and verify keep working.`,
      };
    }
    return { ...result, allowed: true };
  }
}

export const entitlementEngine = new EntitlementEngine();
