import { Request, Response, NextFunction } from 'express';
import { entitlementEngine } from '../lib/entitlement-engine';
import { billingSafetyEngine } from '../lib/billing-safety';
import { PlanFeatureEntitlements } from '../lib/billing-plans';
import { isSelfHosted } from '../lib/edition';
import { cloudDefault } from '../lib/site-config';
import { getSelfHostUsage, isActivated, isRecoveryRequest, selfHostGateEnforced } from '../lib/selfhost-license';

/**
 * The organization the caller was authenticated into. Only auth middleware sets this;
 * client-supplied headers, query strings and bodies are never trusted for billing.
 */
export function getRequestOrganizationId(req: Request): string | null {
  return (req as any).organizationId || null;
}

function sendOrganizationRequired(res: Response) {
  return res.status(403).json({
    error: {
      code: 'ORGANIZATION_CONTEXT_REQUIRED',
      message: 'This operation needs an authenticated organization context for billing checks.',
    },
  });
}

/**
 * The internal "AMARACUS Platform" organization (docs/recovery/platform-vault.md) is not a customer:
 * it holds the key that seals hackathon PII, so it needs no plan and is never metered.
 */
export function isPlatformOrganization(orgId: string | null | undefined): boolean {
  const platformOrgId = process.env.AMARACUS_PLATFORM_ORG_ID?.trim();
  return Boolean(platformOrgId && orgId && orgId === platformOrgId);
}

/** 402 for an organization without an active paid plan. AMARACUS has no free tier. */
function sendPaymentRequired(res: Response) {
  return res.status(402).json({
    error: {
      code: 'PAYMENT_REQUIRED',
      message: 'This organization has no active plan. Choose a plan in Billing (console, Billing) to use the API.',
      currentPlan: 'FREE',
      upgradeRequired: true,
      billingUrl: `${cloudDefault('appUrl')}/dashboard/billing`,
    },
  });
}

/** 403 until someone has accepted the two licences on this self-hosted installation. */
function sendLicenseAcceptanceRequired(res: Response) {
  return res.status(403).json({
    error: {
      code: 'LICENSE_ACCEPTANCE_REQUIRED',
      message:
        'This self-hosted installation is not activated. Sign in to the console and accept the PolyForm Shield 1.0.0 licence and the AMARACUS Additional Commercial Terms.',
    },
  });
}

/**
 * Self-hosted gate. Returns true when it has answered the request.
 * - Not activated: nothing runs, except decrypt, unwrap and verify.
 * - Past the lifetime allowance (10,000 free plus licence keys): new operations stop with 402.
 * - Decrypt, unwrap and verify are never stopped, so earlier data always stays readable.
 * The check is local; nothing is sent to AMARACUS.
 */
export async function selfHostGateBlocks(req: Request, res: Response, estimatedQuantity: number, metered: boolean): Promise<boolean> {
  if (!selfHostGateEnforced()) return false;
  if (metered && isRecoveryRequest(req)) return false;
  if (!(await isActivated())) {
    sendLicenseAcceptanceRequired(res);
    return true;
  }
  const usage = await getSelfHostUsage();
  const exhausted = metered
    ? usage.lifetimeOperations + estimatedQuantity > usage.totalAllowance
    : usage.lifetimeOperations >= usage.totalAllowance;
  if (!exhausted) return false;
  res.status(402).json({
    error: {
      code: 'SELF_HOST_LICENSE_REQUIRED',
      message:
        'This installation has used its licensed lifetime operations. Add a licence key in the console (Billing) to run new operations. Decrypt, unwrap and verify keep working.',
      lifetimeOperations: usage.lifetimeOperations,
      freeAllowance: usage.freeAllowance,
      licensedOperations: usage.licensedOperations,
      totalAllowance: usage.totalAllowance,
      ratePer1kOpsCents: usage.ratePer1kOpsCents,
      currency: usage.currency,
    },
  });
  return true;
}

/**
 * Middleware that lets a request through only when the organization has an active paid plan
 * (Starter, Pro, Business or Pay As You Go). Used where nothing is metered, such as creating API keys.
 */
export function requirePaidPlan() {
  return async (req: Request, res: Response, next: NextFunction) => {
    const orgId = getRequestOrganizationId(req);
    if (!orgId) {
      return sendOrganizationRequired(res);
    }
    try {
      if (isSelfHosted()) {
        if (await selfHostGateBlocks(req, res, 0, false)) return;
        return next();
      }
      if (isPlatformOrganization(orgId)) return next();
      const plan = await entitlementEngine.getOrganizationPlan(orgId);
      if (plan.id === 'FREE') return sendPaymentRequired(res);
      next();
    } catch (err: any) {
      next(err);
    }
  };
}

/**
 * Middleware requiring a specific feature entitlement.
 * Fails closed if the organization's plan lacks the capability or the org is unknown.
 */
export function requireEntitlement(feature: keyof PlanFeatureEntitlements) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const orgId = getRequestOrganizationId(req);

    if (!orgId) {
      return sendOrganizationRequired(res);
    }

    try {
      const allowed = await entitlementEngine.hasEntitlement(orgId, feature);
      if (!allowed) {
        const plan = await entitlementEngine.getOrganizationPlan(orgId);
        return res.status(403).json({
          error: {
            code: 'FEATURE_NOT_ENTITLED',
            message: `Feature '${feature}' is not included in the ${plan.name} plan. Upgrade to access this feature.`,
            feature,
            currentPlan: plan.id,
            upgradeRequired: true,
          },
        });
      }
      next();
    } catch (err: any) {
      next(err);
    }
  };
}

/**
 * Middleware guarding cryptographic operation execution.
 * Enforces:
 * 1. Billing safety circuit breaker (velocity, spending cap)
 * 2. Subscription monthly operation allowances (fails safe rather than surprise overage billing)
 * 3. Commercial spending boundaries (prevents runaway financial liabilities)
 */
export function requireOperationAllowance(estimatedQuantity: number = 1) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const orgId = getRequestOrganizationId(req);

    if (!orgId) {
      return sendOrganizationRequired(res);
    }

    try {
      if (isSelfHosted()) {
        if (await selfHostGateBlocks(req, res, estimatedQuantity, true)) return;
        return next();
      }
      if (isPlatformOrganization(orgId)) return next();
      const plan = await entitlementEngine.getOrganizationPlan(orgId);

      // 0. No free tier: an organization without an active paid plan runs no operations.
      if (plan.id === 'FREE') {
        return sendPaymentRequired(res);
      }

      // 1. Evaluate Billing Safety & Circuit Breaker
      const safetyResult = await billingSafetyEngine.evaluateSafety(orgId, estimatedQuantity, plan);
      if (!safetyResult.allowed) {
        return res.status(429).json({
          error: {
            code: safetyResult.status === 'SUSPENDED' ? 'CIRCUIT_BREAKER_SUSPENDED' : 'BILLING_SAFETY_HALT',
            message: safetyResult.reason || 'Operations suspended by billing safety circuit breaker.',
            circuitBreakerStatus: safetyResult.status,
          },
        });
      }

      // If throttled, apply backpressure delay
      if (safetyResult.delayMs && safetyResult.delayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, safetyResult.delayMs));
      }

      // 2. Check Monthly Operation Allowance & Commercial Spending Boundary
      const allowanceResult = await entitlementEngine.checkOperationAllowance(orgId, estimatedQuantity);
      if (!allowanceResult.allowed) {
        const errorCode =
          allowanceResult.planId === 'PAYG'
            ? 'SPENDING_LIMIT_REACHED'
            : allowanceResult.overagePolicy === 'AUTHORIZED_OVERAGE'
            ? 'SPENDING_AUTHORIZATION_EXHAUSTED'
            : 'OPERATION_ALLOWANCE_EXHAUSTED';

        return res.status(402).json({
          error: {
            code: errorCode,
            message: allowanceResult.reason,
            plan: allowanceResult.planId,
            currentUsage: allowanceResult.currentUsage,
            includedAllowance: allowanceResult.includedAllowance,
            authorizedOverageAllowance: allowanceResult.authorizedOverageAllowance,
            maximumAuthorizedOperations: allowanceResult.maximumAuthorizedOperations,
            overagePolicy: allowanceResult.overagePolicy,
            upgradeRequired: true,
          },
        });
      }

      next();
    } catch (err: any) {
      next(err);
    }
  };
}
