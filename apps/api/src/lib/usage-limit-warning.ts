import { site } from './site-config';
/**
 * Emails an organization's billing contacts when usage nears the monthly included operations.
 * The trigger is 14/15 of the allowance: 14,000 of Starter's 15,000.
 *
 * It needs no "already sent" flag. The usage counter is incremented atomically, so exactly one
 * operation crosses the threshold in each billing period. Pay As You Go has no allowance, so it
 * never warns.
 */
import { db, BillingUsageRecord } from './data-store';
import { BILLING_PLANS, PlanId, CloudPlanId } from './billing-plans';
import { hasPermission } from './permissions';
import { sendUsageLimitWarningEmail } from './email-service';

const NEXT_PLAN: Partial<Record<PlanId, PlanId>> = { FREE: 'STARTER', STARTER: 'PRO', PRO: 'BUSINESS' };

export function usageWarningThreshold(includedAllowance: number): number {
  return Math.ceil((includedAllowance * 14) / 15);
}

export function crossedUsageWarning(previousCount: number, currentCount: number, includedAllowance: number): boolean {
  if (includedAllowance <= 0) return false;
  const threshold = usageWarningThreshold(includedAllowance);
  return previousCount < threshold && currentCount >= threshold;
}

function upgradeAdvice(planId: PlanId): string {
  const next = NEXT_PLAN[planId];
  if (!next) {
    return `If you need more than your plan includes, write to ${site('supportEmail')}.`;
  }
  const plan = BILLING_PLANS[next as CloudPlanId];
  const offer =
    `${plan.name} is $${plan.monthlyBasePriceCents / 100} a month and includes ` +
    `${plan.limits.includedMonthlyOperations.toLocaleString('en-US')} operations.`;
  return planId === 'FREE'
    ? `${offer} You can choose it on your billing page.`
    : `${offer} To change plans, open your billing page and select Customer Portal & Invoices.`;
}

/** Sends the warning to every member who can change the plan. One failed address does not stop the rest. */
export async function notifyUsageLimitApproaching(params: {
  organizationId: string;
  planId: PlanId;
  planName: string;
  includedAllowance: number;
  usage: BillingUsageRecord;
}): Promise<void> {
  const { organizationId, planId, planName, includedAllowance, usage } = params;
  const [members, safety] = await Promise.all([
    db.getOrgMembers(organizationId),
    db.getBillingSafetyState(organizationId),
  ]);
  const overageAuthorized =
    safety.overagePolicy === 'AUTHORIZED_OVERAGE' && safety.authorizedOverageSpendingLimitCents > 0;
  const recipients = members.filter((member) => member.user?.email && hasPermission(member.role, 'billing:manage'));

  const results = await Promise.allSettled(
    recipients.map((member) =>
      sendUsageLimitWarningEmail({
        toEmail: member.user.email,
        recipientName: member.user.name,
        planName,
        operationsUsed: usage.operationCount,
        includedOperations: includedAllowance,
        resetsOn: usage.periodEnd,
        overageAuthorized,
        upgradeAdvice: upgradeAdvice(planId),
      })
    )
  );
  const failed = results.filter((r) => r.status === 'rejected' || !r.value.success).length;
  if (failed > 0) {
    console.warn(`[UsageLimitWarning] ${failed} of ${results.length} emails failed for ${organizationId}`);
  }
}
