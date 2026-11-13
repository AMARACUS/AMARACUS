"use client";

/** AMARACUS Cloud plan upgrades do not exist in a self-hosted installation. */
export type ProjectLimitUpgradeInfo = never;

export async function resolveProjectLimitUpgrade(
  _err: { details?: Record<string, unknown> },
  _organizationId: string,
  _projectCount: number
): Promise<ProjectLimitUpgradeInfo | null> {
  return null;
}

export function ProjectLimitUpgradeModal(_props: {
  limitUpgrade: ProjectLimitUpgradeInfo | null;
  isOpen: boolean;
  onClose: () => void;
  onPlanActivated: (planName: string) => void;
}) {
  return null;
}
