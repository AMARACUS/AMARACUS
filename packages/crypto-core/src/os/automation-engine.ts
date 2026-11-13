/**
 * @file packages/crypto-core/src/os/automation-engine.ts
 * Controlled Cryptographic Automation Rules Engine (Phase 20)
 */

import { AutomationRule, PostureFinding, UnifiedResource } from './types';

export class CryptographicAutomationEngine {
  /**
   * Default enterprise automation rules.
   */
  public static getDefaultRules(orgId: string): AutomationRule[] {
    return [
      {
        id: `rule_rot_${orgId}`,
        orgId,
        name: 'Proactive Key Rotation Alerting',
        description: 'Automatically flags keys exceeding 90 days of age and queues rotation workflow.',
        trigger: 'KEY_ROTATION_DUE',
        conditions: { maxAgeDays: 90 },
        action: 'INSTANTIATE_WORKFLOW',
        workflowTemplateId: 'tpl_key_rotation',
        enabled: true,
        requiresApproval: true,
      },
      {
        id: `rule_cert_${orgId}`,
        orgId,
        name: 'Certificate Expiration Watchdog',
        description: 'Detects certificates expiring within 30 days and schedules automated renewal workflow.',
        trigger: 'CERT_EXPIRING',
        conditions: { thresholdDays: 30 },
        action: 'INSTANTIATE_WORKFLOW',
        workflowTemplateId: 'tpl_cert_renewal',
        enabled: true,
        requiresApproval: false,
      },
      {
        id: `rule_drift_${orgId}`,
        orgId,
        name: 'Continuous Posture Audit',
        description: 'Periodically assesses cryptographic inventory, deduplicates findings, and publishes health score.',
        trigger: 'SCHEDULED_AUDIT',
        conditions: { intervalHours: 24 },
        action: 'GENERATE_POSTURE_REPORT',
        enabled: true,
        requiresApproval: false,
      },
    ];
  }

  /**
   * Evaluates automation rules against current findings and resources.
   */
  public static evaluateRules(
    rules: AutomationRule[],
    resources: UnifiedResource[],
    findings: PostureFinding[]
  ): Array<{ rule: AutomationRule; triggered: boolean; affectedCount: number; reason?: string }> {
    const results: Array<{ rule: AutomationRule; triggered: boolean; affectedCount: number; reason?: string }> = [];

    for (const rule of rules) {
      if (!rule.enabled) {
        results.push({ rule, triggered: false, affectedCount: 0, reason: 'Rule is disabled' });
        continue;
      }

      if (rule.trigger === 'KEY_ROTATION_DUE') {
        const rotationFindings = findings.filter((f) => f.category === 'KEY_ROTATION');
        results.push({
          rule,
          triggered: rotationFindings.length > 0,
          affectedCount: rotationFindings.length,
          reason: rotationFindings.length > 0
            ? `${rotationFindings.length} key(s) require rotation.`
            : 'All keys comply with rotation schedule.',
        });
      } else if (rule.trigger === 'CERT_EXPIRING') {
        const certFindings = findings.filter((f) => f.category === 'CERT_EXPIRATION');
        results.push({
          rule,
          triggered: certFindings.length > 0,
          affectedCount: certFindings.length,
          reason: certFindings.length > 0
            ? `${certFindings.length} certificate(s) expiring soon.`
            : 'All certificates are well within validity windows.',
        });
      } else if (rule.trigger === 'SCHEDULED_AUDIT') {
        results.push({
          rule,
          triggered: true,
          affectedCount: resources.length,
          reason: `Continuous audit active across ${resources.length} verified/discovered resources.`,
        });
      } else {
        results.push({ rule, triggered: false, affectedCount: 0, reason: 'Trigger conditions not met' });
      }
    }

    return results;
  }
}
