/**
 * @file packages/crypto-core/src/assurance/control-evaluator.ts
 * Deterministic Control Assessment, Gap Analysis, Exception Enforcement & Report Generation (Phase 22)
 */

import {
  ComplianceFrameworkId,
  ControlRequirement,
  EvidenceArtifact,
  ControlAssessment,
  ControlGap,
  ComplianceException,
  FrameworkAssessmentReport,
} from './types';
import { FrameworkRegistry } from './framework-registry';
import { EvidenceCollector } from './evidence-collector';

export interface EvaluationOptions {
  frameworkId?: ComplianceFrameworkId;
  exceptions?: ComplianceException[];
}

export class ControlEvaluator {
  public static readonly COMPLIANCE_DISCLAIMER =
    'IMPORTANT NOTICE: This automated assurance evaluation is generated for internal compliance monitoring, readiness assessment, and evidence tracking. It does not constitute a formal certification, attestation, audit opinion, or endorsement by the AICPA, ISO, NIST, or any accredited third-party auditing firm. Technical controls must be verified in combination with customer-managed operational controls.';

  /**
   * Assesses a single control requirement against collected evidence artifacts
   * and active compliance exceptions.
   */
  public static evaluateControl(
    requirement: ControlRequirement,
    evidence: EvidenceArtifact[],
    exceptions: ComplianceException[] = []
  ): ControlAssessment {
    // 1. Check for active, approved exception
    const now = Date.now();
    const activeException = exceptions.find(
      (e) =>
        e.controlId === requirement.id &&
        e.status === 'APPROVED' &&
        new Date(e.expiresAt).getTime() > now
    );

    // 2. Filter evidence matching required types
    const matchingEvidence = evidence.filter((e) =>
      requirement.requiredEvidenceTypes.includes(e.type)
    );
    const evidenceIds = matchingEvidence.map((e) => e.id);

    // 3. Run control evaluator
    const evalResult = requirement.evaluate(matchingEvidence);

    // 4. Map gaps with deterministic IDs
    const gaps: ControlGap[] = evalResult.gaps.map((g, idx) => ({
      ...g,
      id: `gap_${requirement.id.toLowerCase().replace(/[^a-z0-9]/g, '_')}_${idx + 1}`,
    }));

    // If an approved exception exists, override status
    if (activeException) {
      return {
        controlId: requirement.id,
        frameworkId: requirement.frameworkId,
        code: requirement.code,
        title: requirement.title,
        category: requirement.category,
        responsibility: requirement.responsibility,
        status: 'EXCEPTION_GRANTED',
        score: Math.max(evalResult.score, 85),
        details: `Exception granted (ID: ${activeException.id}). Justification: ${activeException.justification}. Compensating: ${activeException.compensatingControls}. Original evaluation: ${evalResult.details}`,
        evidenceIds,
        gaps,
        exceptionId: activeException.id,
        lastAssessedAt: new Date().toISOString(),
      };
    }

    return {
      controlId: requirement.id,
      frameworkId: requirement.frameworkId,
      code: requirement.code,
      title: requirement.title,
      category: requirement.category,
      responsibility: requirement.responsibility,
      status: evalResult.status,
      score: evalResult.score,
      details: evalResult.details,
      evidenceIds,
      gaps,
      lastAssessedAt: new Date().toISOString(),
    };
  }

  /**
   * Assesses all controls for a specific framework or all frameworks,
   * producing complete, tamper-evident FrameworkAssessmentReports.
   */
  public static evaluateFramework(
    orgId: string,
    frameworkId: ComplianceFrameworkId,
    evidence: EvidenceArtifact[],
    exceptions: ComplianceException[] = []
  ): FrameworkAssessmentReport {
    const framework = FrameworkRegistry.getFramework(frameworkId);
    if (!framework) {
      throw new Error(`Framework "${frameworkId}" is not registered.`);
    }

    const controls = FrameworkRegistry.getControls(frameworkId);
    const assessments: ControlAssessment[] = controls.map((req) =>
      this.evaluateControl(req, evidence, exceptions)
    );

    let totalScore = 0;
    let satisfiedCount = 0;
    let partiallySatisfiedCount = 0;
    let unsatisfiedCount = 0;
    let exceptionsCount = 0;
    let gapsCount = 0;

    for (const a of assessments) {
      totalScore += a.score;
      if (a.status === 'SATISFIED') satisfiedCount++;
      else if (a.status === 'PARTIALLY_SATISFIED') partiallySatisfiedCount++;
      else if (a.status === 'UNSATISFIED') unsatisfiedCount++;
      else if (a.status === 'EXCEPTION_GRANTED') {
        exceptionsCount++;
        satisfiedCount++;
      }
      gapsCount += a.gaps.length;
    }

    const overallScore = controls.length > 0 ? Math.round(totalScore / controls.length) : 0;
    const generatedAt = new Date().toISOString();
    const id = `rep_${frameworkId.toLowerCase()}_${Date.now()}`;

    // Canonical representation for digest
    const reportData = {
      id,
      orgId,
      frameworkId,
      overallScore,
      totalControls: controls.length,
      satisfiedCount,
      gapsCount,
      controls: assessments.map((c) => ({
        controlId: c.controlId,
        status: c.status,
        score: c.score,
        gapsCount: c.gaps.length,
      })),
      generatedAt,
    };

    const reportDigest = EvidenceCollector.computeDigest(reportData);

    return {
      id,
      orgId,
      frameworkId,
      frameworkName: framework.name,
      overallScore,
      totalControls: controls.length,
      satisfiedControls: satisfiedCount,
      partiallySatisfiedControls: partiallySatisfiedCount,
      unsatisfiedControls: unsatisfiedCount,
      exceptionsCount,
      gapsCount,
      controls: assessments,
      evidenceCount: evidence.length,
      reportDigest,
      generatedAt,
      disclaimer: this.COMPLIANCE_DISCLAIMER,
    };
  }

  /**
   * Generates a CSV export of an assessment report.
   */
  public static exportReportToCsv(report: FrameworkAssessmentReport): string {
    const lines: string[] = [];

    // Header info
    lines.push(`"Report ID","${report.id}"`);
    lines.push(`"Framework","${report.frameworkName}"`);
    lines.push(`"Organization","${report.orgId}"`);
    lines.push(`"Overall Compliance Score","${report.overallScore}%"`);
    lines.push(`"Generated At","${report.generatedAt}"`);
    lines.push(`"Report SHA-256 Digest","${report.reportDigest}"`);
    lines.push(`"Disclaimer","${report.disclaimer.replace(/"/g, '""')}"`);
    lines.push('');

    // Table Header
    lines.push('"Control ID","Code","Title","Category","Shared Responsibility","Status","Score","Details","Gaps"');

    // Table rows
    for (const c of report.controls) {
      const gapDescriptions = c.gaps.map((g) => `[${g.severity}] ${g.title}`).join('; ');
      lines.push(
        `"${c.controlId}","${c.code}","${c.title}","${c.category}","${c.responsibility}","${c.status}","${c.score}%","${c.details.replace(/"/g, '""')}","${gapDescriptions.replace(/"/g, '""')}"`
      );
    }

    return lines.join('\n');
  }
}
