/**
 * @file packages/crypto-core/src/os/workflow-engine.ts
 * Enterprise Cryptographic Workflow & Approval Engine (Phase 20)
 */

import {
  WorkflowInstance,
  WorkflowState,
  WorkflowStep,
  WorkflowTemplate,
} from './types';

export const ENTERPRISE_WORKFLOW_TEMPLATES: WorkflowTemplate[] = [
  {
    id: 'tpl_key_rotation',
    name: 'Staged Key Rotation',
    description: 'Safely rotates a cryptographic key, executes round-trip verification, repoints active pointer, and retires old version without destruction.',
    category: 'KEY_MANAGEMENT',
    requiresDualApproval: true,
    supportedResourceTypes: ['KEY'],
    defaultSteps: [
      {
        name: 'Validate Prerequisites & Target Algorithm',
        type: 'VALIDATION',
        parameters: { checkPolicies: true },
      },
      {
        name: 'Provision Target Key Material',
        type: 'KEY_ROTATION',
        parameters: { stage: 'GENERATE' },
      },
      {
        name: 'Execute Verification Round-Trip',
        type: 'VALIDATION',
        parameters: { testRoundtrip: true },
      },
      {
        name: 'Repoint Active Key Pointer & Retire Source',
        type: 'KEY_ROTATION',
        parameters: { stage: 'CUTOVER' },
      },
    ],
  },
  {
    id: 'tpl_cert_renewal',
    name: 'Certificate Renewal & Chain Verification',
    description: 'Issues a renewed X.509 certificate before expiration, verifies chain of trust, and activates new certificate.',
    category: 'CERTIFICATES',
    requiresDualApproval: false,
    supportedResourceTypes: ['CERTIFICATE'],
    defaultSteps: [
      {
        name: 'Validate CA Health & CSR Parameters',
        type: 'VALIDATION',
        parameters: { verifyCa: true },
      },
      {
        name: 'Issue Renewed Certificate',
        type: 'CERT_RENEWAL',
        parameters: { action: 'ISSUE' },
      },
      {
        name: 'Verify Cryptographic Chain of Trust',
        type: 'VALIDATION',
        parameters: { action: 'VERIFY_CHAIN' },
      },
    ],
  },
  {
    id: 'tpl_pqc_transition',
    name: 'Post-Quantum Transition (NIST FIPS 203/204)',
    description: 'Transitions classical asymmetric keys to Post-Quantum or Hybrid lattice primitives (ML-KEM-768 or ML-DSA-65).',
    category: 'PQC',
    requiresDualApproval: true,
    supportedResourceTypes: ['KEY'],
    defaultSteps: [
      {
        name: 'Pre-Flight Post-Quantum Compatibility Check',
        type: 'ASSESSMENT',
        parameters: { evaluatePqcSupport: true },
      },
      {
        name: 'Generate NIST FIPS Lattice Key Pair',
        type: 'KEY_ROTATION',
        parameters: { algorithm: 'ML-KEM-768' },
      },
      {
        name: 'Verify Hybrid Encapsulation & Decapsulation',
        type: 'VALIDATION',
        parameters: { verifyKEM: true },
      },
    ],
  },
  {
    id: 'tpl_posture_assessment',
    name: 'Automated Posture Assessment & Drift Audit',
    description: 'Scans cryptographic inventory, deduplicates findings, checks compliance drift, and generates an updated posture summary.',
    category: 'POSTURE',
    requiresDualApproval: false,
    supportedResourceTypes: ['ORGANIZATION', 'PROJECT'],
    defaultSteps: [
      {
        name: 'Discover Cryptographic Resources',
        type: 'ASSESSMENT',
        parameters: { scanInventory: true },
      },
      {
        name: 'Evaluate Policies & Deduplicate Findings',
        type: 'VALIDATION',
        parameters: { evaluatePolicies: true },
      },
      {
        name: 'Publish Posture Summary & Health Score',
        type: 'NOTIFICATION',
        parameters: { notifyWebhooks: true },
      },
    ],
  },
];

export class CryptographicWorkflowEngine {
  /**
   * Instantiates a workflow from an enterprise template.
   */
  public static instantiateTemplate(
    templateId: string,
    params: {
      orgId: string;
      proposerId: string;
      name?: string;
      projectId?: string;
      envId?: string;
      customParameters?: Record<string, any>;
    }
  ): WorkflowInstance {
    const tpl = ENTERPRISE_WORKFLOW_TEMPLATES.find((t) => t.id === templateId);
    if (!tpl) {
      throw new Error(`Enterprise workflow template '${templateId}' not found`);
    }

    const workflowId = `wf_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    const steps: WorkflowStep[] = tpl.defaultSteps.map((s, idx) => ({
      id: `${workflowId}_step_${idx + 1}`,
      name: s.name,
      type: s.type,
      status: 'PENDING',
      parameters: { ...s.parameters, ...(params.customParameters || {}) },
    }));

    return {
      id: workflowId,
      orgId: params.orgId,
      projectId: params.projectId,
      envId: params.envId,
      templateId: tpl.id,
      name: params.name || tpl.name,
      description: tpl.description,
      state: 'DRAFT',
      requiresDualApproval: tpl.requiresDualApproval,
      proposerId: params.proposerId,
      currentStepIndex: 0,
      steps,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      metadata: {},
    };
  }

  /**
   * Validates a workflow and advances state to AWAITING_APPROVAL or READY.
   */
  public static validateWorkflow(workflow: WorkflowInstance): WorkflowInstance {
    if (workflow.state !== 'DRAFT') {
      throw new Error(`Cannot validate workflow in state '${workflow.state}' (must be DRAFT)`);
    }

    if (!workflow.steps || workflow.steps.length === 0) {
      throw new Error('Workflow contains no executable steps');
    }

    const nextState: WorkflowState = workflow.requiresDualApproval
      ? 'AWAITING_APPROVAL'
      : 'READY';

    return {
      ...workflow,
      state: nextState,
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * Approves a workflow under server-side separation of duties (proposer != approver).
   */
  public static approveWorkflow(
    workflow: WorkflowInstance,
    approverId: string
  ): WorkflowInstance {
    if (workflow.state !== 'AWAITING_APPROVAL') {
      throw new Error(
        `Workflow in state '${workflow.state}' is not awaiting approval`
      );
    }

    if (workflow.requiresDualApproval && workflow.proposerId === approverId) {
      const err = new Error(
        `SEPARATION_OF_DUTIES_VIOLATION: Proposer '${workflow.proposerId}' cannot approve their own high-impact workflow.`
      );
      (err as any).code = 'SEPARATION_OF_DUTIES_VIOLATION';
      throw err;
    }

    return {
      ...workflow,
      state: 'READY',
      approverId,
      approvedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * Cancels a workflow with an explicit reason.
   */
  public static cancelWorkflow(
    workflow: WorkflowInstance,
    reason: string
  ): WorkflowInstance {
    if (['COMPLETED', 'CANCELLED'].includes(workflow.state)) {
      throw new Error(`Cannot cancel workflow already in terminal state '${workflow.state}'`);
    }

    return {
      ...workflow,
      state: 'CANCELLED',
      cancelReason: reason,
      cancelledAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }
}
