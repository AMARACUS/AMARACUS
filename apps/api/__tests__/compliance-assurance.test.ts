/**
 * @file apps/api/__tests__/compliance-assurance.test.ts
 * Comprehensive Test Suite for Phase 22: AMARACUS Cryptographic Trust, Compliance & Assurance Platform
 */

import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { generateAmaracusApiKey } from '../src/lib/api-keys';
import { Amaracus } from '@amaracus/sdk';
import {
  FrameworkRegistry,
  EvidenceCollector,
  ControlEvaluator,
  EvidenceArtifact,
  ComplianceFrameworkId,
} from '@amaracus/crypto-core';
import { complianceAssuranceService } from '../src/lib/compliance-assurance-service';

describe('Phase 22 — AMARACUS Cryptographic Trust, Compliance & Assurance Platform', () => {
  let server: http.Server;
  let baseUrl: string;

  // Tenant A: Primary Enterprise Organization
  let orgA: any;
  let projectA: any;
  let apiKeyALive: string;

  // Tenant B: Isolated Organization for Tenant Isolation & IDOR Verification
  let orgB: any;
  let projectB: any;
  let apiKeyBLive: string;

  // Identities for Four-Eyes Principle
  const requesterId = `usr_proposer_${Date.now()}`;
  const approverId = `usr_auditor_${Date.now()}`;

  let sdkClientA: Amaracus;
  let sdkClientB: Amaracus;

  beforeAll(async () => {
    // 1. Launch HTTP server on dynamic port
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // 2. Setup Tenant A
    orgA = await db.createOrganization({
      name: 'Cyber Assurance Enterprise A',
      slug: `assurance-org-a-${Date.now()}`,
    });
    projectA = await db.createProject({
      organizationId: orgA.id,
      name: 'Production Core Workloads',
      slug: 'prod-core',
    });
    const envAProd = await db.createEnvironment({
      projectId: projectA.id,
      name: 'Production',
      slug: 'production',
      type: 'production',
    });

    const keyResultA = generateAmaracusApiKey('live');
    await db.createApiCredential({
      organizationId: orgA.id,
      projectId: projectA.id,
      environmentId: envAProd.id,
      name: 'Compliance Full Access Key A',
      prefix: keyResultA.prefix,
      keyHash: keyResultA.keyHash,
      scopes: [
        'compliance:read',
        'compliance:assess',
        'compliance:evidence',
        'compliance:exceptions',
        'compliance:export',
        'keys:read',
        'keys:create',
      ],
      env: 'live',
    });
    apiKeyALive = keyResultA.fullKey;

    // 3. Setup Tenant B
    orgB = await db.createOrganization({
      name: 'Isolated Enterprise B',
      slug: `assurance-org-b-${Date.now()}`,
    });
    projectB = await db.createProject({
      organizationId: orgB.id,
      name: 'Secondary Workloads',
      slug: 'secondary-core',
    });
    const envBProd = await db.createEnvironment({
      projectId: projectB.id,
      name: 'Production',
      slug: 'production',
      type: 'production',
    });

    const keyResultB = generateAmaracusApiKey('live');
    await db.createApiCredential({
      organizationId: orgB.id,
      projectId: projectB.id,
      environmentId: envBProd.id,
      name: 'Compliance Key B',
      prefix: keyResultB.prefix,
      keyHash: keyResultB.keyHash,
      scopes: [
        'compliance:read',
        'compliance:assess',
        'compliance:evidence',
        'compliance:exceptions',
        'compliance:export',
      ],
      env: 'live',
    });
    apiKeyBLive = keyResultB.fullKey;

    // 4. Initialize SDK clients
    sdkClientA = new Amaracus({
      apiKey: apiKeyALive,
      baseUrl: `${baseUrl}/api/v1`,
    });

    sdkClientB = new Amaracus({
      apiKey: apiKeyBLive,
      baseUrl: `${baseUrl}/api/v1`,
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  beforeEach(() => {
    complianceAssuranceService.resetState();
  });

  describe('1. Framework Registry & Authoritative Standards', () => {
    it('registers all 6 authoritative compliance frameworks', () => {
      const frameworks = FrameworkRegistry.getFrameworks();
      expect(frameworks.length).toBe(6);

      const frameworkIds = frameworks.map((f) => f.id);
      expect(frameworkIds).toContain('SOC_2_TYPE_II');
      expect(frameworkIds).toContain('ISO_27001_2022');
      expect(frameworkIds).toContain('NIST_SP_800_53_R5');
      expect(frameworkIds).toContain('NIST_SP_800_57');
      expect(frameworkIds).toContain('FIPS_140_3');
      expect(frameworkIds).toContain('NIST_PQC');
    });

    it('retrieves detailed definitions for SOC 2 Type II with correct controls', () => {
      const soc2 = FrameworkRegistry.getFramework('SOC_2_TYPE_II');
      expect(soc2).toBeDefined();
      expect(soc2?.authority).toContain('AICPA');

      const controls = FrameworkRegistry.getControls('SOC_2_TYPE_II');
      expect(controls.length).toBe(3);
      expect(controls.map((c) => c.code)).toEqual(['CC6.1', 'CC6.6', 'CC6.7']);
    });

    it('correctly maps shared responsibility parties across technical controls', () => {
      const cc61 = FrameworkRegistry.getControl('SOC2-CC6.1');
      expect(cc61?.responsibility).toBe('SHARED_RESPONSIBILITY');

      const cc66 = FrameworkRegistry.getControl('SOC2-CC6.6');
      expect(cc66?.responsibility).toBe('AMARACUS_MANAGED');

      const sc12 = FrameworkRegistry.getControl('NIST-SC-12');
      expect(sc12?.responsibility).toBe('CLOUD_PROVIDER_HSM');

      const sc28 = FrameworkRegistry.getControl('NIST-SC-28');
      expect(sc28?.responsibility).toBe('CUSTOMER_CONFIGURED');
    });
  });

  describe('2. Verifiable Evidence Collection, Sanitization & Digest Integrity', () => {
    it('creates tamper-evident evidence artifact with valid SHA-256 digest and chain of custody', () => {
      const artifact = EvidenceCollector.createArtifact(orgA.id, {
        type: 'KEY_METADATA',
        source: 'keys/key-prod-01',
        title: 'Master Key Metadata',
        properties: {
          keyId: 'key-prod-01',
          algorithm: 'AES-256-GCM',
          provider: 'azure_managed_hsm',
        },
      });

      expect(artifact.id).toMatch(/^evi_key_metadata_[a-f0-9]{12}$/);
      expect(artifact.digest).toHaveLength(64);
      expect(artifact.chainOfCustody.digestAlgorithm).toBe('SHA-256');
      expect(artifact.freshness).toBe('VALID');
      expect(EvidenceCollector.verifyIntegrity(artifact)).toBe(true);
    });

    it('strictly sanitizes and redacts raw private keys, plaintexts, and secret tokens from evidence properties', () => {
      const rawProps = {
        keyId: 'key-prod-01',
        algorithm: 'AES-256-GCM',
        privateKey: 'MIICXAIBAAKCAQEA0Y...',
        secretKey: 'topsecret123',
        rawKey: Buffer.from('confidential').toString('hex'),
        plaintext: 'Sensitive Customer Credit Card Number',
        token: 'amk_live_supersecret',
        safeMetadata: {
          rotationIntervalDays: 90,
          innerSecret: 'nested_password',
        },
      };

      const sanitized = EvidenceCollector.sanitizeProperties(rawProps);

      expect(sanitized.keyId).toBe('key-prod-01');
      expect(sanitized.algorithm).toBe('AES-256-GCM');
      expect(sanitized.privateKey).toBe('[REDACTED_CONFIDENTIAL_KEY_MATERIAL]');
      expect(sanitized.secretKey).toBe('[REDACTED_CONFIDENTIAL_KEY_MATERIAL]');
      expect(sanitized.rawKey).toBe('[REDACTED_CONFIDENTIAL_KEY_MATERIAL]');
      expect(sanitized.plaintext).toBe('[REDACTED_CONFIDENTIAL_KEY_MATERIAL]');
      expect(sanitized.token).toBe('[REDACTED_CONFIDENTIAL_KEY_MATERIAL]');
      expect(sanitized.safeMetadata.rotationIntervalDays).toBe(90);
      expect(sanitized.safeMetadata.innerSecret).toBe('[REDACTED_CONFIDENTIAL_KEY_MATERIAL]');
    });

    it('evaluates evidence freshness correctly based on TTL', () => {
      const now = Date.now();
      const validCollected = new Date(now - 1000 * 60).toISOString();
      const validExpiry = new Date(now + 1000 * 60 * 60 * 24).toISOString();
      expect(EvidenceCollector.evaluateFreshness(validCollected, validExpiry)).toBe('VALID');

      const expiredCollected = new Date(now - 1000 * 60 * 60 * 25).toISOString();
      const expiredExpiry = new Date(now - 1000 * 60).toISOString();
      expect(EvidenceCollector.evaluateFreshness(expiredCollected, expiredExpiry)).toBe('EXPIRED');
    });
  });

  describe('3. Deterministic Control Evaluation & Gap Analysis', () => {
    it('evaluates SOC 2 Type II with 100% compliance when evidence satisfies all controls', async () => {
      const evidence = await complianceAssuranceService.collectEvidence(orgA.id);
      const report = ControlEvaluator.evaluateFramework(orgA.id, 'SOC_2_TYPE_II', evidence);

      expect(report.frameworkId).toBe('SOC_2_TYPE_II');
      expect(report.overallScore).toBe(100);
      expect(report.satisfiedControls).toBe(3);
      expect(report.gapsCount).toBe(0);
      expect(report.disclaimer).toContain('IMPORTANT NOTICE: This automated assurance evaluation');
      expect(report.reportDigest).toHaveLength(64);
    });

    it('flags CRITICAL gap when unmanaged plaintext keys are detected in inventory', async () => {
      const badEvidence: EvidenceArtifact = EvidenceCollector.createArtifact(orgA.id, {
        type: 'KEY_METADATA',
        source: 'keys/bad-key',
        title: 'Unmanaged Plaintext Key',
        properties: {
          keyId: 'bad-key-1',
          algorithm: 'AES-256-GCM',
          provider: 'local_unencrypted',
        },
      });

      const report = ControlEvaluator.evaluateFramework(orgA.id, 'SOC_2_TYPE_II', [badEvidence]);
      const cc61 = report.controls.find((c) => c.code === 'CC6.1');

      expect(cc61?.status).toBe('UNSATISFIED');
      expect(cc61?.score).toBe(40);
      expect(cc61?.gaps.length).toBe(1);
      expect(cc61?.gaps[0].severity).toBe('CRITICAL');
      expect(cc61?.gaps[0].remediationGuidance).toContain('Phase 19 Cryptographic Migration Platform');
    });

    it('detects deprecated algorithm gap in ISO/IEC 27001 A.8.24 when CBOM reports legacy algorithms', async () => {
      const legacyCbom: EvidenceArtifact = EvidenceCollector.createArtifact(orgA.id, {
        type: 'CBOM_INVENTORY',
        source: 'cbom/legacy-scan',
        title: 'CBOM with Deprecated Ciphers',
        properties: {
          deprecatedAlgorithmsCount: 3,
        },
      });

      const report = ControlEvaluator.evaluateFramework(orgA.id, 'ISO_27001_2022', [legacyCbom]);
      const a824 = report.controls.find((c) => c.code === 'A.8.24');

      expect(a824?.status).toBe('PARTIALLY_SATISFIED');
      expect(a824?.score).toBe(60);
      expect(a824?.gaps[0].severity).toBe('HIGH');
      expect(a824?.gaps[0].title).toContain('Deprecated cryptographic algorithms');
    });
  });

  describe('4. Controlled Exceptions Lifecycle & Four-Eyes Principle', () => {
    it('requests a compliance exception in PENDING state', async () => {
      const futureExpiry = new Date(Date.now() + 30 * 86400000).toISOString();
      const exception = await complianceAssuranceService.requestException(
        orgA.id,
        {
          controlId: 'SOC2-CC6.1',
          justification: 'Legacy banking mainframe batch connector migration scheduled for Q4',
          compensatingControls: 'Air-gapped VPC subnet, mutual TLS 1.3, hourly HMAC log verification',
          expiresAt: futureExpiry,
        },
        requesterId
      );

      expect(exception.id).toMatch(/^exc_soc2_cc6_1_\d+$/);
      expect(exception.status).toBe('PENDING');
      expect(exception.requestedBy).toBe(requesterId);
      expect(exception.approvedBy).toBeUndefined();
    });

    it('strictly enforces Four-Eyes Principle: proposer CANNOT approve their own exception', async () => {
      const futureExpiry = new Date(Date.now() + 30 * 86400000).toISOString();
      const exception = await complianceAssuranceService.requestException(
        orgA.id,
        {
          controlId: 'ISO-A.8.24',
          justification: 'Legacy archive decryption requires 3DES for 14 days',
          compensatingControls: 'Read-only restricted key usage in isolated enclave',
          expiresAt: futureExpiry,
        },
        requesterId
      );

      await expect(
        complianceAssuranceService.approveException(orgA.id, exception.id, requesterId)
      ).rejects.toThrow('FOUR_EYES_VIOLATION');
    });

    it('allows distinct authorized auditor to approve exception and reflects EXCEPTION_GRANTED in report', async () => {
      const futureExpiry = new Date(Date.now() + 30 * 86400000).toISOString();
      const exception = await complianceAssuranceService.requestException(
        orgA.id,
        {
          controlId: 'SOC2-CC6.1',
          justification: 'Mainframe batch transition grace period',
          compensatingControls: 'Dedicated isolated bastion host',
          expiresAt: futureExpiry,
        },
        requesterId
      );

      // Distinct approver approves
      const approved = await complianceAssuranceService.approveException(
        orgA.id,
        exception.id,
        approverId
      );
      expect(approved.status).toBe('APPROVED');
      expect(approved.approvedBy).toBe(approverId);

      // Evaluator now returns EXCEPTION_GRANTED
      const badEvidence: EvidenceArtifact = EvidenceCollector.createArtifact(orgA.id, {
        type: 'KEY_METADATA',
        source: 'keys/legacy',
        title: 'Legacy Key',
        properties: { provider: 'local_unencrypted' },
      });

      const report = ControlEvaluator.evaluateFramework(orgA.id, 'SOC_2_TYPE_II', [badEvidence], [approved]);
      const cc61 = report.controls.find((c) => c.code === 'CC6.1');

      expect(cc61?.status).toBe('EXCEPTION_GRANTED');
      expect(cc61?.exceptionId).toBe(approved.id);
      expect(report.exceptionsCount).toBe(1);
    });

    it('rejects approval on an expired exception', async () => {
      // Create past date timestamp
      const pastExpiry = new Date(Date.now() + 200).toISOString();
      const exception = await complianceAssuranceService.requestException(
        orgA.id,
        {
          controlId: 'NIST-SC-12',
          justification: 'Temporary rotation delay',
          compensatingControls: 'IP whitelisting',
          expiresAt: pastExpiry,
        },
        requesterId
      );

      // Wait 300ms for expiration
      await new Promise((r) => setTimeout(r, 300));

      await expect(
        complianceAssuranceService.approveException(orgA.id, exception.id, approverId)
      ).rejects.toThrow('Cannot approve an expired compliance exception');
    });
  });

  describe('5. Audit-Ready Reporting & Export', () => {
    it('generates JSON report with legal non-certification disclaimer and report digest', async () => {
      const { data, contentType } = await complianceAssuranceService.generateReport(
        orgA.id,
        'SOC_2_TYPE_II',
        'json'
      );

      expect(contentType).toBe('application/json');
      expect(data.frameworkId).toBe('SOC_2_TYPE_II');
      expect(data.disclaimer).toContain('does not constitute a formal certification');
      expect(data.reportDigest).toBeDefined();
    });

    it('exports audit report in RFC 4180 compliant CSV format', async () => {
      const { data, contentType } = await complianceAssuranceService.generateReport(
        orgA.id,
        'SOC_2_TYPE_II',
        'csv'
      );

      expect(contentType).toBe('text/csv');
      expect(typeof data).toBe('string');
      expect(data).toContain('"Report ID"');
      expect(data).toContain('"SOC 2 Type II (Trust Services Criteria)"');
      expect(data).toContain('"CC6.1"');
      expect(data).toContain('"CC6.6"');
      expect(data).toContain('"CC6.7"');
      expect(data).toContain('"Disclaimer"');
    });
  });

  describe('6. Official TypeScript SDK Integration', () => {
    it('lists all compliance frameworks via sdkClient.compliance.getFrameworks()', async () => {
      const frameworks = await sdkClientA.compliance.getFrameworks();
      expect(Array.isArray(frameworks)).toBe(true);
      expect(frameworks.length).toBe(6);
      expect(frameworks[0].id).toBeDefined();
    });

    it('retrieves single framework via sdkClient.compliance.getFramework()', async () => {
      const fw = await sdkClientA.compliance.getFramework('NIST_SP_800_53_R5');
      expect(fw.id).toBe('NIST_SP_800_53_R5');
      expect(fw.controlCount).toBe(4);
    });

    it('evaluates compliance posture via sdkClient.compliance.evaluate()', async () => {
      const report = await sdkClientA.compliance.evaluate({
        frameworkId: 'SOC_2_TYPE_II',
        forceRefresh: true,
      });

      expect(report).toBeDefined();
      expect((report as any).frameworkId).toBe('SOC_2_TYPE_II');
      expect((report as any).overallScore).toBeGreaterThanOrEqual(0);
    });

    it('retrieves evidence artifacts via sdkClient.compliance.getEvidence()', async () => {
      const evidence = await sdkClientA.compliance.getEvidence();
      expect(Array.isArray(evidence)).toBe(true);
      expect(evidence.length).toBeGreaterThan(0);
      expect(evidence[0].digest).toHaveLength(64);
    });

    it('requests and approves an exception via sdkClient.compliance', async () => {
      const futureExpiry = new Date(Date.now() + 15 * 86400000).toISOString();
      const exc = await sdkClientA.compliance.requestException({
        controlId: 'NIST-SC-8',
        justification: 'Internal legacy load-balancer TLS transition',
        compensatingControls: 'VPC private isolation',
        expiresAt: futureExpiry,
      });

      expect(exc.id).toBeDefined();
      expect(exc.status).toBe('PENDING');

      const approved = await sdkClientA.compliance.approveException(exc.id, approverId);
      expect(approved.status).toBe('APPROVED');
      expect(approved.approvedBy).toBe(approverId);
    });

    it('verifies sdkClient.assurance is a valid alias for sdkClient.compliance', () => {
      expect(sdkClientA.assurance).toBe(sdkClientA.compliance);
    });
  });

  describe('7. Multi-Tenancy & Perimeter Security', () => {
    it('strictly isolates evidence between Tenant A and Tenant B', async () => {
      // Ingest Tenant B specific evidence
      const customEvidenceB: EvidenceArtifact = EvidenceCollector.createArtifact(orgB.id, {
        type: 'KEY_METADATA',
        source: 'keys/tenant-b-unique',
        title: 'Tenant B Private Key Metadata',
        properties: { keyId: 'tenant-b-unique-key' },
      });
      complianceAssuranceService.addEvidenceArtifact(orgB.id, customEvidenceB);

      const evidenceA = await sdkClientA.compliance.getEvidence();
      const evidenceB = await sdkClientB.compliance.getEvidence();

      const bIdsInA = evidenceA.filter((e) => e.source.includes('tenant-b-unique'));
      const bIdsInB = evidenceB.filter((e) => e.source.includes('tenant-b-unique'));

      expect(bIdsInA.length).toBe(0);
      expect(bIdsInB.length).toBe(1);
    });

    it('rejects unauthenticated requests with 401', async () => {
      const unauthClient = new Amaracus({
        apiKey: 'am_live_invalidkeywithzeroaccess1234567890abcdef',
        baseUrl: `${baseUrl}/api/v1`,
      });

      await expect(unauthClient.compliance.getFrameworks()).rejects.toThrow();
    });
  });
});
