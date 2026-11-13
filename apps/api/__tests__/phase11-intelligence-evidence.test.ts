import { db } from '../src/lib/data-store';
import { CryptoIntelligenceService } from '../src/lib/crypto-intelligence-service';

describe('Phase 11: intelligence evidence comes from real records', () => {
  const service = CryptoIntelligenceService.getInstance();
  let orgId: string;

  beforeAll(async () => {
    const org = await db.createOrganization({ name: 'P11 Org', slug: `p11-${Date.now()}` });
    orgId = org.id;
    await db.upsertBillingSubscription({ organizationId: orgId, plan: 'BUSINESS', status: 'ACTIVE' });
  });

  it('describes certificates by their real subject, issuer and key algorithm', async () => {
    const now = Date.now();
    await db.createCertificate({
      organizationId: orgId,
      projectId: 'prj',
      environmentId: 'env',
      authorityId: 'ca_p11',
      keyReference: 'key_ref',
      subject: 'CN=pq.example.com, O=Example, C=US',
      issuer: 'CN=P11 CA',
      serialNumber: 'p11-serial',
      certificateType: 'SERVER',
      keyAlgorithm: 'ML-DSA-65',
      signatureAlgorithm: 'ML-DSA-65',
      publicKeyAlgorithm: 'ML-DSA-65',
      status: 'ACTIVE',
      notBefore: new Date(now - 86_400_000),
      notAfter: new Date(now + 200 * 86_400_000),
      fingerprint: 'fp',
      certificatePem: '-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----',
    } as any);

    const snapshot = await service.buildEvidenceSnapshot(orgId);
    const cert = snapshot.certificates!.find((c) => c.id && c.commonName === 'pq.example.com');
    expect(cert).toMatchObject({ algorithm: 'ML-DSA-65', issuerId: 'ca_p11' });
    expect(snapshot.certificates!.some((c) => c.algorithm === 'RSA-2048')).toBe(false);
  });

  it('reports usage for the billing period, counting server errors but not client errors as failures', async () => {
    const record = (statusCode: number) =>
      db.recordApiUsage({
        organizationId: orgId,
        endpoint: '/v1/encrypt',
        method: 'POST',
        statusCode,
        durationMs: 5,
      } as any);
    // 600 requests: more than the 500 that used to cap every total.
    for (let i = 0; i < 560; i++) await record(200);
    for (let i = 0; i < 10; i++) await record(400);
    for (let i = 0; i < 30; i++) await record(503);

    const snapshot = await service.buildEvidenceSnapshot(orgId);
    expect(snapshot.usage).toHaveLength(1);
    const usage = snapshot.usage![0];
    expect(usage.totalOperations).toBe(600);
    expect(usage.failedOperations).toBe(30);
    expect(usage.billedCostUsd).toBeUndefined();
    expect(typeof usage.estimatedCostUsd).toBe('number');

    const metrics = await db.getApiUsageMetrics(orgId);
    expect(metrics.totalRequests).toBe(600);
    expect(metrics.byStatusCode['503']).toBe(30);
  });

  it('leaves usage empty for an organization with no recorded requests', async () => {
    const quiet = await db.createOrganization({ name: 'P11 quiet', slug: `p11-quiet-${Date.now()}` });
    expect((await service.buildEvidenceSnapshot(quiet.id)).usage).toEqual([]);
  });
});
