import { Router, Request, Response } from 'express';
import credentialsRouter from './credentials';
import webhooksRouter from './webhooks';
import jobsRouter from './jobs';
import usageRouter from './usage';
import pqcRouter from './pqc';
import docsRouter from './docs';
import cryptoUniversalRouter from './crypto-universal';
import keysUniversalRouter from './keys-universal';
import operationsRouter from './operations';
import policiesRouter from './policies';
import controlRouter from './control';
import migrationsRouter from './migrations';
import osRouter from './os';
import intelligenceOptimizationRouter from './intelligence';
import complianceRouter from './compliance';
import emailRouter from './email';

import cryptoRoutes from '../crypto';
import keysRoutes from '../keys';
import byokRoutes from '../byok';
import pkiRoutes from '../pki';
import intelligenceRoutes from '../intelligence';
import { advancedCryptoRouter } from '../advanced-crypto';

import { requireAuth, requireOrgMember } from '../../middleware/auth';
import { sendSuccess } from '../../middleware/response-formatter';
import { loadCloudModule } from '../../lib/edition';

// AMARACUS Cloud only (billing, payment webhooks, hackathon, reviews). Null when self-hosted.
const cloud = loadCloudModule();

const v1Router = Router();

// 1. Health & Identity verification
v1Router.get('/health', (req: Request, res: Response) => {
  return sendSuccess(res, {
    status: 'ok',
    version: '1.0.0',
    service: 'amaracus-developer-platform',
    timestamp: new Date().toISOString(),
  });
});

v1Router.get('/auth/me', requireAuth, requireOrgMember, (req: Request, res: Response) => {
  if (req.apiKey) {
    return sendSuccess(res, {
      type: 'API_CREDENTIAL',
      id: req.apiKey.id,
      name: req.apiKey.name,
      prefix: req.apiKey.prefix,
      organizationId: req.apiKey.organizationId,
      projectId: req.apiKey.projectId,
      environmentId: req.apiKey.environmentId,
      scopes: req.apiKey.scopes || [],
      status: req.apiKey.status,
    });
  }

  return sendSuccess(res, {
    type: 'USER_SESSION',
    user: req.user
      ? {
          id: req.user.id,
          name: req.user.name,
          email: req.user.email,
        }
      : null,
    organizationId: req.organizationId,
    orgRole: req.orgRole,
  });
});

// 2. Developer Platform Core Endpoints
v1Router.use('/credentials', credentialsRouter);
if (cloud) cloud.mountCloudV1Webhooks(v1Router);
v1Router.use('/webhooks', webhooksRouter);
v1Router.use('/jobs', jobsRouter);
v1Router.use('/usage', usageRouter);
if (cloud) cloud.mountCloudV1Routes(v1Router);
v1Router.use('/email', emailRouter);

// 3. Phase 12 Universal Cryptographic API, Keys & Policies (Phase 15) & Control Plane (Phase 16), Migrations (Phase 19), OS (Phase 20)
v1Router.use('/os', osRouter);
v1Router.use('/migrations', migrationsRouter);
v1Router.use('/control', controlRouter);
v1Router.use('/policies', policiesRouter);
v1Router.use('/operations', operationsRouter);
v1Router.use('/keys', keysUniversalRouter);
v1Router.use('/', cryptoUniversalRouter);

// 4. Namespaced Crypto & PQC Endpoints
v1Router.use('/crypto', cryptoRoutes);
v1Router.use('/pqc', pqcRouter);

// 5. BYOK & Customer Key Providers
v1Router.use('/customer-key-providers', byokRoutes);

// 6. PKI & Certificates (/v1/pki/certificates, /v1/pki/certificate-authorities, /v1/pki/csrs)
v1Router.use('/pki', pkiRoutes);

// 7. Crypto Intelligence & Autonomous Optimization (Phase 21) & CBOM (Phase 8)
v1Router.use('/optimization', intelligenceOptimizationRouter);
v1Router.use('/intelligence', intelligenceOptimizationRouter);
v1Router.use('/crypto/inventory', intelligenceRoutes);
v1Router.use('/crypto/findings', intelligenceRoutes);
v1Router.use('/crypto/cbom', intelligenceRoutes);
v1Router.use('/crypto/migrations', intelligenceRoutes);
v1Router.use('/intelligence', intelligenceRoutes);


// 8. Cryptographic Trust, Compliance & Assurance (Phase 22)
v1Router.use('/compliance', complianceRouter);
v1Router.use('/assurance', complianceRouter);

// 9. Advanced Cryptography (ZK, FHE, MPC, Threshold)
v1Router.use('/advanced', advancedCryptoRouter);
v1Router.use('/advanced-crypto', advancedCryptoRouter);

// 10. Universal Hosting & Multi-Cloud Infrastructure (Phase 23): AMARACUS Cloud only.
if (cloud) cloud.mountCloudV1Hosting(v1Router);

// 11. Documentation & OpenAPI Spec
v1Router.use('/', docsRouter);

export { v1Router };
export default v1Router;
