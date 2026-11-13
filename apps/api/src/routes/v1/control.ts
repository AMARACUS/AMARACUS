import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { db } from '../../lib/data-store';
import { requireAuth } from '../../middleware/auth';
import { requireResourceAccess } from '../../middleware/resource-access';
import { sendSuccess } from '../../middleware/response-formatter';
import { canManageTargetRole, Role } from '../../lib/permissions';

const controlRouter = Router();

// Apply base authentication for all control-plane endpoints
controlRouter.use(requireAuth);

// Helper for consistent error responses
function sendError(res: Response, status: number, code: string, message: string, req: Request) {
  const requestId = (req as any).requestId || `req_${Date.now()}`;
  return res.status(status).json({
    error: { code, message, requestId },
  });
}

// ==========================================
// 1. ORGANIZATIONS & SETTINGS (Sections 4, 32)
// ==========================================

controlRouter.get('/organizations/:orgId', requireResourceAccess('organization:read'), async (req: Request, res: Response) => {
  const org = await db.findOrgById(req.params.orgId);
  if (!org) return sendError(res, 404, 'ORGANIZATION_NOT_FOUND', 'Organization not found.', req);
  const security = await db.getOrganizationSecuritySettings(org.id);
  return sendSuccess(res, {
    organization: org,
    securitySettings: security,
  });
});

controlRouter.patch('/organizations/:orgId', requireResourceAccess('organization:update'), async (req: Request, res: Response) => {
  const org = await db.findOrgById(req.params.orgId);
  if (!org) return sendError(res, 404, 'ORGANIZATION_NOT_FOUND', 'Organization not found.', req);

  if (req.body.name) {
    await db.updateOrg(org.id, { name: req.body.name });
  }

  if (req.body.securitySettings) {
    await db.updateOrganizationSecuritySettings(org.id, req.body.securitySettings);
  }

  const updatedOrg = await db.findOrgById(org.id);
  const updatedSec = await db.getOrganizationSecuritySettings(org.id);

  await db.createAuditEvent({
    organizationId: org.id,
    userId: req.user?.id || req.apiKey?.id || 'system',
    action: 'ORGANIZATION_SETTINGS_UPDATED',
    resourceType: 'ORGANIZATION',
    resourceId: org.id,
    metadata: { fields: Object.keys(req.body) },
  });

  return sendSuccess(res, {
    organization: updatedOrg,
    securitySettings: updatedSec,
  });
});

controlRouter.get('/organizations/:orgId/members', requireResourceAccess('members:read'), async (req: Request, res: Response) => {
  const members = await db.getOrgMembers(req.params.orgId);
  return sendSuccess(res, { members });
});

controlRouter.post('/organizations/:orgId/members', requireResourceAccess('members:invite'), async (req: Request, res: Response) => {
  const { email, role } = req.body;
  if (!email) return sendError(res, 400, 'INVALID_REQUEST', 'Email is required.', req);

  const targetRole = (role || 'DEVELOPER').toUpperCase() as Role;
  if (!canManageTargetRole(req.orgRole || 'MEMBER', targetRole)) {
    return sendError(res, 403, 'FORBIDDEN', `Your role '${req.orgRole}' cannot assign role '${targetRole}'.`, req);
  }

  // Find or create user
  let user = await db.findUserByEmail(email);
  if (!user) {
    user = await db.createUser({
      email,
      name: email.split('@')[0],
      passwordHash: crypto.randomBytes(16).toString('hex'),
    });
  }

  const member = await db.addMember({
    organizationId: req.params.orgId,
    userId: user.id,
    role: targetRole,
  });

  await db.createAuditEvent({
    organizationId: req.params.orgId,
    userId: req.user?.id || 'system',
    action: 'MEMBER_ADDED',
    resourceType: 'MEMBER',
    resourceId: user.id,
    metadata: { email, role: targetRole },
  });

  return sendSuccess(res, { member }, 201);
});

controlRouter.patch('/organizations/:orgId/members/:userId', requireResourceAccess('members:update_role'), async (req: Request, res: Response) => {
  const { role } = req.body;
  if (!role) return sendError(res, 400, 'INVALID_REQUEST', 'Role is required.', req);

  const targetRole = role.toUpperCase() as Role;
  if (!canManageTargetRole(req.orgRole || 'MEMBER', targetRole)) {
    return sendError(res, 403, 'FORBIDDEN', `Your role '${req.orgRole}' cannot assign role '${targetRole}'.`, req);
  }

  const currentMember = await db.getMember(req.params.orgId, req.params.userId);
  if (!currentMember) return sendError(res, 404, 'MEMBER_NOT_FOUND', 'Member not found in organization.', req);

  // An OWNER can only be modified by an OWNER
  if (currentMember.role === 'OWNER' && req.orgRole !== 'OWNER') {
    return sendError(res, 403, 'FORBIDDEN', 'Only an OWNER can modify the role of an OWNER.', req);
  }

  if (!canManageTargetRole(req.orgRole || 'MEMBER', currentMember.role) && req.orgRole !== 'OWNER') {
    return sendError(res, 403, 'FORBIDDEN', `Your role '${req.orgRole}' cannot manage a member with role '${currentMember.role}'.`, req);
  }

  const updated = await db.updateMemberRole(req.params.orgId, req.params.userId, targetRole);

  await db.createAuditEvent({
    organizationId: req.params.orgId,
    userId: req.user?.id || 'system',
    action: 'MEMBER_ROLE_UPDATED',
    resourceType: 'MEMBER',
    resourceId: req.params.userId,
    metadata: { newRole: targetRole },
  });

  return sendSuccess(res, { member: updated });
});

controlRouter.delete('/organizations/:orgId/members/:userId', requireResourceAccess('members:remove'), async (req: Request, res: Response) => {
  const currentMember = await db.getMember(req.params.orgId, req.params.userId);
  if (!currentMember) return sendError(res, 404, 'MEMBER_NOT_FOUND', 'Member not found in organization.', req);

  if (currentMember.role === 'OWNER' && req.orgRole !== 'OWNER') {
    return sendError(res, 403, 'FORBIDDEN', 'Only an OWNER can remove an OWNER from the organization.', req);
  }

  await db.removeMember(req.params.orgId, req.params.userId);

  await db.createAuditEvent({
    organizationId: req.params.orgId,
    userId: req.user?.id || 'system',
    action: 'MEMBER_REMOVED',
    resourceType: 'MEMBER',
    resourceId: req.params.userId,
  });

  return sendSuccess(res, { success: true });
});

// ==========================================
// 2. PROJECTS & ENVIRONMENTS (Sections 5, 6)
// ==========================================

controlRouter.get('/projects', requireResourceAccess('project:read'), async (req: Request, res: Response) => {
  const orgId = req.organizationId!;
  const projects = await db.getProjectsByOrg(orgId);
  return sendSuccess(res, { projects });
});

controlRouter.post('/projects', requireResourceAccess('project:create'), async (req: Request, res: Response) => {
  const orgId = req.organizationId!;
  const { name, slug, description } = req.body;
  if (!name || !slug) return sendError(res, 400, 'INVALID_REQUEST', 'Name and slug are required.', req);

  const project = await db.createProject({
    organizationId: orgId,
    name: typeof name === 'string' ? name.replace(/&#x2F;/g, '/') : name,
    slug: slug.toLowerCase().replace(/[^a-z0-9_-]/g, '-'),
    description,
  });

  // Automatically create default environments
  await db.createEnvironment({
    projectId: project.id,
    name: 'Production',
    slug: 'production',
    type: 'production',
  });
  await db.createEnvironment({
    projectId: project.id,
    name: 'Staging',
    slug: 'staging',
    type: 'staging',
  });
  await db.createEnvironment({
    projectId: project.id,
    name: 'Development',
    slug: 'development',
    type: 'development',
  });

  const fullProject = await db.getProjectById(project.id);

  await db.createAuditEvent({
    organizationId: orgId,
    userId: req.user?.id || 'system',
    action: 'PROJECT_CREATED',
    resourceType: 'PROJECT',
    resourceId: project.id,
    metadata: { name, slug },
  });

  return sendSuccess(res, { project: fullProject }, 201);
});

controlRouter.get('/projects/:projectId', requireResourceAccess('project:read'), async (req: Request, res: Response) => {
  const project = (req as any).project || (await db.getProjectById(req.params.projectId));
  if (!project || project.organizationId !== req.organizationId) {
    return sendError(res, 404, 'PROJECT_NOT_FOUND', 'Project not found.', req);
  }
  return sendSuccess(res, { project });
});

controlRouter.patch('/projects/:projectId', requireResourceAccess('project:update'), async (req: Request, res: Response) => {
  const project = (req as any).project || (await db.getProjectById(req.params.projectId));
  if (!project || project.organizationId !== req.organizationId) {
    return sendError(res, 404, 'PROJECT_NOT_FOUND', 'Project not found.', req);
  }

  const updated = await db.updateProject(project.id, {
    name: req.body.name,
    description: req.body.description,
  });

  await db.createAuditEvent({
    organizationId: req.organizationId!,
    userId: req.user?.id || 'system',
    action: 'PROJECT_UPDATED',
    resourceType: 'PROJECT',
    resourceId: project.id,
    metadata: req.body,
  });

  return sendSuccess(res, { project: updated });
});

controlRouter.delete('/projects/:projectId', requireResourceAccess('project:delete'), async (req: Request, res: Response) => {
  const project = (req as any).project || (await db.getProjectById(req.params.projectId));
  if (!project || project.organizationId !== req.organizationId) {
    return sendError(res, 404, 'PROJECT_NOT_FOUND', 'Project not found.', req);
  }

  await db.deleteProject(project.id);

  await db.createAuditEvent({
    organizationId: req.organizationId!,
    userId: req.user?.id || 'system',
    action: 'PROJECT_DELETED',
    resourceType: 'PROJECT',
    resourceId: project.id,
  });

  return sendSuccess(res, { success: true });
});

// Environments subroutes
controlRouter.get('/projects/:projectId/environments', requireResourceAccess('environment:read'), async (req: Request, res: Response) => {
  const project = (req as any).project || (await db.getProjectById(req.params.projectId));
  if (!project || project.organizationId !== req.organizationId) {
    return sendError(res, 404, 'PROJECT_NOT_FOUND', 'Project not found.', req);
  }
  const environments = await db.getEnvironmentsByProject(project.id);
  return sendSuccess(res, { environments });
});

controlRouter.post('/projects/:projectId/environments', requireResourceAccess('environment:create'), async (req: Request, res: Response) => {
  const project = (req as any).project || (await db.getProjectById(req.params.projectId));
  if (!project || project.organizationId !== req.organizationId) {
    return sendError(res, 404, 'PROJECT_NOT_FOUND', 'Project not found.', req);
  }

  const { name, slug, type } = req.body;
  if (!name || !slug) return sendError(res, 400, 'INVALID_REQUEST', 'Name and slug are required.', req);

  const env = await db.createEnvironment({
    projectId: project.id,
    name: typeof name === 'string' ? name.replace(/&#x2F;/g, '/') : name,
    slug: slug.toLowerCase().replace(/[^a-z0-9_-]/g, '-'),
    type: type || 'development',
  });

  await db.createAuditEvent({
    organizationId: req.organizationId!,
    userId: req.user?.id || 'system',
    action: 'ENVIRONMENT_CREATED',
    resourceType: 'ENVIRONMENT',
    resourceId: env.id,
    metadata: { projectId: project.id, name, type },
  });

  return sendSuccess(res, { environment: env }, 201);
});

// ==========================================
// 3. TEAMS & COLLABORATION (Section 11)
// ==========================================

controlRouter.get('/teams', requireResourceAccess('teams:read'), async (req: Request, res: Response) => {
  const teams = await db.listTeams(req.organizationId!);
  return sendSuccess(res, { teams });
});

controlRouter.post('/teams', requireResourceAccess('teams:create'), async (req: Request, res: Response) => {
  const { name, description } = req.body;
  if (!name) return sendError(res, 400, 'INVALID_REQUEST', 'Team name is required.', req);

  const team = await db.createTeam({
    organizationId: req.organizationId!,
    name: typeof name === 'string' ? name.replace(/&#x2F;/g, '/') : name,
    description,
  });

  await db.createAuditEvent({
    organizationId: req.organizationId!,
    userId: req.user?.id || 'system',
    action: 'TEAM_CREATED',
    resourceType: 'TEAM',
    resourceId: team.id,
    metadata: { name },
  });

  return sendSuccess(res, { team }, 201);
});

controlRouter.get('/teams/:teamId', requireResourceAccess('teams:read'), async (req: Request, res: Response) => {
  const team = await db.getTeamById(req.params.teamId);
  if (!team || team.organizationId !== req.organizationId) {
    return sendError(res, 404, 'TEAM_NOT_FOUND', 'Team not found.', req);
  }
  const members = await db.listTeamMembers(team.id);
  return sendSuccess(res, { team: { ...team, members } });
});

controlRouter.patch('/teams/:teamId', requireResourceAccess('teams:update'), async (req: Request, res: Response) => {
  const team = await db.getTeamById(req.params.teamId);
  if (!team || team.organizationId !== req.organizationId) {
    return sendError(res, 404, 'TEAM_NOT_FOUND', 'Team not found.', req);
  }

  const updated = await db.updateTeam(team.id, req.body);
  return sendSuccess(res, { team: updated });
});

controlRouter.delete('/teams/:teamId', requireResourceAccess('teams:delete'), async (req: Request, res: Response) => {
  const team = await db.getTeamById(req.params.teamId);
  if (!team || team.organizationId !== req.organizationId) {
    return sendError(res, 404, 'TEAM_NOT_FOUND', 'Team not found.', req);
  }

  await db.deleteTeam(team.id);
  return sendSuccess(res, { success: true });
});

controlRouter.post('/teams/:teamId/members', requireResourceAccess('teams:update'), async (req: Request, res: Response) => {
  const team = await db.getTeamById(req.params.teamId);
  if (!team || team.organizationId !== req.organizationId) {
    return sendError(res, 404, 'TEAM_NOT_FOUND', 'Team not found.', req);
  }

  const { userId, role } = req.body;
  if (!userId) return sendError(res, 400, 'INVALID_REQUEST', 'userId is required.', req);

  const member = await db.addTeamMember({ teamId: team.id, userId, role });
  return sendSuccess(res, { member }, 201);
});

controlRouter.delete('/teams/:teamId/members/:userId', requireResourceAccess('teams:update'), async (req: Request, res: Response) => {
  const team = await db.getTeamById(req.params.teamId);
  if (!team || team.organizationId !== req.organizationId) {
    return sendError(res, 404, 'TEAM_NOT_FOUND', 'Team not found.', req);
  }

  await db.removeTeamMember(team.id, req.params.userId);
  return sendSuccess(res, { success: true });
});

// ==========================================
// 4. SERVICE IDENTITIES & API KEYS (Sections 12, 13)
// ==========================================

controlRouter.get('/service-identities', requireResourceAccess('api_key:read'), async (req: Request, res: Response) => {
  const identities = await db.listServiceIdentities(req.organizationId!);
  // Redact keyHash from responses
  const sanitized = identities.map(({ keyHash, ...rest }) => rest);
  return sendSuccess(res, { serviceIdentities: sanitized });
});

controlRouter.post('/service-identities', requireResourceAccess('api_key:create'), async (req: Request, res: Response) => {
  const { name, description, projectId, environmentId, scopes } = req.body;
  if (!name) return sendError(res, 400, 'INVALID_REQUEST', 'Name is required.', req);

  const secretRaw = `amsi_${crypto.randomBytes(32).toString('hex')}`;
  const keyHash = crypto.createHash('sha256').update(secretRaw).digest('hex');
  const prefix = secretRaw.substring(0, 10);

  const identity = await db.createServiceIdentity({
    organizationId: req.organizationId!,
    projectId,
    environmentId,
    name: typeof name === 'string' ? name.replace(/&#x2F;/g, '/') : name,
    description,
    scopes: scopes || ['crypto:execute', 'keys:read'],
    prefix,
    keyHash,
    createdBy: req.user?.id,
  });

  await db.createAuditEvent({
    organizationId: req.organizationId!,
    userId: req.user?.id || 'system',
    action: 'SERVICE_IDENTITY_CREATED',
    resourceType: 'SERVICE_IDENTITY',
    resourceId: identity.id,
    metadata: { name, prefix, scopes },
  });

  // Return secret ONLY ONCE upon creation
  return sendSuccess(
    res,
    {
      serviceIdentity: {
        id: identity.id,
        name: identity.name,
        prefix: identity.prefix,
        scopes: identity.scopes,
        status: identity.status,
        createdAt: identity.createdAt,
      },
      secretKey: secretRaw, // Plaintext secret displayed only once
    },
    201
  );
});

controlRouter.delete('/service-identities/:id', requireResourceAccess('api_key:revoke'), async (req: Request, res: Response) => {
  const si = await db.getServiceIdentityById(req.params.id);
  if (!si || si.organizationId !== req.organizationId) {
    return sendError(res, 404, 'SERVICE_IDENTITY_NOT_FOUND', 'Service identity not found.', req);
  }

  await db.revokeServiceIdentity(si.id);

  await db.createAuditEvent({
    organizationId: req.organizationId!,
    userId: req.user?.id || 'system',
    action: 'SERVICE_IDENTITY_REVOKED',
    resourceType: 'SERVICE_IDENTITY',
    resourceId: si.id,
  });

  return sendSuccess(res, { success: true });
});

// ==========================================
// 5. KEY MANAGEMENT CONTROL PLANE & POSTURE (Sections 14, 15)
// ==========================================

controlRouter.get('/keys', requireResourceAccess('key:read'), async (req: Request, res: Response) => {
  const keys = await db.listKeys({ organizationId: req.organizationId! });
  const now = Date.now();

  const enriched = keys.map((key) => {
    const ageDays = Math.floor((now - new Date(key.createdAt).getTime()) / (1000 * 60 * 60 * 24));
    const rotationRequired = key.status === 'ACTIVE' && ageDays > 90;
    const isPqc = (key.algorithm || '').toUpperCase().includes('ML-KEM') || (key.algorithm || '').toUpperCase().includes('ML-DSA');

    return {
      id: key.id,
      name: key.name,
      algorithm: key.algorithm,
      purpose: key.purpose,
      provider: key.provider,
      status: rotationRequired ? 'ROTATION_REQUIRED' : key.status,
      currentVersion: key.currentVersion,
      ageDays,
      isPqc,
      createdAt: key.createdAt,
      rotatedAt: key.rotatedAt,
    };
  });

  return sendSuccess(res, { keys: enriched });
});

controlRouter.post('/keys', requireResourceAccess('key:create'), async (req: Request, res: Response) => {
  const { name, algorithm, purpose, provider, projectId, environmentId } = req.body;
  if (!name || !algorithm) return sendError(res, 400, 'INVALID_REQUEST', 'Name and algorithm are required.', req);

  // Fallback to primary project/environment if not provided
  let pId = projectId;
  let eId = environmentId;
  if (!pId) {
    const projects = await db.getProjectsByOrg(req.organizationId!);
    if (projects.length > 0) pId = projects[0].id;
  }
  if (!eId && pId) {
    const envs = await db.getEnvironmentsByProject(pId);
    if (envs.length > 0) eId = envs[0].id;
  }

  const key = await db.createKey({
    organizationId: req.organizationId!,
    projectId: pId || 'default',
    environmentId: eId || 'default',
    name: typeof name === 'string' ? name.replace(/&#x2F;/g, '/') : name,
    algorithm,
    purpose: purpose || 'ENCRYPTION',
    provider: provider || 'LOCAL_DEV',
  });

  await db.createAuditEvent({
    organizationId: req.organizationId!,
    userId: req.user?.id || 'system',
    action: 'KEY_CREATED',
    resourceType: 'KEY',
    resourceId: key.id,
    metadata: { name, algorithm, purpose },
  });

  return sendSuccess(res, { key }, 201);
});

controlRouter.get('/keys/:keyId', requireResourceAccess('key:read'), async (req: Request, res: Response) => {
  const key = await db.findKeyById(req.params.keyId);
  if (!key || key.organizationId !== req.organizationId) {
    return sendError(res, 404, 'KEY_NOT_FOUND', 'Key not found.', req);
  }

  const versions = await db.listKeyVersions(key.id);

  // Guarantee ZERO private key material is returned in the response
  const sanitizedVersions = versions.map(({ keyMaterial, ...rest }: any) => rest);

  return sendSuccess(res, {
    key: {
      ...key,
      versions: sanitizedVersions,
    },
  });
});

controlRouter.post('/keys/:keyId/rotate', requireResourceAccess('key:rotate'), async (req: Request, res: Response) => {
  const key = await db.findKeyById(req.params.keyId);
  if (!key || key.organizationId !== req.organizationId) {
    return sendError(res, 404, 'KEY_NOT_FOUND', 'Key not found.', req);
  }

  const updated = await db.updateKey(key.id, {
    currentVersion: (key.currentVersion || 1) + 1,
    status: 'ACTIVE',
  });

  await db.createAuditEvent({
    organizationId: req.organizationId!,
    userId: req.user?.id || 'system',
    action: 'KEY_ROTATED',
    resourceType: 'KEY',
    resourceId: key.id,
    metadata: { newVersion: updated?.currentVersion },
  });

  return sendSuccess(res, { key: updated });
});

controlRouter.post('/keys/:keyId/disable', requireResourceAccess('key:disable'), async (req: Request, res: Response) => {
  const key = await db.findKeyById(req.params.keyId);
  if (!key || key.organizationId !== req.organizationId) {
    return sendError(res, 404, 'KEY_NOT_FOUND', 'Key not found.', req);
  }

  const updated = await db.updateKey(key.id, { status: 'DISABLED' });

  await db.createAuditEvent({
    organizationId: req.organizationId!,
    userId: req.user?.id || 'system',
    action: 'KEY_DISABLED',
    resourceType: 'KEY',
    resourceId: key.id,
  });

  return sendSuccess(res, { key: updated });
});

controlRouter.post('/keys/:keyId/enable', requireResourceAccess('key:enable'), async (req: Request, res: Response) => {
  const key = await db.findKeyById(req.params.keyId);
  if (!key || key.organizationId !== req.organizationId) {
    return sendError(res, 404, 'KEY_NOT_FOUND', 'Key not found.', req);
  }

  const updated = await db.updateKey(key.id, { status: 'ACTIVE' });

  await db.createAuditEvent({
    organizationId: req.organizationId!,
    userId: req.user?.id || 'system',
    action: 'KEY_ENABLED',
    resourceType: 'KEY',
    resourceId: key.id,
  });

  return sendSuccess(res, { key: updated });
});

controlRouter.delete('/keys/:keyId', requireResourceAccess('key:destroy'), async (req: Request, res: Response) => {
  const key = await db.findKeyById(req.params.keyId);
  if (!key || key.organizationId !== req.organizationId) {
    return sendError(res, 404, 'KEY_NOT_FOUND', 'Key not found.', req);
  }

  // Soft destroy key state
  await db.updateKey(key.id, { status: 'DESTROYED' });

  await db.createAuditEvent({
    organizationId: req.organizationId!,
    userId: req.user?.id || 'system',
    action: 'KEY_DESTROYED',
    resourceType: 'KEY',
    resourceId: key.id,
  });

  return sendSuccess(res, { success: true, status: 'DESTROYED' });
});

// ==========================================
// 6. PROVIDER MANAGEMENT & CAPABILITIES (Sections 16, 17, 18)
// ==========================================

controlRouter.get('/providers', requireResourceAccess('provider:read'), async (req: Request, res: Response) => {
  const customerProviders = await db.listCustomerProviders({ organizationId: req.organizationId! });

  // Default provider capability matrix
  const defaultProviders = [
    {
      id: 'prov_amaracus_local',
      name: 'Amaracus Default Cryptographic Runtime',
      providerType: 'AMARACUS_MANAGED',
      status: 'OPERATIONAL',
      isHsm: false,
      capabilities: {
        symmetricEncryption: true,
        asymmetricEncryption: true,
        digitalSignatures: true,
        pqcAlgorithms: true,
        keyDerivation: true,
        fipsCompliant: false,
      },
    },
    {
      id: 'prov_azure_managed_hsm',
      name: 'Azure Dedicated Managed HSM',
      providerType: 'AZURE_MANAGED_HSM',
      // The integration has not been tested against a live Managed HSM yet.
      status: 'PREVIEW',
      isHsm: true,
      capabilities: {
        symmetricEncryption: true,
        asymmetricEncryption: true,
        digitalSignatures: true,
        pqcAlgorithms: false,
        keyDerivation: true,
        // Microsoft's FIPS 140-3 Level 3 validation of the HSM hardware, not of AMARACUS.
        fipsCompliant: true,
      },
    },
  ];

  const customMapped = customerProviders.map((cp) => ({
    id: cp.id,
    name: cp.name,
    providerType: cp.providerType,
    status: cp.status || 'CONNECTED',
    isHsm: cp.isHsmBacked || false,
    vaultUrl: cp.vaultUrl,
    capabilities: cp.capabilities || {
      symmetricEncryption: true,
      asymmetricEncryption: true,
      digitalSignatures: true,
      pqcAlgorithms: false,
      fipsCompliant: false,
    },
  }));

  return sendSuccess(res, {
    providers: [...defaultProviders, ...customMapped],
  });
});

controlRouter.post('/providers/:providerId/test', requireResourceAccess('provider:read'), async (req: Request, res: Response) => {
  // No live probe happens here; say so instead of reporting a made-up healthy result.
  // Customer Azure vaults are tested for real via POST /v1/organizations/:orgId/byok/providers/test.
  return sendSuccess(res, {
    providerId: req.params.providerId,
    status: 'NOT_TESTED',
    latencyMs: null,
    verifiedAt: null,
    message:
      'Connection tests are not implemented for this endpoint. Use the BYOK provider test to check a customer Azure Key Vault.',
  });
});

// ==========================================
// 7. CRYPTOGRAPHIC POSTURE & DRIFT (Sections 22, 36)
// ==========================================

controlRouter.get('/posture', requireResourceAccess('posture:read'), async (req: Request, res: Response) => {
  const posture = await db.generateCryptographicPosture(req.organizationId!);
  return sendSuccess(res, { posture });
});

controlRouter.get('/drifts', requireResourceAccess('posture:read'), async (req: Request, res: Response) => {
  const drifts = await db.listDriftRecords(req.organizationId!);
  return sendSuccess(res, { drifts });
});

controlRouter.post('/drifts/:driftId/resolve', requireResourceAccess('security:update'), async (req: Request, res: Response) => {
  await db.resolveDrift(req.params.driftId);
  await db.createAuditEvent({
    organizationId: req.organizationId!,
    userId: req.user?.id || 'system',
    action: 'DRIFT_RESOLVED',
    resourceType: 'DRIFT',
    resourceId: req.params.driftId,
  });
  return sendSuccess(res, { success: true });
});

// ==========================================
// 8. OPERATION OBSERVABILITY (Section 27)
// ==========================================

controlRouter.get('/operations', requireResourceAccess('audit:read'), async (req: Request, res: Response) => {
  const { status, type, limit = 50, offset = 0 } = req.query;

  // Retrieve managed operations
  const result = await db.listManagedOperations({
    organizationId: req.organizationId!,
    status: status as string,
    type: type as string,
    limit: Number(limit),
    offset: Number(offset),
  });

  // Guarantee ZERO sensitive plaintext or raw payloads are exposed
  const sanitizedOperations = result.operations.map((op: any) => ({
    id: op.id,
    type: op.type || op.operationType,
    status: op.status,
    executionMode: op.executionMode,
    algorithm: op.algorithm,
    keyIdentifier: op.keyIdentifier || op.keyId,
    provider: op.provider || op.providerId,
    durationMs: op.durationMs,
    retryCount: op.retryCount,
    createdAt: op.createdAt,
    completedAt: op.completedAt,
    errorCode: op.errorCode || op.error?.code,
    errorMessage: op.errorMessage || op.error?.message,
  }));

  return sendSuccess(res, {
    operations: sanitizedOperations,
    total: result.total,
    limit: Number(limit),
    offset: Number(offset),
  });
});

// ==========================================
// 9. AUDIT LOG CONTROL PLANE (Section 28)
// ==========================================

controlRouter.get('/audit', requireResourceAccess('audit:read'), async (req: Request, res: Response) => {
  const { actorId, action, limit = 50, offset = 0 } = req.query;

  const result = await db.listAuditEvents({
    organizationId: req.organizationId!,
    actorId: actorId as string,
    action: action as string,
    limit: Number(limit),
    offset: Number(offset),
  });

  return sendSuccess(res, {
    auditEvents: result.events,
    total: result.total,
    limit: Number(limit),
    offset: Number(offset),
  });
});

// ==========================================
// 10. USAGE & COMMERCIAL VISIBILITY (Section 30)
// ==========================================

controlRouter.get('/usage', requireResourceAccess('billing:read'), async (req: Request, res: Response) => {
  const orgId = req.organizationId!;
  const currentUsage = await db.getCurrentBillingUsage(orgId);
  const subscription = await db.getBillingSubscription(orgId);

  return sendSuccess(res, {
    usage: {
      totalOperations: currentUsage?.operationCount || 0,
      includedUnits: currentUsage?.includedAllowance || 100000,
      additionalUnits: currentUsage?.overageCount || 0,
      periodStart: currentUsage?.periodStart || new Date().toISOString(),
      periodEnd: currentUsage?.periodEnd || new Date().toISOString(),
      plan: subscription?.plan || 'DEVELOPER',
    },
  });
});

// ==========================================
// 11. ENVIRONMENT PROMOTION (Section 35)
// ==========================================

controlRouter.post('/promotions', requireResourceAccess('policy:update'), async (req: Request, res: Response) => {
  const { sourceEnvId, targetEnvId, resourceType, resourceId } = req.body;
  if (!sourceEnvId || !targetEnvId || !resourceId) {
    return sendError(res, 400, 'INVALID_REQUEST', 'sourceEnvId, targetEnvId, and resourceId are required.', req);
  }

  // Validate source and target environments exist
  const sourceEnv = await db.getEnvironmentById(sourceEnvId);
  const targetEnv = await db.getEnvironmentById(targetEnvId);

  if (!sourceEnv || !targetEnv) {
    return sendError(res, 404, 'ENVIRONMENT_NOT_FOUND', 'Source or target environment not found.', req);
  }

  // Record audit log for configuration promotion
  await db.createAuditEvent({
    organizationId: req.organizationId!,
    userId: req.user?.id || 'system',
    action: 'CONFIGURATION_PROMOTED',
    resourceType: resourceType || 'POLICY',
    resourceId,
    metadata: {
      resourceType: resourceType || 'POLICY',
      sourceEnv: sourceEnv.name,
      targetEnv: targetEnv.name,
    },
  });

  return sendSuccess(res, {
    status: 'PROMOTED',
    resourceId,
    sourceEnvironment: sourceEnv.name,
    targetEnvironment: targetEnv.name,
    promotedAt: new Date().toISOString(),
  });
});

export { controlRouter };
export default controlRouter;
