export type Role =
  | 'OWNER'
  | 'ADMIN'
  | 'SECURITY_ADMIN'
  | 'DEVELOPER'
  | 'AUDITOR'
  | 'BILLING_ADMIN'
  | 'READ_ONLY'
  | 'MEMBER';

/**
 * The database stores roles lowercase (the Better Auth convention, shared with
 * the web app); the API works with the uppercase Role. Convert only at the
 * DataStore boundary, with these two functions.
 */
export function toDbRole(role: Role): string {
  return role.toLowerCase();
}

export function fromDbRole(value: string | null | undefined): Role {
  if (!value) return 'MEMBER';
  const upper = value.toUpperCase();
  // An unrecognised stored role gets the least privilege, not MEMBER.
  return upper in ROLE_PERMISSIONS ? (upper as Role) : 'READ_ONLY';
}

export type Permission =
  // Organization
  | 'org:read'
  | 'org:update'
  | 'org:delete'
  | 'organization:read'
  | 'organization:update'
  | 'organization:delete'
  | 'members:read'
  | 'members:invite'
  | 'members:remove'
  | 'members:update_role'
  | 'teams:read'
  | 'teams:create'
  | 'teams:update'
  | 'teams:delete'
  // Projects & Environments
  | 'projects:read'
  | 'projects:create'
  | 'projects:update'
  | 'projects:delete'
  | 'project:read'
  | 'project:create'
  | 'project:update'
  | 'project:delete'
  | 'environments:read'
  | 'environments:create'
  | 'environments:update'
  | 'environments:delete'
  | 'environment:read'
  | 'environment:create'
  | 'environment:update'
  | 'environment:delete'
  // Credentials & API Keys
  | 'credentials:read'
  | 'credentials:create'
  | 'credentials:revoke'
  | 'api_key:read'
  | 'api_key:create'
  | 'api_key:rotate'
  | 'api_key:revoke'
  // Audit & Observability
  | 'audit:read'
  | 'posture:read'
  | 'security:read'
  | 'security:update'
  // Cryptographic Operations & Data Plane
  | 'crypto:execute'
  | 'crypto:keys:generate'
  // Policies & Governance
  | 'crypto:policy:read'
  | 'crypto:policy:update'
  | 'policy:read'
  | 'policy:create'
  | 'policy:update'
  | 'policy:delete'
  | 'policy:simulate'
  // Key Management Control Plane & Lifecycle
  | 'keys:read'
  | 'keys:create'
  | 'keys:update'
  | 'keys:rotate'
  | 'keys:disable'
  | 'keys:enable'
  | 'keys:revoke'
  | 'keys:destroy'
  | 'key:read'
  | 'key:create'
  | 'key:rotate'
  | 'key:disable'
  | 'key:enable'
  | 'key:destroy'
  | 'keys:use:encrypt'
  | 'keys:use:decrypt'
  | 'keys:use:sign'
  | 'keys:use:verify'
  // Providers & HSM / BYOK
  | 'kms:providers:read'
  | 'provider:read'
  | 'provider:configure'
  | 'byok:providers:read'
  | 'byok:providers:create'
  | 'byok:providers:delete'
  | 'byok:keys:read'
  | 'byok:keys:register'
  | 'byok:keys:execute'
  // Billing
  | 'billing:read'
  | 'billing:update'
  | 'billing:manage'
  // PKI & Certificates
  | 'pki:ca:read'
  | 'pki:ca:create'
  | 'pki:ca:disable'
  | 'pki:cert:read'
  | 'pki:cert:issue'
  | 'pki:cert:renew'
  | 'pki:cert:revoke'
  | 'pki:cert:validate'
  | 'pki:csr:create'
  | 'pki:csr:read'
  | 'pki:csr:validate'
  | 'pki:crl:read'
  // Advanced Cryptography
  | 'zk:circuit:read'
  | 'zk:circuit:create'
  | 'zk:prove'
  | 'zk:verify'
  | 'fhe:key:read'
  | 'fhe:key:create'
  | 'fhe:encrypt'
  | 'fhe:decrypt'
  | 'fhe:evaluate'
  | 'mpc:session:read'
  | 'mpc:session:create'
  | 'mpc:session:join'
  | 'mpc:input'
  | 'mpc:execute'
  | 'threshold:key:read'
  | 'threshold:key:create'
  | 'threshold:session:read'
  | 'threshold:session:create'
  | 'threshold:approve'
  | 'threshold:execute'
  | 'advanced:providers:read';

// Normalize equivalent permission aliases
const PERMISSION_ALIASES: Record<string, string[]> = {
  'organization:read': ['org:read'],
  'org:read': ['organization:read'],
  'organization:update': ['org:update'],
  'org:update': ['organization:update'],
  'organization:delete': ['org:delete'],
  'org:delete': ['organization:delete'],
  'project:read': ['projects:read'],
  'projects:read': ['project:read'],
  'project:create': ['projects:create'],
  'projects:create': ['project:create'],
  'project:update': ['projects:update'],
  'projects:update': ['project:update'],
  'project:delete': ['projects:delete'],
  'projects:delete': ['project:delete'],
  'environment:read': ['environments:read'],
  'environments:read': ['environment:read'],
  'environment:create': ['environments:create'],
  'environments:create': ['environment:create'],
  'environment:update': ['environments:update'],
  'environments:update': ['environment:update'],
  'environment:delete': ['environments:delete'],
  'environments:delete': ['environment:delete'],
  'key:read': ['keys:read'],
  'keys:read': ['key:read'],
  'key:create': ['keys:create'],
  'keys:create': ['key:create'],
  'key:rotate': ['keys:rotate'],
  'keys:rotate': ['key:rotate'],
  'key:disable': ['keys:disable'],
  'keys:disable': ['key:disable'],
  'key:enable': ['keys:enable'],
  'keys:enable': ['key:enable'],
  'key:destroy': ['keys:destroy'],
  'keys:destroy': ['key:destroy'],
  'policy:read': ['crypto:policy:read'],
  'crypto:policy:read': ['policy:read'],
  'policy:update': ['crypto:policy:update'],
  'crypto:policy:update': ['policy:update'],
  'api_key:read': ['credentials:read'],
  'credentials:read': ['api_key:read'],
  'api_key:create': ['credentials:create'],
  'credentials:create': ['api_key:create'],
  'api_key:revoke': ['credentials:revoke'],
  'credentials:revoke': ['api_key:revoke'],
  'provider:read': ['kms:providers:read', 'byok:providers:read'],
  'kms:providers:read': ['provider:read'],
  'provider:configure': ['byok:providers:create', 'byok:providers:delete'],
};

const ALL_PERMISSIONS: Permission[] = [
  'org:read', 'org:update', 'org:delete', 'organization:read', 'organization:update', 'organization:delete',
  'members:read', 'members:invite', 'members:remove', 'members:update_role',
  'teams:read', 'teams:create', 'teams:update', 'teams:delete',
  'projects:read', 'projects:create', 'projects:update', 'projects:delete',
  'project:read', 'project:create', 'project:update', 'project:delete',
  'environments:read', 'environments:create', 'environments:update', 'environments:delete',
  'environment:read', 'environment:create', 'environment:update', 'environment:delete',
  'credentials:read', 'credentials:create', 'credentials:revoke',
  'api_key:read', 'api_key:create', 'api_key:rotate', 'api_key:revoke',
  'audit:read', 'posture:read', 'security:read', 'security:update',
  'crypto:execute', 'crypto:keys:generate',
  'crypto:policy:read', 'crypto:policy:update',
  'policy:read', 'policy:create', 'policy:update', 'policy:delete', 'policy:simulate',
  'keys:read', 'keys:create', 'keys:update', 'keys:rotate', 'keys:disable', 'keys:enable', 'keys:revoke', 'keys:destroy',
  'key:read', 'key:create', 'key:rotate', 'key:disable', 'key:enable', 'key:destroy',
  'keys:use:encrypt', 'keys:use:decrypt', 'keys:use:sign', 'keys:use:verify',
  'kms:providers:read', 'provider:read', 'provider:configure',
  'byok:providers:read', 'byok:providers:create', 'byok:providers:delete',
  'byok:keys:read', 'byok:keys:register', 'byok:keys:execute',
  'billing:read', 'billing:update', 'billing:manage',
  'pki:ca:read', 'pki:ca:create', 'pki:ca:disable',
  'pki:cert:read', 'pki:cert:issue', 'pki:cert:renew', 'pki:cert:revoke', 'pki:cert:validate',
  'pki:csr:create', 'pki:csr:read', 'pki:csr:validate', 'pki:crl:read',
  'zk:circuit:read', 'zk:circuit:create', 'zk:prove', 'zk:verify',
  'fhe:key:read', 'fhe:key:create', 'fhe:encrypt', 'fhe:decrypt', 'fhe:evaluate',
  'mpc:session:read', 'mpc:session:create', 'mpc:session:join', 'mpc:input', 'mpc:execute',
  'threshold:key:read', 'threshold:key:create', 'threshold:session:read', 'threshold:session:create',
  'threshold:approve', 'threshold:execute', 'advanced:providers:read',
];

const ROLE_PERMISSIONS: Record<Role, Set<Permission>> = {
  // 1. OWNER: Full unrestricted privileges across the organization
  OWNER: new Set<Permission>(ALL_PERMISSIONS),

  // 2. ADMIN: Full privileges except deleting organization
  ADMIN: new Set<Permission>(ALL_PERMISSIONS.filter((p) => p !== 'org:delete' && p !== 'organization:delete')),

  // 3. SECURITY_ADMIN: Policies, Key lifecycle, HSM/BYOK, Posture, Audit, PKI. CANNOT manage billing.
  SECURITY_ADMIN: new Set<Permission>([
    'org:read', 'organization:read', 'members:read',
    'teams:read',
    'projects:read', 'project:read',
    'environments:read', 'environment:read',
    'credentials:read', 'api_key:read', 'api_key:create', 'api_key:rotate', 'api_key:revoke',
    'audit:read', 'posture:read', 'security:read', 'security:update',
    'crypto:policy:read', 'crypto:policy:update',
    'policy:read', 'policy:create', 'policy:update', 'policy:delete', 'policy:simulate',
    'keys:read', 'keys:create', 'keys:update', 'keys:rotate', 'keys:disable', 'keys:enable', 'keys:revoke', 'keys:destroy',
    'key:read', 'key:create', 'key:rotate', 'key:disable', 'key:enable', 'key:destroy',
    'kms:providers:read', 'provider:read', 'provider:configure',
    'byok:providers:read', 'byok:providers:create', 'byok:providers:delete',
    'byok:keys:read', 'byok:keys:register',
    'pki:ca:read', 'pki:ca:create', 'pki:ca:disable',
    'pki:cert:read', 'pki:cert:issue', 'pki:cert:renew', 'pki:cert:revoke', 'pki:cert:validate',
    'pki:csr:create', 'pki:csr:read', 'pki:csr:validate', 'pki:crl:read',
    'zk:circuit:read', 'fhe:key:read', 'mpc:session:read', 'threshold:key:read', 'threshold:session:read',
    'advanced:providers:read',
  ]),

  // 4. DEVELOPER: Crypto execution, keys read/create/use, project/env read, credentials. CANNOT destroy keys or alter policies.
  DEVELOPER: new Set<Permission>([
    'org:read', 'organization:read', 'members:read',
    'teams:read',
    'projects:read', 'project:read',
    'environments:read', 'environment:read',
    'credentials:read', 'credentials:create', 'api_key:read', 'api_key:create',
    'audit:read',
    'crypto:execute', 'crypto:keys:generate',
    'crypto:policy:read', 'policy:read',
    'keys:read', 'keys:create', 'key:read', 'key:create',
    'keys:use:encrypt', 'keys:use:decrypt', 'keys:use:sign', 'keys:use:verify',
    'kms:providers:read', 'provider:read',
    'byok:providers:read', 'byok:keys:read', 'byok:keys:execute',
    'pki:ca:read', 'pki:cert:read', 'pki:cert:validate', 'pki:csr:create', 'pki:csr:read', 'pki:csr:validate', 'pki:crl:read',
    'zk:circuit:read', 'zk:prove', 'zk:verify',
    'fhe:key:read', 'fhe:encrypt', 'fhe:decrypt', 'fhe:evaluate',
    'mpc:session:read', 'mpc:session:join', 'mpc:input', 'mpc:execute',
    'threshold:key:read', 'threshold:session:read', 'threshold:approve', 'threshold:execute',
    'advanced:providers:read',
  ]),

  // 5. AUDITOR: Complete read-only view of posture, audit logs, policies, keys, and CBOM. CANNOT mutate or execute.
  AUDITOR: new Set<Permission>([
    'org:read', 'organization:read', 'members:read',
    'teams:read',
    'projects:read', 'project:read',
    'environments:read', 'environment:read',
    'credentials:read', 'api_key:read',
    'audit:read', 'posture:read', 'security:read',
    'crypto:policy:read', 'policy:read',
    'keys:read', 'key:read',
    'kms:providers:read', 'provider:read',
    'byok:providers:read', 'byok:keys:read',
    'billing:read',
    'pki:ca:read', 'pki:cert:read', 'pki:cert:validate', 'pki:csr:read', 'pki:crl:read',
    'zk:circuit:read', 'fhe:key:read', 'mpc:session:read', 'threshold:key:read', 'threshold:session:read',
    'advanced:providers:read',
  ]),

  // 6. BILLING_ADMIN: Commercial controls, usage analytics, payment settings. CANNOT modify crypto resources or operational audit logs.
  BILLING_ADMIN: new Set<Permission>([
    'org:read', 'organization:read',
    'billing:read', 'billing:update', 'billing:manage',
    'projects:read', 'project:read',
    'environments:read', 'environment:read',
  ]),

  // 7. READ_ONLY: Read-only access to basic project metadata. CANNOT mutate or execute.
  READ_ONLY: new Set<Permission>([
    'org:read', 'organization:read',
    'projects:read', 'project:read',
    'environments:read', 'environment:read',
    'keys:read', 'key:read',
    'crypto:policy:read', 'policy:read',
    'kms:providers:read', 'provider:read',
  ]),

  // Backward compatibility alias for legacy 'MEMBER' role
  MEMBER: new Set<Permission>([
    'org:read', 'organization:read', 'members:read',
    'projects:read', 'project:read',
    'environments:read', 'environment:read',
    'credentials:read', 'credentials:create', 'api_key:read', 'api_key:create',
    'audit:read',
    'crypto:execute', 'crypto:keys:generate',
    'crypto:policy:read', 'policy:read',
    'keys:read', 'keys:create', 'key:read', 'key:create',
    'keys:use:encrypt', 'keys:use:decrypt', 'keys:use:sign', 'keys:use:verify',
    'kms:providers:read', 'provider:read',
    'byok:providers:read', 'byok:keys:read', 'byok:keys:execute',
    'pki:ca:read', 'pki:cert:read', 'pki:cert:validate', 'pki:csr:create', 'pki:csr:read', 'pki:csr:validate', 'pki:crl:read',
    'zk:circuit:read', 'zk:prove', 'zk:verify',
    'fhe:key:read', 'fhe:encrypt', 'fhe:decrypt', 'fhe:evaluate',
    'mpc:session:read', 'mpc:session:join', 'mpc:input', 'mpc:execute',
    'threshold:key:read', 'threshold:session:read', 'threshold:approve', 'threshold:execute',
    'advanced:providers:read',
  ]),
};

export function hasPermission(role: Role | string, permission: Permission | string): boolean {
  const normalizedRole = (role || 'MEMBER').toUpperCase() as Role;
  const permissions = ROLE_PERMISSIONS[normalizedRole];
  if (!permissions) return false;

  // Direct check
  if (permissions.has(permission as Permission)) return true;

  // Check aliases
  const aliases = PERMISSION_ALIASES[permission];
  if (aliases) {
    for (const alias of aliases) {
      if (permissions.has(alias as Permission)) return true;
    }
  }

  return false;
}

export function canManageTargetRole(actorRole: Role | string, targetRole: Role | string): boolean {
  const normActor = (actorRole || '').toUpperCase();
  const normTarget = (targetRole || '').toUpperCase();

  if (normActor === 'OWNER') return true;
  if (normActor === 'ADMIN') {
    return ['SECURITY_ADMIN', 'DEVELOPER', 'AUDITOR', 'BILLING_ADMIN', 'READ_ONLY', 'MEMBER'].includes(normTarget);
  }
  if (normActor === 'SECURITY_ADMIN') {
    return ['AUDITOR', 'READ_ONLY'].includes(normTarget);
  }
  return false;
}

/**
 * Maps public API scopes (used by requireScope on /v1 routes) to the role
 * permission a signed-in user must hold. API keys are checked against their
 * stored scopes instead. Scopes missing from this map are denied to users.
 */
const SCOPE_PERMISSIONS: Record<string, Permission> = {
  // Read-only views: any organization member
  'compliance:read': 'org:read',
  'compliance:assess': 'org:read',
  'compliance:export': 'org:read',
  'intelligence:analyze': 'org:read',
  'intelligence:recommendations': 'org:read',
  'intelligence:optimize': 'org:read',
  'migrations:read': 'org:read',
  'os:read': 'org:read',
  'os:posture': 'org:read',
  'jobs:read': 'org:read',
  'usage:read': 'org:read',
  'pqc:read': 'org:read',
  'webhooks:read': 'security:read',

  // Credentials and keys
  'credentials:read': 'api_key:read',
  'credentials:manage': 'api_key:create',
  'keys:read': 'key:read',
  'keys:create': 'key:create',
  'keys:write': 'key:create',
  'keys:rotate': 'key:rotate',
  'keys:delete': 'key:destroy',

  // Cryptographic execution
  'crypto:encrypt': 'keys:use:encrypt',
  'crypto:decrypt': 'keys:use:decrypt',
  'crypto:sign': 'keys:use:sign',
  'crypto:verify': 'keys:use:verify',
  'crypto:hash': 'crypto:execute',
  'crypto:execute': 'crypto:execute',
  'pqc:execute': 'crypto:execute',
  'jobs:write': 'crypto:execute',

  // Security configuration changes
  'compliance:evidence': 'security:update',
  'compliance:exceptions': 'security:update',
  'intelligence:remediate': 'security:update',
  'migrations:plan': 'security:update',
  'migrations:execute': 'security:update',
  'migrations:approve': 'security:update',
  'os:workflows': 'security:update',
  'os:automation': 'security:update',
  'os:write': 'security:update',
  'webhooks:write': 'security:update',
};

export function roleHasScope(role: Role | string | undefined, scope: string): boolean {
  if (!role) return false;
  const permission = SCOPE_PERMISSIONS[scope];
  if (!permission) return false;
  return hasPermission(role, permission);
}
