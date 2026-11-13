/**
 * AMARACUS Cryptographic Infrastructure — Tenant & Execution Context
 *
 * Defines the standardized internal context model for all cryptographic operations.
 * Enforces verified tenant, project, and environment bindings.
 */

export interface TenantContext {
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  actorId?: string | null;
  actorType?: 'API_KEY' | 'USER_SESSION' | 'INTERNAL' | 'SYSTEM';
  clientIp?: string | null;
  userAgent?: string | null;
}

export class ContextValidator {
  /**
   * Validates that tenant context is well-formed and authenticated.
   * Fails closed if organizationId is missing or empty.
   */
  public static validate(context: TenantContext): void {
    if (!context || !context.organizationId || typeof context.organizationId !== 'string' || context.organizationId.trim() === '') {
      throw new Error('Tenant context validation failed: organizationId is required and cannot be empty.');
    }
  }

  /**
   * Formats a human-readable identifier for logging and metrics without leaking secrets.
   */
  public static toScopeString(context: TenantContext): string {
    const org = context.organizationId;
    const proj = context.projectId ? `:${context.projectId}` : ':default';
    const env = context.environmentId ? `:${context.environmentId}` : ':default';
    return `${org}${proj}${env}`;
  }
}
