import { sanitizePayload, escapeHtml } from './sanitize';
import { apiUrl } from './api-base';
import type {
  SelfHostStatus,
  SelfHostLicenseTexts,
  SelfHostLedgerPage,
  SelfHostLedgerVerification,
} from './selfhost';

export function resolveTargetUrl(endpoint: string): string {
  return apiUrl(endpoint);
}

class ApiClient {
  public getAuthToken(): string | null {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('amaracus_session_token');
    }
    return null;
  }

  public setAuthToken(token: string | null) {
    if (typeof window !== 'undefined') {
      if (token) {
        localStorage.setItem('amaracus_session_token', token);
      } else {
        localStorage.removeItem('amaracus_session_token');
      }
    }
  }

  private async request<T = any>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const token = this.getAuthToken();
    const headers: Record<string, string> = {
      ...((options.headers as Record<string, string>) || {}),
    };

    if (!(options.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const processedOptions = { ...options };
    if (typeof processedOptions.body === 'string') {
      try {
        const parsed = JSON.parse(processedOptions.body);
        processedOptions.body = JSON.stringify(sanitizePayload(parsed));
      } catch {
        // Not a JSON string, retain as is
      }
    }

    const targetUrl = resolveTargetUrl(endpoint);
    const res = await fetch(targetUrl, {
      ...processedOptions,
      headers,
      credentials: 'include',
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      const rawMessage = data?.error?.message || `HTTP Error ${res.status}: ${res.statusText}`;
      const message = escapeHtml(rawMessage);
      const error = new Error(message);
      (error as any).status = res.status;
      (error as any).code = data?.error?.code;
      (error as any).details = data?.error;
      throw error;
    }

    return data;
  }


  // --- SELF-HOSTED EDITION (the API answers 404 on /v1/selfhost/* when it is AMARACUS Cloud) ---
  public selfhost = {
    status: () => this.request<{ data: SelfHostStatus }>('/v1/selfhost/status'),
    licenses: () => this.request<{ data: SelfHostLicenseTexts }>('/v1/selfhost/licenses'),
    accept: (body: {
      acceptShield: true;
      acceptCommercialTerms: true;
      licensee: string;
      shieldSha256: string;
      commercialSha256: string;
    }) =>
      this.request<{ data: SelfHostStatus }>('/v1/selfhost/accept', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    addLicenseKey: (key: string) =>
      this.request<{ data: SelfHostStatus }>('/v1/selfhost/license-keys', {
        method: 'POST',
        body: JSON.stringify({ key }),
      }),
    ledger: (params?: { limit?: number; afterSeq?: number }) => {
      const query = new URLSearchParams();
      if (params?.limit !== undefined) query.set('limit', String(params.limit));
      if (params?.afterSeq !== undefined) query.set('afterSeq', String(params.afterSeq));
      const qs = query.toString();
      return this.request<{ data: SelfHostLedgerPage }>(`/v1/selfhost/ledger${qs ? `?${qs}` : ''}`);
    },
    verifyLedger: () => this.request<{ data: SelfHostLedgerVerification }>('/v1/selfhost/ledger/verify'),
    exportLedger: async (): Promise<Blob> => {
      const token = this.getAuthToken();
      const res = await fetch(resolveTargetUrl('/v1/selfhost/ledger/export'), {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        credentials: 'include',
      });
      if (!res.ok) throw new Error('Failed to download the usage ledger');
      return res.blob();
    },
  };

  // --- AUTH ---
  auth = {
    signup: (body: { email: string; password: string; name?: string; organizationName?: string; termsAccepted?: boolean; marketingOptIn?: boolean; ageAttested?: boolean }) =>
      this.request('/v1/auth/signup', {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    sendSignupOtp: (body: { email: string; password: string; name?: string; organizationName?: string; termsAccepted?: boolean; marketingOptIn?: boolean; ageAttested?: boolean }) =>
      this.request<{
        success: boolean;
        message: string;
        email: string;
        expiresInSeconds: number;
        simulated?: boolean;
        devOtp?: string;
      }>('/v1/auth/signup/send-otp', {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    verifySignupOtp: (body: { email: string; otp: string }) =>
      this.request<{
        user: { id: string; email: string; name?: string | null };
        session: { token: string; expiresAt: string };
        activeOrganization: { id: string; name: string; slug: string; role: 'OWNER' | 'ADMIN' | 'MEMBER' };
      }>('/v1/auth/signup/verify-otp', {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    resendSignupOtp: (body: { email: string }) =>
      this.request<{
        success: boolean;
        message: string;
        email: string;
        expiresInSeconds: number;
        simulated?: boolean;
        devOtp?: string;
      }>('/v1/auth/signup/resend-otp', {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    signin: (body: { email: string; password: string }) =>
      this.request('/v1/auth/signin', {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    forgotPassword: (body: { email: string }) =>
      this.request<{
        success: boolean;
        message: string;
        simulated?: boolean;
        resetLink?: string;
      }>('/v1/auth/forgot-password', {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    resetPassword: (body: { email: string; token?: string; code?: string; newPassword: string }) =>
      this.request<{
        success: boolean;
        message: string;
      }>('/v1/auth/reset-password', {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    signout: () =>
      this.request('/v1/auth/signout', {
        method: 'POST',
      }),

    me: () => this.request('/v1/auth/me'),
  };

  // --- MCP CONNECTIONS (the /connect consent page) ---
  mcpConnect = {
    request: (request: string) =>
      this.request<{
        data: {
          clientName: string;
          destination: string;
          isLocalApp: boolean;
          scopes: { id: string; label: string; preselected: boolean }[];
        };
      }>('/v1/mcp-connect/request', { method: 'POST', body: JSON.stringify({ request }) }),

    approve: (orgId: string, body: { request: string; environmentId: string; scopes: string[] }) =>
      this.request<{ data: { redirectTo: string } }>('/v1/mcp-connect/approve', {
        method: 'POST',
        headers: { 'X-Organization-Id': orgId },
        body: JSON.stringify(body),
      }),

    deny: (request: string) =>
      this.request<{ data: { redirectTo: string } }>('/v1/mcp-connect/deny', {
        method: 'POST',
        body: JSON.stringify({ request }),
      }),
  };

  // --- ORGANIZATIONS ---
  organizations = {
    list: () => this.request('/v1/organizations'),

    create: (body: { name: string }) =>
      this.request('/v1/organizations', {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    get: (orgId: string) => this.request(`/v1/organizations/${orgId}`),

    update: (orgId: string, body: { name: string }) =>
      this.request(`/v1/organizations/${orgId}`, {
        method: 'PATCH',
        body: JSON.stringify(body),
      }),

    switch: (orgId: string) =>
      this.request(`/v1/organizations/${orgId}/switch`, {
        method: 'POST',
      }),

    getMembers: (orgId: string) => this.request(`/v1/organizations/${orgId}/members`),

    inviteMember: (orgId: string, body: { email: string; role: string }) =>
      this.request(`/v1/organizations/${orgId}/members`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    removeMember: (orgId: string, memberId: string) =>
      this.request(`/v1/organizations/${orgId}/members/${memberId}`, {
        method: 'DELETE',
      }),
  };

  // --- PROJECTS ---
  projects = {
    list: (orgId: string) => this.request(`/v1/organizations/${orgId}/projects`),

    create: (orgId: string, body: { name: string; slug?: string; description?: string }) =>
      this.request(`/v1/organizations/${orgId}/projects`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    get: (orgId: string, projectId: string) =>
      this.request(`/v1/organizations/${orgId}/projects/${projectId}`),

    delete: (orgId: string, projectId: string) =>
      this.request(`/v1/organizations/${orgId}/projects/${projectId}`, {
        method: 'DELETE',
      }),
  };

  // --- ENVIRONMENTS ---
  environments = {
    list: (orgId: string, projectId: string) =>
      this.request(`/v1/organizations/${orgId}/projects/${projectId}/environments`),

    create: (orgId: string, projectId: string, body: { name: string; type: string }) =>
      this.request(`/v1/organizations/${orgId}/projects/${projectId}/environments`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    delete: (orgId: string, projectId: string, envId: string) =>
      this.request(`/v1/organizations/${orgId}/projects/${projectId}/environments/${envId}`, {
        method: 'DELETE',
      }),
  };

  // --- CREDENTIALS ---
  credentials = {
    list: (orgId: string) => this.request(`/v1/organizations/${orgId}/credentials`),

    create: (orgId: string, body: { name: string; environmentId: string; envType?: string }) =>
      this.request(`/v1/organizations/${orgId}/credentials`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    revoke: (orgId: string, credId: string) =>
      this.request(`/v1/organizations/${orgId}/credentials/${credId}`, {
        method: 'DELETE',
      }),
  };

  // --- AUDIT ---
  audit = {
    list: (orgId: string, limit = 50, options: { before?: string | null; action?: string } = {}) => {
      const params = new URLSearchParams({ limit: String(limit) });
      if (options.before) params.set('before', options.before);
      if (options.action) params.set('action', options.action);
      return this.request(`/v1/organizations/${orgId}/audit?${params.toString()}`);
    },
  };

  // --- POLICIES (stored, enforced cryptographic policies) ---
  policies = {
    list: (orgId: string) =>
      this.request<{ data: any[] }>(`/v1/policies?organizationId=${orgId}`, {
        headers: { 'x-organization-id': orgId },
      }),

    create: (
      orgId: string,
      body: { name: string; description?: string; rules: any[]; enforcementMode?: 'ENFORCE' | 'AUDIT' | 'DISABLED' }
    ) =>
      this.request<{ data: any }>(`/v1/policies?organizationId=${orgId}`, {
        method: 'POST',
        headers: { 'x-organization-id': orgId },
        body: JSON.stringify(body),
      }),
  };

  // --- CRYPTOGRAPHY ---
  crypto = {
    getAlgorithms: (orgId: string) =>
      this.request<{ data: any[]; meta: any }>(`/v1/organizations/${orgId}/crypto/algorithms`),

    getPolicies: (orgId: string) =>
      this.request<{ data: any[]; meta: any }>(`/v1/organizations/${orgId}/crypto/policies`),

    hash: (orgId: string, body: { algorithm: string; data: string; encoding?: string; outputEncoding?: string }) =>
      this.request<{ data: { algorithm: string; digest: string; encoding: string; byteLength: number }; meta: { executionTimingMs: number } }>(
        `/v1/organizations/${orgId}/crypto/hash`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    hmac: (orgId: string, body: { algorithm: string; key: string; data: string; outputEncoding?: string }) =>
      this.request<{ data: { algorithm: string; mac: string; encoding: string }; meta: { executionTimingMs: number } }>(
        `/v1/organizations/${orgId}/crypto/hmac`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    verifyHmac: (orgId: string, body: { algorithm: string; key: string; data: string; mac: string }) =>
      this.request<{ data: { valid: boolean; algorithm: string }; meta: { executionTimingMs: number } }>(
        `/v1/organizations/${orgId}/crypto/hmac/verify`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    encrypt: (orgId: string, body: { algorithm?: string; key: string; plaintext: string; keyEncoding?: string; aad?: string }) =>
      this.request<{ data: { v: number; alg: string; iv: string; ct: string; tag: string; aad?: string | null }; meta: { executionTimingMs: number } }>(
        `/v1/organizations/${orgId}/crypto/encrypt`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    decrypt: (orgId: string, body: { envelope: any; key: string; keyEncoding?: string }) =>
      this.request<{ data: { plaintext: string }; meta: { executionTimingMs: number } }>(
        `/v1/organizations/${orgId}/crypto/decrypt`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    generateKeypair: (orgId: string, algorithm: 'ED25519' | 'X25519') =>
      this.request<{ data: { algorithm: string; publicKey: string; privateKey: string; format: string }; meta: { executionTimingMs: number } }>(
        `/v1/organizations/${orgId}/crypto/keypair`,
        { method: 'POST', body: JSON.stringify({ algorithm }) }
      ),

    sign: (orgId: string, body: { algorithm?: string; privateKey: string; message: string; signatureEncoding?: string }) =>
      this.request<{ data: { algorithm: string; signature: string; encoding: string }; meta: { executionTimingMs: number } }>(
        `/v1/organizations/${orgId}/crypto/sign`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    verify: (orgId: string, body: { algorithm?: string; publicKey: string; message: string; signature: string }) =>
      this.request<{ data: { valid: boolean; algorithm: string }; meta: { executionTimingMs: number } }>(
        `/v1/organizations/${orgId}/crypto/verify`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    keyAgreement: (orgId: string, body: { algorithm?: string; privateKey: string; publicKey: string }) =>
      this.request<{ data: { algorithm: string; sharedSecret: string; encoding: string }; meta: { executionTimingMs: number } }>(
        `/v1/organizations/${orgId}/crypto/key-agreement`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    random: (orgId: string, length = 32, encoding = 'hex') =>
      this.request<{ data: { random: string; length: number }; meta: any }>(
        `/v1/organizations/${orgId}/crypto/random`,
        { method: 'POST', body: JSON.stringify({ length, encoding }) }
      ),
  };

  // --- POST-QUANTUM CRYPTOGRAPHY (PHASE 6) ---
  pqc = {
    getAlgorithms: (orgId: string) =>
      this.request<{ data: { pqc: any[]; hybrid: any[] }; meta: any }>(
        `/v1/organizations/${orgId}/crypto/pqc/algorithms`
      ),

    selectAlgorithm: (orgId: string, body: {
      operation: 'key_encapsulation' | 'digital_signature' | 'key_agreement';
      policy?: string;
      minSecurityLevel?: number;
      preferHybrid?: boolean;
    }) =>
      this.request<{ data: any }>(
        `/v1/organizations/${orgId}/crypto/pqc/agility/select`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    getMigrationAdvice: (orgId: string, algorithm: string) =>
      this.request<{ data: any }>(
        `/v1/organizations/${orgId}/crypto/pqc/agility/migration-advice`,
        { method: 'POST', body: JSON.stringify({ algorithm }) }
      ),

    // ML-KEM (FIPS 203)
    kemKeygen: (orgId: string, body?: { algorithm?: string; encoding?: string; policy?: string }) =>
      this.request<{ data: any; meta: any }>(
        `/v1/organizations/${orgId}/crypto/kem/keygen`,
        { method: 'POST', body: JSON.stringify(body || {}) }
      ),

    kemEncapsulate: (orgId: string, body: {
      algorithm?: string;
      publicKey: string;
      publicKeyEncoding?: string;
      outputEncoding?: string;
      policy?: string;
    }) =>
      this.request<{ data: any; meta: any }>(
        `/v1/organizations/${orgId}/crypto/kem/encapsulate`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    kemDecapsulate: (orgId: string, body: {
      algorithm?: string;
      privateKey: string;
      ciphertext: string;
      privateKeyEncoding?: string;
      ciphertextEncoding?: string;
      outputEncoding?: string;
      policy?: string;
    }) =>
      this.request<{ data: any; meta: any }>(
        `/v1/organizations/${orgId}/crypto/kem/decapsulate`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    // ML-DSA (FIPS 204)
    signatureKeygen: (orgId: string, body?: { algorithm?: string; encoding?: string; policy?: string }) =>
      this.request<{ data: any; meta: any }>(
        `/v1/organizations/${orgId}/crypto/signature/pqc-keygen`,
        { method: 'POST', body: JSON.stringify(body || {}) }
      ),

    signatureSign: (orgId: string, body: {
      algorithm?: string;
      privateKey: string;
      message: string;
      privateKeyEncoding?: string;
      messageEncoding?: string;
      signatureEncoding?: string;
      outputEncoding?: string;
      context?: string;
      policy?: string;
    }) =>
      this.request<{ data: any; meta: any }>(
        `/v1/organizations/${orgId}/crypto/signature/pqc-sign`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    signatureVerify: (orgId: string, body: {
      algorithm?: string;
      publicKey: string;
      message: string;
      signature: string;
      publicKeyEncoding?: string;
      messageEncoding?: string;
      signatureEncoding?: string;
      context?: string;
      policy?: string;
    }) =>
      this.request<{ data: { valid: boolean; algorithm: string }; meta: any }>(
        `/v1/organizations/${orgId}/crypto/signature/pqc-verify`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    // Hybrid Key Exchange (X25519 + ML-KEM-768)
    hybridKeygen: (orgId: string, body?: { algorithm?: string; encoding?: string; policy?: string }) =>
      this.request<{ data: any; meta: any }>(
        `/v1/organizations/${orgId}/crypto/hybrid/keygen`,
        { method: 'POST', body: JSON.stringify(body || {}) }
      ),

    hybridEncapsulate: (orgId: string, body: {
      algorithm?: string;
      publicKey: { x25519PublicKey: string; mlkemPublicKey: string };
      encoding?: string;
      outputEncoding?: string;
      policy?: string;
    }) =>
      this.request<{ data: any; meta: any }>(
        `/v1/organizations/${orgId}/crypto/hybrid/encapsulate`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    hybridDecapsulate: (orgId: string, body: {
      algorithm?: string;
      privateKey: { x25519PrivateKey: string; mlkemPrivateKey: string };
      ciphertext: { ephemeralX25519PublicKey: string; mlkemCiphertext: string } | string;
      encoding?: string;
      outputEncoding?: string;
      policy?: string;
    }) =>
      this.request<{ data: any; meta: any }>(
        `/v1/organizations/${orgId}/crypto/hybrid/decapsulate`,
        { method: 'POST', body: JSON.stringify(body) }
      ),
  };

  // --- KEYS (PHASE 5) ---
  keys = {
    getProviders: (orgId: string) =>
      this.request<{ data: any[]; meta: any }>(`/v1/organizations/${orgId}/keys/providers`),

    list: (orgId: string, params?: { projectId?: string; environmentId?: string; status?: string; search?: string }) => {
      const query = new URLSearchParams();
      if (params?.projectId) query.set('projectId', params.projectId);
      if (params?.environmentId) query.set('environmentId', params.environmentId);
      if (params?.status) query.set('status', params.status);
      if (params?.search) query.set('search', params.search);
      const qs = query.toString() ? `?${query.toString()}` : '';
      return this.request<{ data: any[]; meta: { count: number } }>(`/v1/organizations/${orgId}/keys${qs}`);
    },

    create: (orgId: string, body: {
      name: string;
      description?: string;
      projectId: string;
      environmentId: string;
      algorithm: string;
      purpose: string;
      provider: string;
      metadata?: any;
    }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/keys`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    get: (orgId: string, keyId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/keys/${keyId}`),

    listVersions: (orgId: string, keyId: string) =>
      this.request<{ data: any[]; meta: { count: number } }>(`/v1/organizations/${orgId}/keys/${keyId}/versions`),

    getVersion: (orgId: string, keyId: string, version: number) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/keys/${keyId}/versions/${version}`),

    rotate: (orgId: string, keyId: string) =>
      this.request<{ data: { key: any; newVersion: any } }>(`/v1/organizations/${orgId}/keys/${keyId}/rotate`, {
        method: 'POST',
      }),

    disable: (orgId: string, keyId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/keys/${keyId}/disable`, {
        method: 'POST',
      }),

    enable: (orgId: string, keyId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/keys/${keyId}/enable`, {
        method: 'POST',
      }),

    revoke: (orgId: string, keyId: string, reason?: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/keys/${keyId}/revoke`, {
        method: 'POST',
        body: JSON.stringify({ reason }),
      }),

    scheduleDeletion: (orgId: string, keyId: string, pendingDays: number = 7) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/keys/${keyId}/schedule-deletion`, {
        method: 'POST',
        body: JSON.stringify({ pendingDays }),
      }),

    cancelDeletion: (orgId: string, keyId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/keys/${keyId}/cancel-deletion`, {
        method: 'POST',
      }),

    recover: (orgId: string, keyId: string) =>
      this.request<{ data: any; message: string }>(`/v1/organizations/${orgId}/keys/${keyId}/recover`, {
        method: 'POST',
      }),

    purge: (orgId: string, keyId: string) =>
      this.request<{ data: any; message: string }>(`/v1/organizations/${orgId}/keys/${keyId}/purge`, {
        method: 'POST',
      }),

    destroy: (orgId: string, keyId: string) =>
      this.request<{ data: any; message: string }>(`/v1/organizations/${orgId}/keys/${keyId}`, {
        method: 'DELETE',
      }),

    encrypt: (orgId: string, keyId: string, body: { plaintext: string; aad?: string; version?: number }) =>
      this.request<{ data: { envelope: any; keyId: string; version: number; algorithm: string } }>(
        `/v1/organizations/${orgId}/keys/${keyId}/encrypt`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    decrypt: (orgId: string, keyId: string, body: { envelope: any; version?: number }) =>
      this.request<{ data: { plaintext: string; keyId: string; version: number } }>(
        `/v1/organizations/${orgId}/keys/${keyId}/decrypt`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    sign: (orgId: string, keyId: string, body: { data: string; version?: number }) =>
      this.request<{ data: { signature: string; encoding: string; keyId: string; version: number; algorithm: string } }>(
        `/v1/organizations/${orgId}/keys/${keyId}/sign`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    verify: (orgId: string, keyId: string, body: { data: string; signature: string; version?: number; encoding?: string }) =>
      this.request<{ data: { isValid: boolean; keyId: string; version: number; algorithm: string } }>(
        `/v1/organizations/${orgId}/keys/${keyId}/verify`,
        { method: 'POST', body: JSON.stringify(body) }
      ),
  };

  // --- BYOK / CUSTOMER HSM (PHASE 5.2) ---
  byok = {
    testConnection: (orgId: string, body: {
      providerType?: string;
      vaultUrl?: string;
      hsmUrl?: string;
      authType?: string;
      tenantId?: string;
      clientId?: string;
      clientSecret?: string;
    }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/byok/providers/test`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    createProvider: (orgId: string, body: {
      name: string;
      projectId: string;
      environmentId: string;
      providerType: string;
      vaultUrl: string;
      hsmUrl?: string;
      authType?: string;
      tenantId?: string;
      clientId?: string;
      clientSecret?: string;
    }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/byok/providers`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    listProviders: (orgId: string, params?: { projectId?: string; environmentId?: string }) => {
      const query = new URLSearchParams();
      if (params?.projectId) query.set('projectId', params.projectId);
      if (params?.environmentId) query.set('environmentId', params.environmentId);
      const qs = query.toString() ? `?${query.toString()}` : '';
      return this.request<{ data: any[] }>(`/v1/organizations/${orgId}/byok/providers${qs}`);
    },

    getProvider: (orgId: string, providerId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/byok/providers/${providerId}`),

    disconnectProvider: (orgId: string, providerId: string) =>
      this.request<{ data: { success: boolean; message: string } }>(
        `/v1/organizations/${orgId}/byok/providers/${providerId}/disconnect`,
        { method: 'POST' }
      ),

    discoverKeys: (orgId: string, providerId: string) =>
      this.request<{ data: any[] }>(`/v1/organizations/${orgId}/byok/providers/${providerId}/discover`),

    registerKey: (
      orgId: string,
      providerId: string,
      payload: string | { keyIdentifier: string; purpose?: string; keyType?: string; algorithm?: string; displayName?: string }
    ) => {
      const body = typeof payload === 'string' ? { keyIdentifier: payload } : payload;
      return this.request<{ data: any }>(`/v1/organizations/${orgId}/byok/providers/${providerId}/keys`, {
        method: 'POST',
        body: JSON.stringify(body),
      });
    },

    listRegisteredKeys: (orgId: string, providerId: string) =>
      this.request<{ data: any[] }>(`/v1/organizations/${orgId}/byok/providers/${providerId}/keys`),

    getRegisteredKey: (orgId: string, providerId: string, keyId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/byok/providers/${providerId}/keys/${keyId}`),

    refreshKey: (orgId: string, providerId: string, keyId: string) =>
      this.request<{ data: any }>(
        `/v1/organizations/${orgId}/byok/providers/${providerId}/keys/${keyId}/refresh`,
        { method: 'POST' }
      ),

    encrypt: (orgId: string, providerId: string, keyId: string, body: { plaintext: string; aad?: string }) =>
      this.request<{ data: { envelope: any; keyIdentifier: string; version: string; ownershipType: string } }>(
        `/v1/organizations/${orgId}/byok/providers/${providerId}/keys/${keyId}/encrypt`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    decrypt: (orgId: string, providerId: string, keyId: string, body: { envelope: any }) =>
      this.request<{ data: { plaintext: string } }>(
        `/v1/organizations/${orgId}/byok/providers/${providerId}/keys/${keyId}/decrypt`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    sign: (orgId: string, providerId: string, keyId: string, body: { data: string }) =>
      this.request<{ data: { signature: string; keyIdentifier: string; version: string; ownershipType: string } }>(
        `/v1/organizations/${orgId}/byok/providers/${providerId}/keys/${keyId}/sign`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    getCapabilities: (orgId: string, providerId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/byok/providers/${providerId}/capabilities`),

    executeOperation: (
      orgId: string,
      providerId: string,
      keyId: string,
      body: {
        operation: 'ENCRYPT' | 'DECRYPT' | 'SIGN' | 'VERIFY' | 'WRAP' | 'UNWRAP';
        plaintext?: string;
        envelope?: any;
        data?: string;
        signature?: string;
        aad?: string;
        version?: string;
      }
    ) =>
      this.request<{ data: any }>(
        `/v1/organizations/${orgId}/byok/providers/${providerId}/keys/${keyId}/operations`,
        { method: 'POST', body: JSON.stringify(body) }
      ),

    getOnboardingStatus: (orgId: string, providerId: string) =>
      this.request<{
        providerId: string;
        state: string;
        progress: {
          configuration: string;
          connection: string;
          capabilities: string;
          keyRegistration: string;
        };
        nextAction: string;
        canProceed: boolean;
      }>(`/v1/organizations/${orgId}/byok/providers/${providerId}/onboarding-status`),
  };

  // --- PKI & CERTIFICATE MANAGEMENT ---
  pki = {
    // Certificate Authorities
    listAuthorities: (orgId: string, params?: { projectId?: string; environmentId?: string; status?: string }) => {
      const q = new URLSearchParams();
      if (params?.projectId) q.append('projectId', params.projectId);
      if (params?.environmentId) q.append('environmentId', params.environmentId);
      if (params?.status) q.append('status', params.status);
      const queryStr = q.toString() ? `?${q.toString()}` : '';
      return this.request<{ data: any[] }>(`/v1/organizations/${orgId}/pki/certificate-authorities${queryStr}`);
    },

    getAuthority: (orgId: string, caId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/certificate-authorities/${caId}`),

    createAuthority: (
      orgId: string,
      body: {
        name: string;
        description?: string;
        projectId: string;
        environmentId: string;
        type: 'ROOT_CA' | 'INTERMEDIATE_CA';
        subject: string;
        parentAuthorityId?: string;
        keyAlgorithm?: string;
        validityDays?: number;
        pathLenConstraint?: number;
        crlDistributionPoint?: string;
        ocspUrl?: string;
      }
    ) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/certificate-authorities`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    getCrl: (orgId: string, caId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/certificate-authorities/${caId}/crl`),

    generateCrl: (orgId: string, caId: string, body?: { nextUpdateDays?: number }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/certificate-authorities/${caId}/crl`, {
        method: 'POST',
        body: JSON.stringify(body || {}),
      }),

    // Certificates
    listCertificates: (
      orgId: string,
      params?: { projectId?: string; environmentId?: string; status?: string; authorityId?: string }
    ) => {
      const q = new URLSearchParams();
      if (params?.projectId) q.append('projectId', params.projectId);
      if (params?.environmentId) q.append('environmentId', params.environmentId);
      if (params?.status) q.append('status', params.status);
      if (params?.authorityId) q.append('authorityId', params.authorityId);
      const queryStr = q.toString() ? `?${q.toString()}` : '';
      return this.request<{ data: any[] }>(`/v1/organizations/${orgId}/pki/certificates${queryStr}`);
    },

    getCertificate: (orgId: string, certId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/certificates/${certId}`),

    issueCertificate: (
      orgId: string,
      body: {
        name: string;
        authorityId: string;
        projectId: string;
        environmentId: string;
        certificateType: string;
        subject: string;
        keyAlgorithm?: string;
        validityDays?: number;
        san?: { dns?: string[]; ips?: string[]; emails?: string[]; uris?: string[] };
        keyUsage?: string[];
        extendedKeyUsage?: string[];
      }
    ) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/certificates`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    validateCertificate: (
      orgId: string,
      certId: string,
      body?: { checkRevocation?: boolean; checkExpiry?: boolean }
    ) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/certificates/${certId}/validate`, {
        method: 'POST',
        body: JSON.stringify(body || {}),
      }),

    renewCertificate: (
      orgId: string,
      certId: string,
      body?: { reuseExistingKey?: boolean; validityDays?: number }
    ) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/certificates/${certId}/renew`, {
        method: 'POST',
        body: JSON.stringify(body || {}),
      }),

    revokeCertificate: (
      orgId: string,
      certId: string,
      body: { reason: string; invalidityDate?: string; comment?: string }
    ) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/certificates/${certId}/revoke`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    getOcsp: (orgId: string, certId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/ocsp/${certId}`),

    // CSRs
    listCsrs: (orgId: string, params?: { projectId?: string; environmentId?: string; status?: string }) => {
      const q = new URLSearchParams();
      if (params?.projectId) q.append('projectId', params.projectId);
      if (params?.environmentId) q.append('environmentId', params.environmentId);
      if (params?.status) q.append('status', params.status);
      const queryStr = q.toString() ? `?${q.toString()}` : '';
      return this.request<{ data: any[] }>(`/v1/organizations/${orgId}/pki/csrs${queryStr}`);
    },

    getCsr: (orgId: string, csrId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/csrs/${csrId}`),

    createCsr: (
      orgId: string,
      body: {
        projectId: string;
        environmentId: string;
        subject: string;
        keyAlgorithm?: string;
        san?: { dns?: string[]; ips?: string[]; emails?: string[]; uris?: string[] };
        keyUsage?: string[];
        extendedKeyUsage?: string[];
      }
    ) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/csrs`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    validateCsr: (orgId: string, body: { csrPem: string }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/csrs/validate`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    signCsr: (
      orgId: string,
      csrId: string,
      body: {
        authorityId: string;
        certificateType?: string;
        validityDays?: number;
      }
    ) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/pki/csrs/${csrId}/sign`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
  };

  // --- CRYPTO INTELLIGENCE & CBOM (PHASE 8) ---
  intelligence = {
    scan: (
      orgId: string,
      body?: {
        sourceFiles?: Array<{ path: string; content: string }>;
        policyName?: string;
      }
    ) =>
      this.request<{ success: boolean; message: string; scan: any }>(
        `/v1/organizations/${orgId}/intelligence/scan`,
        {
          method: 'POST',
          body: JSON.stringify(body || {}),
        }
      ),

    getInventory: (orgId: string) =>
      this.request<{
        success: boolean;
        data: {
          totalAssets: number;
          assetsByType: Record<string, number>;
          openFindingsCount: number;
          totalFindingsCount: number;
          findingsBySeverity: Record<string, number>;
          quantumStatusSummary: Record<string, number>;
          latestScanDate: string | null;
        };
      }>(`/v1/organizations/${orgId}/intelligence/inventory`),

    listAssets: (
      orgId: string,
      params?: { assetType?: string; status?: string; algorithm?: string; quantumStatus?: string }
    ) => {
      const q = new URLSearchParams();
      if (params?.assetType) q.append('assetType', params.assetType);
      if (params?.status) q.append('status', params.status);
      if (params?.algorithm) q.append('algorithm', params.algorithm);
      if (params?.quantumStatus) q.append('quantumStatus', params.quantumStatus);
      const queryStr = q.toString() ? `?${q.toString()}` : '';
      return this.request<{ success: boolean; data: any[] }>(
        `/v1/organizations/${orgId}/intelligence/assets${queryStr}`
      );
    },

    getAsset: (orgId: string, id: string) =>
      this.request<{ success: boolean; data: any }>(
        `/v1/organizations/${orgId}/intelligence/assets/${id}`
      ),

    listRelationships: (orgId: string) =>
      this.request<{ success: boolean; data: any[] }>(
        `/v1/organizations/${orgId}/intelligence/relationships`
      ),

    getImpact: (orgId: string, assetId: string) =>
      this.request<{ success: boolean; data: any }>(
        `/v1/organizations/${orgId}/intelligence/impact/${assetId}`
      ),

    listFindings: (
      orgId: string,
      params?: { severity?: string; status?: string; category?: string }
    ) => {
      const q = new URLSearchParams();
      if (params?.severity) q.append('severity', params.severity);
      if (params?.status) q.append('status', params.status);
      if (params?.category) q.append('category', params.category);
      const queryStr = q.toString() ? `?${q.toString()}` : '';
      return this.request<{ success: boolean; data: any[] }>(
        `/v1/organizations/${orgId}/intelligence/findings${queryStr}`
      );
    },

    updateFinding: (
      orgId: string,
      id: string,
      body: { status: string; resolutionComment?: string }
    ) =>
      this.request<{ success: boolean; data: any }>(
        `/v1/organizations/${orgId}/intelligence/findings/${id}`,
        {
          method: 'PATCH',
          body: JSON.stringify(body),
        }
      ),

    getCbom: (orgId: string, environment?: string) => {
      const queryStr = environment ? `?environment=${encodeURIComponent(environment)}` : '';
      return this.request<any>(`/v1/organizations/${orgId}/intelligence/cbom${queryStr}`);
    },

    exportCbom: (orgId: string, environment?: string) => {
      const queryStr = environment ? `?environment=${encodeURIComponent(environment)}` : '';
      return this.request<any>(`/v1/organizations/${orgId}/intelligence/cbom/export${queryStr}`, {
        method: 'POST',
      });
    },

    listMigrations: (orgId: string) =>
      this.request<{ success: boolean; data: any[] }>(
        `/v1/organizations/${orgId}/intelligence/migrations`
      ),

    createMigration: (
      orgId: string,
      body: {
        name: string;
        description?: string;
        affectedAssetIds?: string[];
        currentAlgorithm: string;
        targetAlgorithm?: string;
        migrationStrategy?: string;
        environmentId?: string;
      }
    ) =>
      this.request<{ success: boolean; data: any }>(
        `/v1/organizations/${orgId}/intelligence/migrations`,
        {
          method: 'POST',
          body: JSON.stringify(body),
        }
      ),

    getMigration: (orgId: string, id: string) =>
      this.request<{ success: boolean; data: any }>(
        `/v1/organizations/${orgId}/intelligence/migrations/${id}`
      ),

    updateMigration: (orgId: string, id: string, body: any) =>
      this.request<{ success: boolean; data: any }>(
        `/v1/organizations/${orgId}/intelligence/migrations/${id}`,
        {
          method: 'PATCH',
          body: JSON.stringify(body),
        }
      ),

    listSnapshots: (orgId: string) =>
      this.request<{ success: boolean; data: any[] }>(
        `/v1/organizations/${orgId}/intelligence/snapshots`
      ),

    getSnapshotsDiff: (orgId: string) =>
      this.request<{ success: boolean; latestSnapshotId?: string; previousSnapshotId?: string; drift?: any; message?: string }>(
        `/v1/organizations/${orgId}/intelligence/snapshots/diff`
      ),
  };

  // --- PHASE 9: ADVANCED CRYPTOGRAPHY ---
  advanced = {
    getProviders: (orgId: string) =>
      this.request<{ data: any[] }>(`/v1/organizations/${orgId}/advanced/providers`),

    // ZK
    listCircuits: (orgId: string) =>
      this.request<{ data: any[] }>(`/v1/organizations/${orgId}/advanced/zk/circuits`),

    createCircuit: (orgId: string, body: any) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/zk/circuits`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    getCircuit: (orgId: string, id: string, version?: string) =>
      this.request<{ data: any }>(
        `/v1/organizations/${orgId}/advanced/zk/circuits/${id}${version ? `?version=${version}` : ''}`
      ),

    prove: (orgId: string, body: { circuitId: string; version?: string; statement: any; witness: any }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/zk/prove`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    verify: (orgId: string, body: { circuitId: string; version?: string; statement: any; proof: any }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/zk/verify`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    // FHE
    getLimits: (orgId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/fhe/limits`),

    listFheKeys: (orgId: string) =>
      this.request<{ data: any[] }>(`/v1/organizations/${orgId}/advanced/fhe/keys`),

    generateFheKey: (orgId: string, body?: { scheme?: string; polyModulusDegree?: number }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/fhe/keygen`, {
        method: 'POST',
        body: JSON.stringify(body || {}),
      }),

    encryptFhe: (orgId: string, body: { keyId: string; value: number }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/fhe/encrypt`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    decryptFhe: (orgId: string, body: { keyId: string; ciphertextBase64: string }) =>
      this.request<{ data: { value: number } }>(`/v1/organizations/${orgId}/advanced/fhe/decrypt`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    evaluateFhe: (orgId: string, body: { keyId: string; operation: string; ciphertexts: string[] }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/fhe/evaluate`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    // MPC
    listMpcSessions: (orgId: string) =>
      this.request<{ data: any[] }>(`/v1/organizations/${orgId}/advanced/mpc/sessions`),

    createMpcSession: (orgId: string, body: { title?: string; operation?: string; requiredParties?: number; threshold?: number }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/mpc/sessions`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    getMpcSession: (orgId: string, id: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/mpc/sessions/${id}`),

    joinMpcSession: (orgId: string, id: string, body: { partyId: string; name?: string; role?: string }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/mpc/sessions/${id}/join`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    submitMpcInput: (orgId: string, id: string, body: { partyId: string; input: number }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/mpc/sessions/${id}/input`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    executeMpcRound: (orgId: string, id: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/mpc/sessions/${id}/execute`, {
        method: 'POST',
      }),

    getMpcResult: (orgId: string, id: string) =>
      this.request<{ data: { result: number; status: string } }>(`/v1/organizations/${orgId}/advanced/mpc/sessions/${id}/result`),

    // Threshold
    listThresholdKeys: (orgId: string) =>
      this.request<{ data: any[] }>(`/v1/organizations/${orgId}/advanced/threshold/keys`),

    createThresholdKey: (orgId: string, body: { name?: string; threshold?: number; totalParticipants?: number }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/threshold/keys`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    getThresholdKey: (orgId: string, id: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/threshold/keys/${id}`),

    createThresholdSession: (orgId: string, body: { keyId: string; operation?: string; messageToSign?: string; payloadToAuthorize?: string }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/threshold/sessions`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    getThresholdSession: (orgId: string, id: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/threshold/sessions/${id}`),

    approveThresholdSession: (orgId: string, id: string, body: { participantId: string }) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/threshold/sessions/${id}/approve`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),

    executeThresholdSession: (orgId: string, id: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/advanced/threshold/sessions/${id}/execute`, {
        method: 'POST',
      }),
  };

  // --- BILLING & LADDER ---
  billing = {
    get: (orgId: string) =>
      this.request<{ data: any }>(`/v1/billing?organizationId=${orgId}`, {
        headers: { 'x-organization-id': orgId },
      }),

    getLadder: (orgId: string) =>
      this.request<{ data: any }>(`/v1/billing/ladder?organizationId=${orgId}`, {
        headers: { 'x-organization-id': orgId },
      }),

    updateLadderPreference: (orgId: string, body: { isPermanentPayg?: boolean; autoLadderEnabled?: boolean }) =>
      this.request<{ data: any }>(`/v1/billing/ladder/preference?organizationId=${orgId}`, {
        method: 'POST',
        headers: { 'x-organization-id': orgId },
        body: JSON.stringify(body),
      }),

    upgrade: (orgId: string, body: { planId: string; reason?: string }) =>
      this.request<{ data: any }>(`/v1/billing/upgrade?organizationId=${orgId}`, {
        method: 'POST',
        headers: { 'x-organization-id': orgId },
        body: JSON.stringify(body),
      }),

    verifyCheckout: (orgId: string, body: { checkoutId: string; planId: string }) =>
      this.request<{ data: any }>(`/v1/billing/verify-checkout?organizationId=${orgId}`, {
        method: 'POST',
        headers: { 'x-organization-id': orgId },
        body: JSON.stringify(body),
      }),

    checkoutPreview: (orgId: string, planId: string, country?: string, interval: 'month' | 'year' = 'month') =>
      this.request<{ data: any }>(`/v1/billing/checkout/preview?organizationId=${orgId}`, {
        method: 'POST',
        headers: { 'x-organization-id': orgId },
        body: JSON.stringify({ planId, country, interval }),
      }),

    checkout: (orgId: string, body: { planId: string; interval?: 'month' | 'year'; successUrl?: string; cancelUrl?: string }) =>
      this.request<{ data: { checkoutUrl?: string; checkoutId?: string; planId?: string; interval?: string } }>(`/v1/billing/checkout?organizationId=${orgId}`, {
        method: 'POST',
        headers: { 'x-organization-id': orgId },
        body: JSON.stringify(body),
      }),

    portal: (orgId: string) =>
      this.request<{ data: { portalUrl?: string } }>(`/v1/billing/portal?organizationId=${orgId}`, {
        method: 'POST',
        headers: { 'x-organization-id': orgId },
      }),

    updateSafety: (orgId: string, body: any) =>
      this.request<{ data: any }>(`/v1/billing/safety?organizationId=${orgId}`, {
        method: 'PUT',
        headers: { 'x-organization-id': orgId },
        body: JSON.stringify(body),
      }),

    resetSafety: (orgId: string) =>
      this.request<{ data: any }>(`/v1/billing/safety/reset?organizationId=${orgId}`, {
        method: 'POST',
        headers: { 'x-organization-id': orgId },
      }),

    cancel: (orgId: string, body?: { atPeriodEnd?: boolean; reason?: string }) =>
      this.request<{ data: any }>(`/v1/billing/cancel?organizationId=${orgId}`, {
        method: 'POST',
        headers: { 'x-organization-id': orgId },
        body: JSON.stringify(body || {}),
      }),

    resume: (orgId: string) =>
      this.request<{ data: any }>(`/v1/billing/resume?organizationId=${orgId}`, {
        method: 'POST',
        headers: { 'x-organization-id': orgId },
      }),

    razorpayPlans: (orgId: string) =>
      this.request<{ data: { plans: { planId: string; interval?: 'month' | 'year'; amount: number; currency: string }[] } }>(`/v1/billing/razorpay/plans?organizationId=${orgId}`, {
        headers: { 'x-organization-id': orgId },
      }),

    razorpayCreateSubscription: (orgId: string, body: { planId: string; interval?: 'month' | 'year' }) =>
      this.request<{ data: { subscription_id: string } }>(`/v1/billing/razorpay/subscription?organizationId=${orgId}`, {
        method: 'POST',
        headers: { 'x-organization-id': orgId },
        body: JSON.stringify(body),
      }),

    razorpayVerifySubscription: (orgId: string, body: { razorpay_payment_id: string; razorpay_subscription_id: string; razorpay_signature: string }) =>
      this.request<{ data: { verified: boolean; subscription_id: string; status: string } }>(`/v1/billing/razorpay/verify-subscription?organizationId=${orgId}`, {
        method: 'POST',
        headers: { 'x-organization-id': orgId },
        body: JSON.stringify(body),
      }),
  };

  // --- SECURE UPLOADS ---
  uploads = {
    upload: (orgId: string, file: File | Blob, fieldName = 'file') => {
      const formData = new FormData();
      formData.append(fieldName, file);
      return this.request<{ data: { upload: any } }>(`/v1/organizations/${orgId}/uploads`, {
        method: 'POST',
        body: formData,
      });
    },

    list: (orgId: string, params?: { limit?: number; offset?: number }) => {
      const q = new URLSearchParams();
      if (params?.limit) q.set('limit', String(params.limit));
      if (params?.offset) q.set('offset', String(params.offset));
      const qs = q.toString() ? `?${q.toString()}` : '';
      return this.request<{ data: { uploads: any[]; pagination: any } }>(`/v1/organizations/${orgId}/uploads${qs}`);
    },

    get: (orgId: string, uploadId: string) =>
      this.request<{ data: { upload: any } }>(`/v1/organizations/${orgId}/uploads/${uploadId}`),

    delete: (orgId: string, uploadId: string) =>
      this.request<{ data: { deleted: boolean; id: string } }>(`/v1/organizations/${orgId}/uploads/${uploadId}`, {
        method: 'DELETE',
      }),
  };

  // --- PRIVACY & USER MANAGEMENT ---
  user = {
    getPrivacyStatus: () => this.request<any>('/v1/user/privacy-status'),
    acceptTerms: (body: { termsVersion: string; privacyPolicyVersion: string }) =>
      this.request<{ success: boolean; message: string }>('/v1/user/accept-terms', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    getPreferences: () =>
      this.request<{
        preferences: {
          marketingEmails: boolean;
          securityAlertsOnly: boolean;
          telemetryOptIn: boolean;
          cookieConsentStatus: string;
          updatedAt: string;
        };
      }>('/v1/user/preferences'),
    updatePreferences: (body: {
      marketingEmails?: boolean;
      securityAlertsOnly?: boolean;
      telemetryOptIn?: boolean;
    }) =>
      this.request<{
        success: boolean;
        preferences: {
          marketingEmails: boolean;
          securityAlertsOnly: boolean;
          telemetryOptIn: boolean;
          updatedAt: string;
        };
      }>('/v1/user/preferences', {
        method: 'PUT',
        body: JSON.stringify(body),
      }),
    exportData: async () => {
      const token = this.getAuthToken();
      const targetUrl = resolveTargetUrl('/v1/user/export-data');
      const res = await fetch(targetUrl, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        credentials: 'include',
      });
      if (!res.ok) throw new Error('Failed to download data export');
      return res.blob();
    },
    deleteAccount: (password: string) =>
      this.request<{ success: boolean; message: string }>('/v1/user/delete-account', {
        method: 'POST',
        body: JSON.stringify({ confirm: true, password }),
      }),
  };

  public email = {
    unsubscribe: (token: string) =>
      this.request<{
        data: {
          unsubscribed: boolean;
          maskedEmail: string;
          category: string;
          syncedWithAccount: boolean;
          suppressedAt: string;
          message: string;
          essentialNoticesNotice: string;
        };
      }>(`/v1/email/unsubscribe?token=${encodeURIComponent(token)}`),
    resubscribe: (token: string) =>
      this.request<{
        data: {
          resubscribed: boolean;
          maskedEmail: string;
          message: string;
        };
      }>('/v1/email/resubscribe', {
        method: 'POST',
        body: JSON.stringify({ token }),
      }),
  };

  public hosting = {
    listNodes: (orgId: string, params?: { runtimeType?: string; status?: string; environment?: string }) => {
      const query = new URLSearchParams(params as any).toString();
      return this.request<{ data: any[]; meta: any }>(`/v1/organizations/${orgId}/hosting/nodes${query ? `?${query}` : ''}`);
    },
    getNode: (orgId: string, nodeId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/hosting/nodes/${nodeId}`),
    registerNode: (orgId: string, body: any) =>
      this.request<{ data: { node: any; enrollmentToken: string; clientTlsConfig: any } }>(`/v1/organizations/${orgId}/hosting/nodes/register`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    heartbeat: (orgId: string, nodeId: string, body?: any) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/hosting/nodes/${nodeId}/heartbeat`, {
        method: 'POST',
        body: JSON.stringify(body || {}),
      }),
    getAttestation: (orgId: string, nodeId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/hosting/nodes/${nodeId}/attestation`),
    decommissionNode: (orgId: string, nodeId: string) =>
      this.request<{ data: any }>(`/v1/organizations/${orgId}/hosting/nodes/${nodeId}`, {
        method: 'DELETE',
      }),
    getDockerCompose: (orgId: string, options?: { nodeName?: string; environment?: string }) => {
      const query = new URLSearchParams(options as any).toString();
      return this.request<{ data: { manifest: string; runtime: string; filename: string } }>(`/v1/organizations/${orgId}/hosting/deploy/docker-compose${query ? `?${query}` : ''}`);
    },
    getKubernetesManifest: (orgId: string, options?: { nodeName?: string; namespace?: string; replicas?: number }) => {
      const query = new URLSearchParams(options as any).toString();
      return this.request<{ data: { manifest: string; runtime: string; filename: string } }>(`/v1/organizations/${orgId}/hosting/deploy/kubernetes${query ? `?${query}` : ''}`);
    },
    getInstallScript: (orgId: string, os: 'sh' | 'ps1', options?: { nodeName?: string }) => {
      const query = new URLSearchParams({ os, ...(options || {}) }).toString();
      return this.request<{ data: { script: string; osType: string; commandOneLiner: string } }>(`/v1/organizations/${orgId}/hosting/deploy/script?${query}`);
    },
  };
}

export const api = new ApiClient();
