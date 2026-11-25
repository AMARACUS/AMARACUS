import { appUrl, site } from '../lib/site-config';

/**
 * Public addresses of the MCP server and its OAuth endpoints. MCP_PUBLIC_URL overrides the API's
 * own address (used behind a different hostname, and by local end-to-end tests).
 */
export function mcpBaseUrl(): string {
  return (process.env.MCP_PUBLIC_URL?.trim() || site('apiUrl')).replace(/\/+$/, '');
}

/** The MCP endpoint. It is also the OAuth resource identifier (RFC 8707). */
export function mcpResourceUrl(): string {
  return `${mcpBaseUrl()}/mcp`;
}

export function protectedResourceMetadataUrl(): string {
  return `${mcpBaseUrl()}/.well-known/oauth-protected-resource/mcp`;
}

export function consentPageUrl(request: string): string {
  return `${appUrl()}/connect/?request=${encodeURIComponent(request)}`;
}

export interface McpScope {
  id: string;
  label: string;
  /** Pre-selected on the consent page. Scopes that reveal data or change existing keys are opt-in. */
  preselected: boolean;
}

/** Everything an MCP connection can be allowed to do. Deleting keys and managing API keys is not on the list. */
export const MCP_SCOPES: McpScope[] = [
  { id: 'keys:read', label: 'See your keys (names, algorithms and status, never key material)', preselected: true },
  { id: 'usage:read', label: 'See request counts for your organization', preselected: true },
  { id: 'crypto:hash', label: 'Hash data', preselected: true },
  { id: 'crypto:encrypt', label: 'Encrypt data with your keys', preselected: true },
  { id: 'keys:create', label: 'Create keys', preselected: true },
  { id: 'crypto:decrypt', label: 'Decrypt data with your keys (the assistant will see the decrypted text)', preselected: false },
  { id: 'keys:rotate', label: 'Rotate keys to a new version', preselected: false },
  { id: 'keys:write', label: 'Disable and re-enable keys', preselected: false },
];

export const MCP_SCOPE_IDS = MCP_SCOPES.map((s) => s.id);
