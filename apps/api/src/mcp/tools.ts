import { fromJsonSchema, McpServer } from '@modelcontextprotocol/server';
import { isCloud } from '../lib/edition';
import { appUrl } from '../lib/site-config';
import { mcpBaseUrl } from './config';
import { GUIDE_TOPICS, GuideTopic, integrationGuide } from './integration-guide';

/** Runs one request against this API as the connected caller, so every check applies as usual. */
export type ApiCall = (method: 'GET' | 'POST' | 'PATCH', path: string, body?: unknown) => Promise<{ status: number; body: any }>;

export interface McpCaller {
  call: ApiCall;
  scopes: string[];
  connectionName: string;
}

type Json = Record<string, unknown>;
interface ToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: Json;
  readOnly: boolean;
  destructive: boolean;
  idempotent: boolean;
  run: (args: any, caller: McpCaller) => Promise<Json>;
}

class ToolFailure extends Error {}

const object = (properties: Json = {}, required: string[] = []): Json => ({
  type: 'object',
  properties,
  ...(required.length ? { required } : {}),
  additionalProperties: false,
});

const KEY_ID = { type: 'string', minLength: 1, maxLength: 200, description: 'Key ID, from list_keys or create_key.' };
const SENSITIVE_NOTE =
  'Do not send passwords, API keys, payment card numbers, government identifiers or health records through this tool; call the AMARACUS API from your own server for those.';
const MAX_TEXT = 200_000;

function explain(status: number, body: any): string {
  const code = body?.error?.code as string | undefined;
  const message = (body?.error?.message as string | undefined) || 'The request failed.';
  if (status === 402 && code === 'PAYMENT_REQUIRED') {
    return `This organization has no active AMARACUS plan, so the operation is not available.${isCloud() ? ` Plans are described at ${appUrl()}/pricing/.` : ''}`;
  }
  if (code === 'INSUFFICIENT_SCOPE') {
    return `${message} This connection was not given that permission. Reconnect AMARACUS and tick it, or use an API key that has the scope.`;
  }
  if (status === 429) {
    const wait = body?.error?.retryAfter;
    return `Too many requests.${wait ? ` Try again in ${wait} seconds.` : ''}`;
  }
  if (status >= 500) return 'AMARACUS could not complete the request. Nothing was returned; try again in a moment.';
  return code ? `${code}: ${message}` : message;
}

async function ok(caller: McpCaller, method: 'GET' | 'POST' | 'PATCH', path: string, body?: unknown): Promise<any> {
  const res = await caller.call(method, path, body);
  if (res.status < 200 || res.status > 299) throw new ToolFailure(explain(res.status, res.body));
  return res.body;
}

function describeKey(k: any): Json {
  return {
    id: k.id,
    name: k.name,
    ...(k.description ? { description: k.description } : {}),
    algorithm: k.algorithm,
    purpose: k.purpose,
    status: k.status,
    currentVersion: k.currentVersion,
  };
}

const keyPath = (id: string) => `/v1/keys/${encodeURIComponent(id)}`;

export const MCP_TOOLS: ToolDefinition[] = [
  {
    name: 'get_connection',
    title: 'Get connection details',
    description: 'Shows the name of this AMARACUS connection and which permissions it has. Use it to check why another tool was refused.',
    inputSchema: object(),
    readOnly: true,
    destructive: false,
    idempotent: true,
    run: async (_args, caller) => ({ connection: caller.connectionName, permissions: caller.scopes }),
  },
  {
    name: 'list_keys',
    title: 'List keys',
    description: 'Lists the managed keys of the connected organization: ID, name, algorithm, purpose, status and version. Key material is never returned.',
    inputSchema: object({
      status: { type: 'string', enum: ['ACTIVE', 'DISABLED', 'REVOKED', 'DESTROYED'], description: 'Only keys with this status.' },
      limit: { type: 'integer', minimum: 1, maximum: 100, description: 'How many keys to return (default 50).' },
      offset: { type: 'integer', minimum: 0, maximum: 100000, description: 'How many keys to skip.' },
    }),
    readOnly: true,
    destructive: false,
    idempotent: true,
    run: async (args, caller) => {
      const query = new URLSearchParams();
      for (const name of ['status', 'limit', 'offset']) if (args[name] !== undefined) query.set(name, String(args[name]));
      const res = await ok(caller, 'GET', `/v1/keys${query.size ? `?${query}` : ''}`);
      return { keys: res.data.map(describeKey), total: res.meta?.total ?? res.data.length };
    },
  },
  {
    name: 'get_key',
    title: 'Get key details',
    description: 'Shows one managed key and its versions, including public keys of signing keys. Private and symmetric key material is never returned.',
    inputSchema: object({ key_id: KEY_ID }, ['key_id']),
    readOnly: true,
    destructive: false,
    idempotent: true,
    run: async (args, caller) => {
      const { data } = await ok(caller, 'GET', keyPath(args.key_id));
      return {
        ...describeKey(data),
        versions: (data.versions || []).map((v: any) => ({
          version: v.version,
          status: v.status,
          ...(v.publicKey ? { publicKey: v.publicKey } : {}),
        })),
      };
    },
  },
  {
    name: 'list_algorithms',
    title: 'List algorithms',
    description: 'Lists the cryptographic algorithms AMARACUS supports, with category, security status and the standard that defines each.',
    inputSchema: object({ category: { type: 'string', maxLength: 40, description: 'Only this category, for example HASH.' } }),
    readOnly: true,
    destructive: false,
    idempotent: true,
    run: async (args, caller) => {
      const { data } = await ok(caller, 'GET', '/v1/algorithms');
      const wanted = typeof args.category === 'string' ? args.category.toLowerCase() : null;
      return {
        algorithms: data
          .filter((a: any) => !wanted || String(a.category).toLowerCase() === wanted)
          .map((a: any) => ({
            id: a.id,
            category: a.category,
            operations: a.supportedOperations,
            securityStatus: a.securityStatus,
            quantumResistant: a.quantumResistant,
            standard: a.standardReference,
          })),
      };
    },
  },
  {
    name: 'get_integration_guide',
    title: 'Get integration guide',
    description: 'Returns AMARACUS integration notes and code for one topic, for adding encryption to an application: quickstart, nodejs, python, curl, errors or best_practices.',
    inputSchema: object({ topic: { type: 'string', enum: [...GUIDE_TOPICS], description: 'Which notes to return.' } }, ['topic']),
    readOnly: true,
    destructive: false,
    idempotent: true,
    run: async (args) => ({ guide: integrationGuide(args.topic as GuideTopic, mcpBaseUrl()) }),
  },
  {
    name: 'get_usage',
    title: 'Get API usage',
    description: 'Shows how many API requests the connected organization made, with totals per endpoint and status code, optionally for a date range.',
    inputSchema: object({
      from: { type: 'string', format: 'date', description: 'First day, YYYY-MM-DD.' },
      to: { type: 'string', format: 'date', description: 'Last moment, YYYY-MM-DD (midnight UTC).' },
    }),
    readOnly: true,
    destructive: false,
    idempotent: true,
    run: async (args, caller) => {
      const query = new URLSearchParams();
      for (const name of ['from', 'to']) if (args[name]) query.set(name, args[name]);
      const { data } = await ok(caller, 'GET', `/v1/usage${query.size ? `?${query}` : ''}`);
      return {
        totalRequests: data.totalRequests,
        successRequests: data.successRequests,
        errorRequests: data.errorRequests,
        averageLatencyMs: data.averageLatencyMs,
        byEndpoint: data.byEndpoint,
        byStatusCode: data.byStatusCode,
      };
    },
  },
  {
    name: 'create_key',
    title: 'Create key',
    description: 'Creates a managed AES-256-GCM encryption key in the connected environment and returns its key ID. The key counts towards the plan. Names are unique within an environment.',
    inputSchema: object(
      {
        name: { type: 'string', minLength: 1, maxLength: 100, description: 'A name such as customer-data.' },
        description: { type: 'string', maxLength: 500, description: 'What the key is for.' },
      },
      ['name']
    ),
    readOnly: false,
    destructive: false,
    idempotent: false,
    run: async (args, caller) => {
      const { data } = await ok(caller, 'POST', '/v1/keys', {
        name: args.name,
        description: args.description,
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPTION',
      });
      return describeKey(data);
    },
  },
  {
    name: 'rotate_key',
    title: 'Rotate key',
    description: 'Creates a new version of a managed key. New data is encrypted with the new version; data encrypted earlier still decrypts. A rotation cannot be undone.',
    inputSchema: object({ key_id: KEY_ID }, ['key_id']),
    readOnly: false,
    destructive: true,
    idempotent: false,
    run: async (args, caller) => describeKey((await ok(caller, 'POST', `${keyPath(args.key_id)}/rotate`, {})).data),
  },
  {
    name: 'disable_key',
    title: 'Disable key',
    description: 'Disables a managed key: applications can no longer encrypt or sign with it, while existing data can still be decrypted. enable_key reverses it.',
    inputSchema: object({ key_id: KEY_ID }, ['key_id']),
    readOnly: false,
    destructive: true,
    idempotent: true,
    run: async (args, caller) => describeKey((await ok(caller, 'PATCH', keyPath(args.key_id), { status: 'DISABLED' })).data),
  },
  {
    name: 'enable_key',
    title: 'Enable key',
    description: 'Makes a disabled managed key active again. It has no effect on revoked or destroyed keys, which stay that way.',
    inputSchema: object({ key_id: KEY_ID }, ['key_id']),
    readOnly: false,
    destructive: false,
    idempotent: true,
    run: async (args, caller) => describeKey((await ok(caller, 'PATCH', keyPath(args.key_id), { status: 'ACTIVE' })).data),
  },
  {
    name: 'encrypt_data',
    title: 'Encrypt data',
    description: `Encrypts text with a managed key and returns an envelope to store. Uses one operation of the plan. ${SENSITIVE_NOTE}`,
    inputSchema: object(
      {
        key_id: KEY_ID,
        data: { type: 'string', minLength: 1, maxLength: MAX_TEXT, description: 'The text to encrypt.' },
        context: {
          type: 'string',
          maxLength: 500,
          description: 'Optional context bound to the envelope, such as customers:42:note. The same value is needed to decrypt.',
        },
      },
      ['key_id', 'data']
    ),
    readOnly: false,
    destructive: false,
    idempotent: false,
    run: async (args, caller) => {
      const { data } = await ok(caller, 'POST', '/v1/encrypt', { key: args.key_id, data: args.data, aad: args.context });
      return { envelope: data.envelope, algorithm: data.algorithm, keyId: data.keyId, keyVersion: data.keyVersion };
    },
  },
  {
    name: 'decrypt_data',
    title: 'Decrypt data',
    description: `Decrypts an AMARACUS envelope with a managed key and returns the original text to this conversation. Uses one operation of the plan. ${SENSITIVE_NOTE}`,
    inputSchema: object(
      {
        key_id: KEY_ID,
        envelope: { type: 'string', minLength: 1, maxLength: 400_000, description: 'The envelope returned by encrypt_data or the AMARACUS API.' },
        context: { type: 'string', maxLength: 500, description: 'The context the envelope was encrypted with, if any.' },
      },
      ['key_id', 'envelope']
    ),
    readOnly: false,
    destructive: false,
    idempotent: true,
    run: async (args, caller) => {
      const { data } = await ok(caller, 'POST', '/v1/decrypt', { key: args.key_id, envelope: args.envelope, aad: args.context });
      return { text: data.plaintext, encoding: data.encoding };
    },
  },
  {
    name: 'hash_data',
    title: 'Hash data',
    description: 'Computes a SHA-2 or SHA-3 digest of text. Uses one operation of the plan. Not suitable for storing user passwords.',
    inputSchema: object(
      {
        data: { type: 'string', maxLength: MAX_TEXT, description: 'The text to hash.' },
        algorithm: {
          type: 'string',
          enum: ['SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-384', 'SHA3-512'],
          description: 'Digest algorithm (default SHA-256).',
        },
      },
      ['data']
    ),
    readOnly: false,
    destructive: false,
    idempotent: true,
    run: async (args, caller) => {
      const { data } = await ok(caller, 'POST', '/v1/hash', { data: args.data, algorithm: args.algorithm || 'SHA-256' });
      return { digest: data.digest, algorithm: data.algorithm, encoding: data.encoding };
    },
  },
];

export function buildMcpServer(caller: McpCaller): McpServer {
  const server = new McpServer(
    {
      name: 'amaracus',
      title: 'AMARACUS',
      version: '1.0.0',
      ...(isCloud() ? { websiteUrl: `${appUrl()}/mcp/` } : {}),
    },
    {
      instructions:
        'AMARACUS is an encryption and key management service. These tools manage keys, encrypt, decrypt and hash text, ' +
        'and return integration notes for adding AMARACUS to an application. Key material is never returned.',
    }
  );
  for (const tool of MCP_TOOLS) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: fromJsonSchema<any>(tool.inputSchema as any),
        annotations: {
          title: tool.title,
          readOnlyHint: tool.readOnly,
          destructiveHint: tool.destructive,
          idempotentHint: tool.idempotent,
          openWorldHint: false,
        },
      },
      async (args: any) => {
        try {
          const result = await tool.run(args || {}, caller);
          const text = typeof result.guide === 'string' ? result.guide : JSON.stringify(result, null, 2);
          return { content: [{ type: 'text' as const, text }], structuredContent: result };
        } catch (err) {
          if (!(err instanceof ToolFailure)) console.error(`[MCP] Tool ${tool.name} failed:`, (err as Error)?.message || err);
          const text = err instanceof ToolFailure ? err.message : 'AMARACUS could not complete the request. Try again in a moment.';
          return { content: [{ type: 'text' as const, text }], isError: true };
        }
      }
    );
  }
  return server;
}
