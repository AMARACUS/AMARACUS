import fs from 'fs';
import path from 'path';

export function buildOpenApiSpec() {
  return {
    openapi: '3.1.0',
    info: {
      title: 'AMARACUS Cryptographic Developer Platform API',
      version: '1.0.0',
      description:
        'Production-grade cryptographic API providing unified access to Classical Cryptography, Post-Quantum Cryptography (ML-KEM, ML-DSA), Key Management (KMS & BYOK), PKI & Certificates, Cryptographic Bill of Materials (CBOM), and Advanced Cryptography (ZK, FHE, MPC, Threshold Cryptography).',
      contact: {
        name: 'AMARACUS Engineering & Security Team',
        url: 'https://amaracus.tech/support',
        email: 'security@amaracus.tech',
      },
      license: {
        name: 'Apache-2.0',
        url: 'https://www.apache.org/licenses/LICENSE-2.0',
      },
    },
    servers: [
      {
        url: 'http://localhost:4000/api/v1',
        description: 'Local Development Server',
      },
      {
        url: 'https://api.amaracus.tech/api/v1',
        description: 'Production API Gateway',
      },
    ],
    security: [
      {
        ApiKeyAuth: [],
      },
    ],
    components: {
      securitySchemes: {
        ApiKeyAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'am_live_... / am_test_...',
          description:
            'Authenticate using an AMARACUS API Key. Provide the key in the Authorization header: `Bearer am_live_...` or `Bearer am_test_...`.',
        },
      },
      schemas: {
        ErrorObject: {
          type: 'object',
          required: ['code', 'message', 'requestId'],
          properties: {
            code: {
              type: 'string',
              description: 'Standardized error code from the AMARACUS Error Catalog.',
              example: 'INSUFFICIENT_SCOPE',
            },
            message: {
              type: 'string',
              description: 'Human-readable description of the error.',
              example: 'API credential lacks required scope crypto:execute.',
            },
            details: {
              type: 'object',
              description: 'Additional structured error context if available.',
            },
            requestId: {
              type: 'string',
              description: 'Unique correlation ID for tracing the request.',
              example: 'req_1726821600_ab12cd3',
            },
          },
        },
        ErrorResponse: {
          type: 'object',
          required: ['error'],
          properties: {
            error: {
              $ref: '#/components/schemas/ErrorObject',
            },
          },
        },
        PaginationMeta: {
          type: 'object',
          required: ['hasMore', 'total'],
          properties: {
            hasMore: { type: 'boolean', example: false },
            nextCursor: { type: 'string', nullable: true, example: null },
            total: { type: 'integer', example: 1 },
          },
        },
        ApiCredential: {
          type: 'object',
          required: ['id', 'name', 'prefix', 'organizationId', 'scopes', 'status', 'createdAt'],
          properties: {
            id: { type: 'string', example: 'cred_cm12345678' },
            name: { type: 'string', example: 'Production Microservice Key' },
            prefix: { type: 'string', example: 'am_live_9f8e7d6c' },
            organizationId: { type: 'string', example: 'org_main' },
            projectId: { type: 'string', nullable: true, example: 'proj_core' },
            environmentId: { type: 'string', nullable: true, example: 'env_prod' },
            scopes: {
              type: 'array',
              items: { type: 'string' },
              example: ['crypto:execute', 'keys:read', 'pqc:execute'],
            },
            status: {
              type: 'string',
              enum: ['ACTIVE', 'DISABLED', 'REVOKED', 'EXPIRED'],
              example: 'ACTIVE',
            },
            expiresAt: { type: 'string', format: 'date-time', nullable: true },
            lastUsedAt: { type: 'string', format: 'date-time', nullable: true },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
        WebhookEndpoint: {
          type: 'object',
          required: ['id', 'url', 'organizationId', 'events', 'status', 'createdAt'],
          properties: {
            id: { type: 'string', example: 'whk_123456' },
            url: { type: 'string', format: 'uri', example: 'https://api.merchant.com/webhooks' },
            description: { type: 'string', example: 'Key rotation listener' },
            organizationId: { type: 'string', example: 'org_main' },
            events: {
              type: 'array',
              items: { type: 'string' },
              example: ['key.rotated', 'certificate.issued'],
            },
            status: { type: 'string', enum: ['ACTIVE', 'DISABLED'], example: 'ACTIVE' },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
        WebhookDelivery: {
          type: 'object',
          required: ['id', 'webhookEndpointId', 'event', 'status', 'statusCode', 'durationMs', 'attempt', 'createdAt'],
          properties: {
            id: { type: 'string', example: 'del_123456' },
            webhookEndpointId: { type: 'string', example: 'whk_123456' },
            event: { type: 'string', example: 'key.rotated' },
            status: { type: 'string', enum: ['SUCCESS', 'FAILED', 'PENDING'], example: 'SUCCESS' },
            statusCode: { type: 'integer', example: 200 },
            durationMs: { type: 'integer', example: 45 },
            attempt: { type: 'integer', example: 1 },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
        AsyncJob: {
          type: 'object',
          required: ['id', 'type', 'status', 'organizationId', 'progress', 'createdAt'],
          properties: {
            id: { type: 'string', example: 'job_123456' },
            type: {
              type: 'string',
              enum: ['ZK_PROVE', 'FHE_EVALUATE', 'MPC_COMPUTE', 'DISCOVERY_SCAN'],
              example: 'ZK_PROVE',
            },
            status: {
              type: 'string',
              enum: ['QUEUED', 'PROCESSING', 'COMPLETED', 'FAILED', 'CANCELLED'],
              example: 'COMPLETED',
            },
            progress: { type: 'integer', minimum: 0, maximum: 100, example: 100 },
            organizationId: { type: 'string', example: 'org_main' },
            result: { type: 'object', nullable: true },
            error: { type: 'string', nullable: true },
            createdAt: { type: 'string', format: 'date-time' },
            completedAt: { type: 'string', format: 'date-time', nullable: true },
          },
        },
        UsageTelemetry: {
          type: 'object',
          required: ['totalRequests', 'successRequests', 'errorRequests', 'avgLatencyMs'],
          properties: {
            totalRequests: { type: 'integer', example: 1250 },
            successRequests: { type: 'integer', example: 1245 },
            errorRequests: { type: 'integer', example: 5 },
            avgLatencyMs: { type: 'number', example: 28.4 },
          },
        },
        AlgorithmDescriptor: {
          type: 'object',
          required: ['id', 'family', 'securityBits'],
          properties: {
            id: { type: 'string', example: 'AES_256_GCM' },
            name: { type: 'string', example: 'AES-256-GCM' },
            family: { type: 'string', example: 'SYMMETRIC' },
            securityBits: { type: 'integer', example: 256 },
            isPostQuantum: { type: 'boolean', example: false },
          },
        },
        CryptoPolicy: {
          type: 'object',
          required: ['id', 'name', 'minimumSymmetricKeyBits', 'minimumRsaKeyBits'],
          properties: {
            id: { type: 'string', example: 'DEFAULT_SECURE' },
            name: { type: 'string', example: 'Default Secure Policy' },
            minimumSymmetricKeyBits: { type: 'integer', example: 256 },
            minimumRsaKeyBits: { type: 'integer', example: 3072 },
            allowedAlgorithms: { type: 'array', items: { type: 'string' } },
          },
        },
        CryptographicKey: {
          type: 'object',
          required: ['id', 'name', 'algorithm', 'purpose', 'status', 'version', 'createdAt'],
          properties: {
            id: { type: 'string', example: 'key_123456' },
            name: { type: 'string', example: 'payment-token-key' },
            description: { type: 'string', example: 'Primary encryption key' },
            algorithm: { type: 'string', example: 'AES_256_GCM' },
            purpose: { type: 'string', example: 'ENCRYPT_DECRYPT' },
            provider: { type: 'string', example: 'LOCAL_DEV' },
            status: { type: 'string', example: 'ACTIVE' },
            version: { type: 'integer', example: 1 },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
        Certificate: {
          type: 'object',
          required: ['id', 'subject', 'issuer', 'serialNumber', 'status', 'validFrom', 'validTo'],
          properties: {
            id: { type: 'string', example: 'cert_123456' },
            subject: { type: 'string', example: 'CN=api.internal.corp' },
            issuer: { type: 'string', example: 'CN=AMARACUS Root CA' },
            serialNumber: { type: 'string', example: '4a:7b:3c:9d' },
            status: { type: 'string', enum: ['ACTIVE', 'REVOKED', 'EXPIRED'], example: 'ACTIVE' },
            validFrom: { type: 'string', format: 'date-time' },
            validTo: { type: 'string', format: 'date-time' },
          },
        },
      },
    },
    paths: {
      '/health': {
        get: {
          summary: 'Platform Health Check',
          description: 'Returns health status and service metadata.',
          responses: {
            '200': {
              description: 'Service operational',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: {
                        type: 'object',
                        properties: {
                          status: { type: 'string', example: 'ok' },
                          version: { type: 'string', example: '1.0.0' },
                          service: { type: 'string', example: 'amaracus-developer-platform' },
                          timestamp: { type: 'string', format: 'date-time' },
                        },
                      },
                      requestId: { type: 'string', example: 'req_1726821600' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/auth/me': {
        get: {
          summary: 'Inspect Current Principal Context',
          description: 'Inspects authenticated caller identity, organization context, granted scopes, or session details.',
          responses: {
            '200': {
              description: 'Authenticated identity context',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: {
                        type: 'object',
                        properties: {
                          type: { type: 'string', example: 'API_CREDENTIAL' },
                          id: { type: 'string', example: 'cred_123456' },
                          organizationId: { type: 'string', example: 'org_main' },
                          scopes: { type: 'array', items: { type: 'string' } },
                          status: { type: 'string', example: 'ACTIVE' },
                        },
                      },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
            '401': { $ref: '#/components/schemas/ErrorResponse' },
          },
        },
      },
      '/credentials': {
        get: {
          summary: 'List API Credentials',
          description: 'Retrieves all API credentials for the organization. Note that raw secret keys are never returned after creation.',
          parameters: [
            { name: 'limit', in: 'query', schema: { type: 'integer', default: 50 }, description: 'Page size limit' },
            { name: 'cursor', in: 'query', schema: { type: 'string' }, description: 'Pagination cursor' },
          ],
          responses: {
            '200': {
              description: 'List of credential metadata',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { type: 'array', items: { $ref: '#/components/schemas/ApiCredential' } },
                      pagination: { $ref: '#/components/schemas/PaginationMeta' },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
            '403': { $ref: '#/components/schemas/ErrorResponse' },
          },
        },
        post: {
          summary: 'Create API Credential',
          description: 'Generates a new scoped API key. The raw API key (`am_live_...` or `am_test_...`) is returned ONCE in this response. Store it securely; AMARACUS only retains its SHA-256 hash.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['name', 'scopes'],
                  properties: {
                    name: { type: 'string', example: 'Backend Processing Key' },
                    environment: { type: 'string', enum: ['live', 'test'], default: 'live', example: 'live' },
                    scopes: {
                      type: 'array',
                      items: { type: 'string' },
                      example: ['crypto:execute', 'keys:read', 'pqc:execute'],
                    },
                    projectId: { type: 'string', example: 'proj_default' },
                    environmentId: { type: 'string', example: 'env_prod' },
                    expiresInDays: { type: 'integer', example: 90 },
                  },
                },
              },
            },
          },
          responses: {
            '201': {
              description: 'API key successfully created. Contains one-time raw secret.',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: {
                        type: 'object',
                        properties: {
                          credential: { $ref: '#/components/schemas/ApiCredential' },
                          rawApiKey: {
                            type: 'string',
                            example: 'am_live_9f8e7d6c5b4a3210fedcba9876543210123456789abcdef0123456789abcdef0',
                            description: 'Shown ONLY once at creation time.',
                          },
                        },
                      },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
            '400': { $ref: '#/components/schemas/ErrorResponse' },
          },
        },
      },
      '/credentials/{id}': {
        get: {
          summary: 'Get API Credential Metadata',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': {
              description: 'Credential metadata',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { $ref: '#/components/schemas/ApiCredential' },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
            '404': { $ref: '#/components/schemas/ErrorResponse' },
          },
        },
        patch: {
          summary: 'Update Credential Status',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    status: { type: 'string', enum: ['ACTIVE', 'DISABLED'] },
                    name: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Updated credential' },
            '404': { $ref: '#/components/schemas/ErrorResponse' },
          },
        },
        delete: {
          summary: 'Revoke API Credential',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': { description: 'Credential permanently revoked' },
            '404': { $ref: '#/components/schemas/ErrorResponse' },
          },
        },
      },
      '/credentials/{id}/rotate': {
        post: {
          summary: 'Rotate API Credential',
          description: 'Generates a new raw key secret for this credential and immediately invalidates the old secret.',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': {
              description: 'Key successfully rotated. Contains new one-time raw secret.',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: {
                        type: 'object',
                        properties: {
                          credential: { $ref: '#/components/schemas/ApiCredential' },
                          rawApiKey: { type: 'string' },
                        },
                      },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/webhooks': {
        get: {
          summary: 'List Webhook Endpoints',
          responses: {
            '200': {
              description: 'List of registered webhooks',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { type: 'array', items: { $ref: '#/components/schemas/WebhookEndpoint' } },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
        post: {
          summary: 'Register Webhook Endpoint',
          description: 'Registers a webhook endpoint for cryptographic event notifications. Returns signing secret once.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['url', 'events'],
                  properties: {
                    url: { type: 'string', format: 'uri', example: 'https://api.example.com/webhooks' },
                    description: { type: 'string', example: 'Production listener' },
                    events: {
                      type: 'array',
                      items: { type: 'string' },
                      example: ['key.rotated', 'certificate.issued'],
                    },
                  },
                },
              },
            },
          },
          responses: {
            '201': {
              description: 'Webhook created with one-time signing secret',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: {
                        type: 'object',
                        properties: {
                          webhook: { $ref: '#/components/schemas/WebhookEndpoint' },
                          signingSecret: { type: 'string', example: 'whsec_9a8b7c6d...' },
                        },
                      },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/webhooks/{id}/deliveries': {
        get: {
          summary: 'Get Webhook Delivery Logs',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': {
              description: 'Delivery attempt history',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { type: 'array', items: { $ref: '#/components/schemas/WebhookDelivery' } },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/webhooks/{id}/test': {
        post: {
          summary: 'Send Test Webhook Ping',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': { description: 'Test ping dispatched' },
          },
        },
      },
      '/jobs': {
        get: {
          summary: 'List Async Heavy Jobs',
          responses: {
            '200': {
              description: 'List of jobs',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { type: 'array', items: { $ref: '#/components/schemas/AsyncJob' } },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
        post: {
          summary: 'Submit Heavy Cryptographic Async Job',
          description: 'Dispatches asynchronous execution of resource-intensive operations (ZK_PROVE, FHE_EVALUATE, MPC_COMPUTE, DISCOVERY_SCAN).',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['type', 'payload'],
                  properties: {
                    type: {
                      type: 'string',
                      enum: ['ZK_PROVE', 'FHE_EVALUATE', 'MPC_COMPUTE', 'DISCOVERY_SCAN'],
                      example: 'ZK_PROVE',
                    },
                    payload: { type: 'object' },
                  },
                },
              },
            },
          },
          responses: {
            '202': {
              description: 'Job accepted and processing started',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { $ref: '#/components/schemas/AsyncJob' },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/jobs/{id}': {
        get: {
          summary: 'Get Async Job Status & Result',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': {
              description: 'Job status and completed payload result',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { $ref: '#/components/schemas/AsyncJob' },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
        delete: {
          summary: 'Cancel Async Job',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': { description: 'Job cancelled' },
          },
        },
      },
      '/usage': {
        get: {
          summary: 'Query API Usage & Telemetry',
          parameters: [
            { name: 'from', in: 'query', schema: { type: 'string', format: 'date-time' } },
            { name: 'to', in: 'query', schema: { type: 'string', format: 'date-time' } },
          ],
          responses: {
            '200': {
              description: 'Usage summary and timeline',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { $ref: '#/components/schemas/UsageTelemetry' },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/crypto/algorithms': {
        get: {
          summary: 'List Registered Cryptographic Algorithms',
          responses: {
            '200': {
              description: 'Catalog of supported cryptographic algorithms',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { type: 'array', items: { $ref: '#/components/schemas/AlgorithmDescriptor' } },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/crypto/policies': {
        get: {
          summary: 'List Active Cryptographic Policies',
          responses: {
            '200': {
              description: 'List of policies',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { type: 'array', items: { $ref: '#/components/schemas/CryptoPolicy' } },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/crypto/encrypt': {
        post: {
          summary: 'Encrypt Data',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['algorithm', 'plaintext'],
                  properties: {
                    algorithm: { type: 'string', example: 'AES_256_GCM' },
                    plaintext: { type: 'string', description: 'Base64-encoded or raw plaintext' },
                    key: { type: 'string', description: 'Base64 key (if not using keyId)' },
                    keyId: { type: 'string', description: 'KMS Key ID' },
                    associatedData: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'Ciphertext result',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: {
                        type: 'object',
                        properties: {
                          ciphertext: { type: 'string' },
                          iv: { type: 'string' },
                          tag: { type: 'string' },
                          algorithm: { type: 'string' },
                        },
                      },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/crypto/decrypt': {
        post: {
          summary: 'Decrypt Data',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['algorithm', 'ciphertext'],
                  properties: {
                    algorithm: { type: 'string', example: 'AES_256_GCM' },
                    ciphertext: { type: 'string' },
                    key: { type: 'string' },
                    keyId: { type: 'string' },
                    iv: { type: 'string' },
                    tag: { type: 'string' },
                    associatedData: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'Decrypted plaintext',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: {
                        type: 'object',
                        properties: {
                          plaintext: { type: 'string' },
                        },
                      },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/pqc/algorithms': {
        get: {
          summary: 'List Post-Quantum Cryptographic Algorithms',
          description: 'Returns list of FIPS-standardized PQC algorithms (ML-KEM-768, ML-DSA-65).',
          responses: {
            '200': {
              description: 'PQC algorithms',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { type: 'array', items: { type: 'string' }, example: ['ML_KEM_768', 'ML_DSA_65'] },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/pqc/keypair': {
        post: {
          summary: 'Generate Post-Quantum Keypair',
          description: 'Generates an authentic NIST FIPS 203 (ML-KEM) or FIPS 204 (ML-DSA) keypair.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['algorithm'],
                  properties: {
                    algorithm: { type: 'string', enum: ['ML_KEM_768', 'ML_DSA_65'], example: 'ML_KEM_768' },
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'PQC Keypair',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: {
                        type: 'object',
                        properties: {
                          algorithm: { type: 'string' },
                          publicKey: { type: 'string' },
                          privateKey: { type: 'string' },
                        },
                      },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/pqc/encapsulate': {
        post: {
          summary: 'ML-KEM Key Encapsulation',
          description: 'Encapsulates a shared secret under a recipient ML-KEM public key.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['algorithm', 'publicKey'],
                  properties: {
                    algorithm: { type: 'string', example: 'ML_KEM_768' },
                    publicKey: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'Encapsulation result',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: {
                        type: 'object',
                        properties: {
                          cipherText: { type: 'string' },
                          sharedSecret: { type: 'string' },
                        },
                      },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/pqc/decapsulate': {
        post: {
          summary: 'ML-KEM Key Decapsulation',
          description: 'Decapsulates the shared secret using the recipient ML-KEM private key.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['algorithm', 'cipherText', 'privateKey'],
                  properties: {
                    algorithm: { type: 'string', example: 'ML_KEM_768' },
                    cipherText: { type: 'string' },
                    privateKey: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'Decapsulated shared secret',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: {
                        type: 'object',
                        properties: {
                          sharedSecret: { type: 'string' },
                        },
                      },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/keys': {
        get: {
          summary: 'List Cryptographic Keys',
          responses: {
            '200': {
              description: 'List of managed keys',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { type: 'array', items: { $ref: '#/components/schemas/CryptographicKey' } },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
        post: {
          summary: 'Create / Register Cryptographic Key',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['name', 'projectId', 'environmentId', 'algorithm', 'purpose'],
                  properties: {
                    name: { type: 'string', example: 'app-db-key' },
                    description: { type: 'string' },
                    projectId: { type: 'string' },
                    environmentId: { type: 'string' },
                    algorithm: { type: 'string', example: 'AES_256_GCM' },
                    purpose: { type: 'string', example: 'ENCRYPT_DECRYPT' },
                    provider: { type: 'string', default: 'LOCAL_DEV' },
                  },
                },
              },
            },
          },
          responses: {
            '201': {
              description: 'Key created',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { $ref: '#/components/schemas/CryptographicKey' },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/certificates': {
        get: {
          summary: 'List Issued Certificates',
          responses: {
            '200': {
              description: 'List of certificates',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { type: 'array', items: { $ref: '#/components/schemas/Certificate' } },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/certificates/issue': {
        post: {
          summary: 'Issue X.509 Certificate',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['caId', 'subjectCommonName'],
                  properties: {
                    caId: { type: 'string' },
                    subjectCommonName: { type: 'string', example: 'service.corp.internal' },
                    sanDnsNames: { type: 'array', items: { type: 'string' } },
                    validityDays: { type: 'integer', default: 365 },
                  },
                },
              },
            },
          },
          responses: {
            '201': {
              description: 'Certificate issued',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      data: { $ref: '#/components/schemas/Certificate' },
                      requestId: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
  };
}

const spec = buildOpenApiSpec();
const outDir = path.resolve(__dirname);
const outFile = path.join(outDir, 'openapi.json');

fs.writeFileSync(outFile, JSON.stringify(spec, null, 2), 'utf-8');
console.log(`[OpenAPI Generator] Successfully wrote canonical OpenAPI 3.1 specification to ${outFile}`);
