import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { db } from '../../lib/data-store';
import { webhookEngine } from '../../lib/webhook-engine';
import { requireAuth, requireOrgMember, requireScope } from '../../middleware/auth';
import { sendSuccess, sendCollection, sendError, sendCaughtError } from '../../middleware/response-formatter';

const router = Router();

// Supported event types across Phases 1-18
export const SUPPORTED_WEBHOOK_EVENTS = [
  '*',
  'operation.completed',
  'operation.failed',
  'key.created',
  'key.rotated',
  'key.revoked',
  'key.disabled',
  'policy.created',
  'policy.updated',
  'policy.violation',
  'certificate.issued',
  'certificate.expiring',
  'certificate.revoked',
  'provider.connection.failed',
  'provider.health.changed',
  'byok.configuration.changed',
  'usage.threshold.reached',
  'crypto.finding.created',
  'crypto.finding.resolved',
  'pqc.operation.completed',
  'advanced.operation.completed',
] as const;

// GET /api/v1/webhooks & /api/v1/webhooks/endpoints - List webhook endpoints
router.get(
  ['/', '/endpoints'],
  requireAuth,
  requireOrgMember,
  requireScope('webhooks:read'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const endpoints = await db.getWebhookEndpointsByOrg(orgId);

      const items = endpoints.map((ep) => ({
        id: ep.id,
        url: ep.url,
        description: ep.description,
        secretPrefix: ep.secretPrefix,
        events: ep.events,
        status: ep.status,
        failureCount: ep.failureCount,
        createdAt: ep.createdAt,
        updatedAt: ep.updatedAt,
      }));

      return sendCollection(res, items, { hasMore: false, total: items.length });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to list webhook endpoints.');
    }
  }
);

// POST /api/v1/webhooks & /api/v1/webhooks/endpoints - Register new webhook endpoint
router.post(
  ['/', '/endpoints'],
  requireAuth,
  requireOrgMember,
  requireScope('webhooks:write'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const { url, description, events } = req.body;

      if (!url || typeof url !== 'string' || !url.startsWith('http')) {
        return sendError(res, 400, 'VALIDATION_FAILED', 'A valid HTTP or HTTPS destination URL is required.');
      }

      if (!events || !Array.isArray(events) || events.length === 0) {
        return sendError(res, 400, 'VALIDATION_FAILED', 'At least one event subscription must be specified.');
      }

      const invalidEvents = events.filter((e) => !(SUPPORTED_WEBHOOK_EVENTS as readonly string[]).includes(e));
      if (invalidEvents.length > 0) {
        return sendError(
          res,
          400,
          'VALIDATION_FAILED',
          `Unsupported events specified: [${invalidEvents.join(', ')}]. Supported: [${SUPPORTED_WEBHOOK_EVENTS.join(', ')}]`
        );
      }

      // Generate high-entropy HMAC signing secret
      const rawSecret = `whsec_${crypto.randomBytes(24).toString('hex')}`;
      const secretPrefix = rawSecret.slice(0, 10);
      const secretHash = rawSecret; // Stored securely to compute HMAC signatures

      const endpoint = await db.createWebhookEndpoint({
        organizationId: orgId,
        url: url.trim(),
        description: description?.trim() || null,
        secretHash,
        secretPrefix,
        events,
      });

      return res.status(201).json({
        data: {
          endpoint: {
            id: endpoint.id,
            url: endpoint.url,
            description: endpoint.description,
            secretPrefix: endpoint.secretPrefix,
            events: endpoint.events,
            status: endpoint.status,
            createdAt: endpoint.createdAt,
          },
          webhook: {
            id: endpoint.id,
            url: endpoint.url,
            description: endpoint.description,
            secretPrefix: endpoint.secretPrefix,
            events: endpoint.events,
            status: endpoint.status,
            createdAt: endpoint.createdAt,
          },
          secret: rawSecret,
          signingSecret: rawSecret,
          warning: 'Store this webhook signing secret now. Use it to verify incoming X-AMARACUS-Signature headers.',
        },
        requestId: (req as any).requestId,
      });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to register webhook endpoint.');
    }
  }
);

// GET /api/v1/webhooks/:id & /endpoints/:id - Get endpoint details
router.get(
  ['/:id', '/endpoints/:id'],
  requireAuth,
  requireOrgMember,
  requireScope('webhooks:read'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const endpoint = await db.getWebhookEndpointById(req.params.id);

      if (!endpoint || endpoint.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'Webhook endpoint not found.');
      }

      return sendSuccess(res, {
        id: endpoint.id,
        url: endpoint.url,
        description: endpoint.description,
        secretPrefix: endpoint.secretPrefix,
        events: endpoint.events,
        status: endpoint.status,
        failureCount: endpoint.failureCount,
        createdAt: endpoint.createdAt,
        updatedAt: endpoint.updatedAt,
      });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to retrieve webhook endpoint.');
    }
  }
);

// PATCH /api/v1/webhooks/:id & /endpoints/:id - Update endpoint URL, events, or status
router.patch(
  ['/:id', '/endpoints/:id'],
  requireAuth,
  requireOrgMember,
  requireScope('webhooks:write'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const endpoint = await db.getWebhookEndpointById(req.params.id);

      if (!endpoint || endpoint.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'Webhook endpoint not found.');
      }

      const { url, description, events, status } = req.body;

      if (url && (typeof url !== 'string' || !url.startsWith('http'))) {
        return sendError(res, 400, 'VALIDATION_FAILED', 'Invalid destination URL format.');
      }

      if (status && !['ACTIVE', 'DISABLED'].includes(status)) {
        return sendError(res, 400, 'VALIDATION_FAILED', "Status must be either 'ACTIVE' or 'DISABLED'.");
      }

      const updated = await db.updateWebhookEndpoint(endpoint.id, {
        url: url?.trim(),
        description: description?.trim(),
        events,
        status,
        failureCount: status === 'ACTIVE' ? 0 : endpoint.failureCount,
      });

      return sendSuccess(res, updated);
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to update webhook endpoint.');
    }
  }
);

// DELETE /api/v1/webhooks/:id & /endpoints/:id - Delete endpoint
router.delete(
  ['/:id', '/endpoints/:id'],
  requireAuth,
  requireOrgMember,
  requireScope('webhooks:write'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const endpoint = await db.getWebhookEndpointById(req.params.id);

      if (!endpoint || endpoint.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'Webhook endpoint not found.');
      }

      await db.deleteWebhookEndpoint(endpoint.id);
      return sendSuccess(res, { success: true, message: 'Webhook endpoint deleted successfully.' });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to delete webhook endpoint.');
    }
  }
);

// GET /api/v1/webhooks/:id/deliveries & /endpoints/:id/deliveries - List delivery logs
router.get(
  ['/:id/deliveries', '/endpoints/:id/deliveries'],
  requireAuth,
  requireOrgMember,
  requireScope('webhooks:read'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const endpoint = await db.getWebhookEndpointById(req.params.id);

      if (!endpoint || endpoint.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'Webhook endpoint not found.');
      }

      const deliveries = await db.getWebhookDeliveriesByEndpoint(endpoint.id, 50);
      return sendCollection(res, deliveries, { hasMore: false, total: deliveries.length });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to retrieve delivery history.');
    }
  }
);

// POST /api/v1/webhooks/:id/test & /endpoints/:id/test - Send a test ping event
router.post(
  ['/:id/test', '/endpoints/:id/test'],
  requireAuth,
  requireOrgMember,
  requireScope('webhooks:write'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const endpoint = await db.getWebhookEndpointById(req.params.id);

      if (!endpoint || endpoint.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'Webhook endpoint not found.');
      }

      const delivery = await webhookEngine.deliverToEndpoint(
        endpoint,
        {
          id: `evt_test_${Date.now()}`,
          type: 'webhook.test_ping',
          timestamp: new Date().toISOString(),
          data: {
            message: 'Hello from AMARACUS Cryptographic Developer Platform! Signature verification test.',
            organizationId: orgId,
          },
        },
        1
      );

      return sendSuccess(res, {
        success: true,
        delivered: delivery.status === 'DELIVERED',
        delivery: {
          ...delivery,
          event: delivery.eventType || 'webhook.test_ping',
        },
      });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to send test webhook.');
    }
  }
);

// POST /api/v1/webhooks/:id/rotate-secret & /endpoints/:id/rotate-secret - Rotate signing secret
router.post(
  ['/:id/rotate-secret', '/endpoints/:id/rotate-secret'],
  requireAuth,
  requireOrgMember,
  requireScope('webhooks:write'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const endpoint = await db.getWebhookEndpointById(req.params.id);

      if (!endpoint || endpoint.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'Webhook endpoint not found.');
      }

      // Generate new high-entropy HMAC signing secret
      const rawSecret = `whsec_${crypto.randomBytes(24).toString('hex')}`;
      const secretPrefix = rawSecret.slice(0, 10);
      const secretHash = rawSecret;

      const updated = await db.updateWebhookEndpoint(endpoint.id, {
        secretHash,
        secretPrefix,
      });

      return sendSuccess(res, {
        endpoint: {
          id: updated?.id || endpoint.id,
          url: updated?.url || endpoint.url,
          secretPrefix,
          updatedAt: updated?.updatedAt || new Date(),
        },
        signingSecret: rawSecret,
        warning: 'Update your webhook receiver application with this new secret immediately. Historical events signed with the previous secret cannot be re-verified with this secret.',
      });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to rotate webhook secret.');
    }
  }
);

export default router;
