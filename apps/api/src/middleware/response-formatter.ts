import { Request, Response, NextFunction } from 'express';

export interface StandardSuccessResponse<T = any> {
  data: T;
  requestId: string;
}

export interface StandardCollectionResponse<T = any> {
  data: T[];
  pagination: {
    nextCursor?: string | null;
    hasMore: boolean;
    total?: number;
  };
  requestId: string;
}

export interface StandardErrorResponse {
  error: {
    code: string;
    message: string;
    requestId: string;
    details?: any;
  };
}

/**
 * Sends a standardized success envelope.
 */
export function sendSuccess<T>(res: Response, data: T, statusCode = 200): Response {
  const req = res.req as Request;
  const requestId = (req as any).requestId || `req_${Date.now()}`;
  return res.status(statusCode).json({
    data,
    requestId,
  });
}

/**
 * Sends a standardized collection envelope with cursor pagination.
 */
export function sendCollection<T>(
  res: Response,
  items: T[],
  pagination: { nextCursor?: string | null; hasMore: boolean; total?: number },
  statusCode = 200
): Response {
  const req = res.req as Request;
  const requestId = (req as any).requestId || `req_${Date.now()}`;
  return res.status(statusCode).json({
    data: items,
    pagination,
    requestId,
  });
}

/**
 * Sends a standardized public error envelope.
 */
export function sendError(
  res: Response,
  statusCode: number,
  code: string,
  message: string,
  details?: any
): Response {
  const req = res.req as Request;
  const requestId = (req as any).requestId || `req_${Date.now()}`;
  return res.status(statusCode).json({
    error: {
      code,
      message,
      requestId,
      ...(details ? { details } : {}),
    },
  });
}

/**
 * Responder for route catch blocks. A dependency outage (an error carrying
 * statusCode 503, e.g. DatabaseUnavailableError or PolarUnavailableError) keeps
 * its 503 and code; anything else becomes the route's masked 500.
 */
export function sendCaughtError(res: Response, err: unknown, code: string, message: string): Response {
  const e = err as { statusCode?: number; code?: unknown; message?: string } | null;
  if (e?.statusCode === 503 && typeof e.code === 'string') {
    return sendError(res, 503, e.code, e.message || 'A required service is temporarily unavailable.');
  }
  return sendError(res, 500, code, message);
}

/**
 * Status, code and message to send for a caught error. Runtime results carry `statusCode`;
 * CryptoEngineError carries `status`. Unexpected 500s get a generic code and message so
 * internals never reach the client.
 */
export function publicError(
  err: any,
  fallbackMessage: string
): { status: number; code: string; message: string } {
  const status = Number(err?.statusCode || err?.status) || 500;
  if (status === 500) {
    console.error('[API Error]:', err);
    return { status, code: 'INTERNAL_ERROR', message: fallbackMessage };
  }
  return { status, code: err?.code || 'INTERNAL_ERROR', message: err?.message || fallbackMessage };
}

/**
 * Centralized API Error Mapper that converts internal exceptions into clean, safe public errors.
 * Guarantees zero secret, private key, stack trace, or database connection string leakage.
 */
export function apiErrorHandler(
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const requestId = (req as any).requestId || `req_${Date.now()}`;
  console.error(`[API Error] [${requestId}]:`, err?.message || err);

  const status = err.status || err.statusCode || 500;
  let code = err.code || 'INTERNAL_ERROR';
  let message = err.message || 'An unexpected error occurred.';

  // Map known error signatures safely
  if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
    code = 'UNAUTHENTICATED';
    message = 'Invalid or expired token.';
  } else if (err.name === 'ValidationError' || err.code === 'P2002') {
    code = 'VALIDATION_FAILED';
    message = 'Request validation failed or conflict with existing resource.';
  } else if (status === 404) {
    code = err.code || 'RESOURCE_NOT_FOUND';
  } else if (status === 403) {
    code = err.code || 'FORBIDDEN';
  } else if (status === 401) {
    code = err.code || 'UNAUTHENTICATED';
  } else if (status === 429) {
    code = 'RATE_LIMITED';
  } else if (status >= 500) {
    // Mask raw internal errors to prevent leakage of paths, credentials, or SQL
    code = 'INTERNAL_ERROR';
    message = 'An internal cryptographic service error occurred. Please contact support with the requestId.';
  }

  res.status(status).json({
    error: {
      code,
      message,
      requestId,
    },
  });
}
