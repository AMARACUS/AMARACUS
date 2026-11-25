import http from 'http';
import { Duplex } from 'stream';

export interface InProcessRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body?: unknown;
  /** The address the original connection came from, so req.ip is worked out exactly as for a direct call. */
  remoteAddress?: string;
}

/** Runs one request through an HTTP handler (the Express app) without opening a connection. */
export function dispatchInProcess(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
  request: InProcessRequest,
  timeoutMs = 60_000
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const socket = new Duplex({ read() {}, write: (_chunk, _encoding, done) => done() });
    Object.defineProperty(socket, 'remoteAddress', { value: request.remoteAddress });

    const payload = request.body === undefined ? null : Buffer.from(JSON.stringify(request.body), 'utf8');
    const req = new http.IncomingMessage(socket as any);
    req.method = request.method;
    req.url = request.path;
    req.httpVersion = '1.1';
    req.httpVersionMajor = 1;
    req.httpVersionMinor = 1;
    req.headers = {
      host: 'localhost',
      ...request.headers,
      ...(payload ? { 'content-type': 'application/json', 'content-length': String(payload.length) } : {}),
    };
    req.rawHeaders = Object.entries(req.headers).flatMap(([name, value]) => [name, String(value)]);
    if (payload) req.push(payload);
    req.push(null);
    req.complete = true;

    const res = new http.ServerResponse(req);
    res.shouldKeepAlive = false;
    res.assignSocket(socket as any);

    // Own properties, so they survive Express swapping the response's prototype.
    const chunks: Buffer[] = [];
    const capture = (chunk: any, encoding: any) => {
      if (typeof chunk === 'string') chunks.push(Buffer.from(chunk, typeof encoding === 'string' ? (encoding as BufferEncoding) : 'utf8'));
      else if (chunk instanceof Uint8Array) chunks.push(Buffer.from(chunk));
    };
    const { write, end } = res;
    res.write = function (this: http.ServerResponse, ...args: any[]) {
      capture(args[0], args[1]);
      return (write as any).apply(this, args);
    } as typeof res.write;
    res.end = function (this: http.ServerResponse, ...args: any[]) {
      capture(args[0], args[1]);
      return (end as any).apply(this, args);
    } as typeof res.end;

    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`${request.method} ${request.path.split('?')[0]} timed out`));
    }, timeoutMs);
    timer.unref();
    res.once('finish', () => {
      clearTimeout(timer);
      resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') });
      socket.destroy();
    });
    res.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });

    try {
      handler(req, res);
    } catch (err) {
      clearTimeout(timer);
      reject(err);
    }
  });
}
