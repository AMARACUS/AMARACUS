import express from 'express';
import http from 'http';
import { AddressInfo } from 'net';
import { resolveTrustProxyHops } from '../src/lib/runtime-config';

describe('Phase 7: trust proxy hops', () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
  });

  it('does not trust X-Forwarded-For under the test runner by default', () => {
    delete process.env.TRUST_PROXY_HOPS;
    expect(resolveTrustProxyHops()).toBe(false);
  });

  it('uses TRUST_PROXY_HOPS when set, and 0 means off', () => {
    process.env.TRUST_PROXY_HOPS = '2';
    expect(resolveTrustProxyHops()).toBe(2);
    process.env.TRUST_PROXY_HOPS = '0';
    expect(resolveTrustProxyHops()).toBe(false);
  });

  it('rejects nonsense values instead of trusting every hop', () => {
    for (const bad of ['true', '-1', '1.5', '99']) {
      process.env.TRUST_PROXY_HOPS = bad;
      expect(() => resolveTrustProxyHops()).toThrow(/TRUST_PROXY_HOPS/);
    }
  });

  it('with 2 hops, req.ip is the client even when the client forges an extra entry', async () => {
    const app = express();
    app.set('trust proxy', 2);
    app.get('/ip', (req, res) => res.json({ ip: req.ip }));
    const server = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    try {
      const { port } = server.address() as AddressInfo;
      // forged, client (added by Cloudflare), Cloudflare edge (added by Render)
      const res = await fetch(`http://127.0.0.1:${port}/ip`, {
        headers: { 'X-Forwarded-For': '6.6.6.6, 203.0.113.7, 172.68.1.1' },
      });
      expect((await res.json()).ip).toBe('203.0.113.7');
    } finally {
      server.close();
    }
  });
});
