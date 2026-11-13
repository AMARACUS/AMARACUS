import http from 'http';
import { AddressInfo } from 'net';
import express from 'express';
import uploadsRoutes from '../src/routes/uploads';
import { db } from '../src/lib/data-store';

// Mock auth middleware to provide authenticated session and test organization
jest.mock('../src/middleware/auth', () => ({
  requireAuth: (req: any, _res: any, next: any) => {
    req.user = { id: 'usr_test_upload', email: 'uploader@amaracus.dev' };
    next();
  },
  requireOrgMember: (req: any, _res: any, next: any) => {
    req.organizationId = req.params.orgId;
    next();
  },
}));

describe('Uploads HTTP API Integration', () => {
  let server: http.Server;
  let baseUrl: string;
  const orgId = 'org_test_uploads';

  beforeAll(async () => {
    const app = express();
    app.use(express.json());
    app.use('/v1/organizations/:orgId/uploads', uploadsRoutes);

    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  afterAll((done) => {
    if (server) {
      server.close(done);
    } else {
      done();
    }
  });

  it('successfully uploads a valid certificate file and stores it with inert identifier', async () => {
    const validPemContent = '-----BEGIN CERTIFICATE-----\nMIIB...sample...test\n-----END CERTIFICATE-----\n';
    const blob = new Blob([validPemContent], { type: 'application/x-pem-file' });
    const formData = new FormData();
    formData.append('file', blob, 'client-cert.pem');

    const res = await fetch(`${baseUrl}/v1/organizations/${orgId}/uploads`, {
      method: 'POST',
      body: formData,
    });

    expect(res.status).toBe(201);
    const body: any = await res.json();
    expect(body.data).toBeDefined();
    expect(body.data.upload).toBeDefined();
    expect(body.data.upload.fileName).toBe('client-cert.pem');
    expect(body.data.upload.sha256).toBeDefined();
    expect(body.data.upload.size).toBe(Buffer.byteLength(validPemContent));

    const uploadId = body.data.upload.id;

    // Verify it is listed in organization uploads
    const listRes = await fetch(`${baseUrl}/v1/organizations/${orgId}/uploads`);
    expect(listRes.status).toBe(200);
    const listBody: any = await listRes.json();
    expect(listBody.data.uploads.length).toBeGreaterThan(0);
    expect(listBody.data.uploads.some((u: any) => u.id === uploadId)).toBe(true);

    // Verify safe download headers
    const downloadRes = await fetch(`${baseUrl}/v1/organizations/${orgId}/uploads/${uploadId}/download`);
    expect(downloadRes.status).toBe(200);
    expect(downloadRes.headers.get('content-disposition')).toContain('attachment');
    expect(downloadRes.headers.get('content-disposition')).toContain('client-cert.pem');
    expect(downloadRes.headers.get('x-content-type-options')).toBe('nosniff');
    expect(downloadRes.headers.get('content-security-policy')).toBe("default-src 'none'; sandbox");
    const downloadText = await downloadRes.text();
    expect(downloadText).toBe(validPemContent);

    // Verify cleanup
    const delRes = await fetch(`${baseUrl}/v1/organizations/${orgId}/uploads/${uploadId}`, {
      method: 'DELETE',
    });
    expect(delRes.status).toBe(200);
    const delBody: any = await delRes.json();
    expect(delBody.data.deleted).toBe(true);
  });

  it('rejects an executable payload (.exe) with 400 Bad Request', async () => {
    const maliciousBytes = new Uint8Array([0x4D, 0x5A, 0x90, 0x00]); // MZ executable
    const blob = new Blob([maliciousBytes], { type: 'application/octet-stream' });
    const formData = new FormData();
    formData.append('file', blob, 'exploit.exe');

    const res = await fetch(`${baseUrl}/v1/organizations/${orgId}/uploads`, {
      method: 'POST',
      body: formData,
    });

    expect(res.status).toBe(400);
    const body: any = await res.json();
    expect(body.error).toBeDefined();
    expect(body.error.message).toMatch(/forbidden executable|not permitted/i);
  });

  it('rejects an executable disguised as a txt file via magic byte inspection', async () => {
    // Linux ELF header in a .txt file
    const fakeTxtBytes = new Uint8Array([0x7F, 0x45, 0x4C, 0x46, 0x65, 0x76, 0x69, 0x6C]);
    const blob = new Blob([fakeTxtBytes], { type: 'text/plain' });
    const formData = new FormData();
    formData.append('file', blob, 'innocent.txt');

    const res = await fetch(`${baseUrl}/v1/organizations/${orgId}/uploads`, {
      method: 'POST',
      body: formData,
    });

    expect(res.status).toBe(400);
    const body: any = await res.json();
    expect(body.error).toBeDefined();
    expect(body.error.message).toMatch(/Executable binary signature detected/i);
  });

  it('rejects zero-byte empty file uploads', async () => {
    const emptyBlob = new Blob([], { type: 'text/plain' });
    const formData = new FormData();
    formData.append('file', emptyBlob, 'empty.txt');

    const res = await fetch(`${baseUrl}/v1/organizations/${orgId}/uploads`, {
      method: 'POST',
      body: formData,
    });

    expect(res.status).toBe(400);
    const body: any = await res.json();
    expect(body.error).toBeDefined();
    expect(body.error.message).toMatch(/0 bytes/i);
  });
});
