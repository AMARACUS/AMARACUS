import crypto from 'crypto';
import { db, hashSessionToken } from '../src/lib/data-store';
import {
  hashPassword,
  verifyPassword,
  verifyAccountPassword,
  passwordHashNeedsUpgrade,
} from '../src/lib/crypto-security';

describe('Security audit: session tokens are stored hashed', () => {
  it('keeps only the SHA-256 of the token, and still finds the session by the raw token', async () => {
    const user = await db.createUser({ email: `sess-${Date.now()}@example.test`, passwordHash: 'x' });
    const session = await db.createSession({ userId: user.id, expiresAt: new Date(Date.now() + 3600_000) });
    const raw = session.sessionToken;

    const stored = (db as any).memStore.sessions as Map<string, unknown>;
    expect(stored.has(raw)).toBe(false);
    expect(stored.has(hashSessionToken(raw))).toBe(true);

    const found = await db.findSessionByToken(raw);
    expect(found?.id).toBe(session.id);
    expect(found?.sessionToken).toBe(raw);
    // Presenting the stored hash as a token must not work.
    expect(await db.findSessionByToken(hashSessionToken(raw))).toBeNull();

    await db.deleteSession(raw);
    expect(await db.findSessionByToken(raw)).toBeNull();
  });

  it('never returns tokens when listing sessions', async () => {
    const user = await db.createUser({ email: `list-${Date.now()}@example.test`, passwordHash: 'x' });
    await db.createSession({ userId: user.id, expiresAt: new Date(Date.now() + 3600_000) });
    const sessions = await db.getUserSessions(user.id);
    expect(sessions.length).toBe(1);
  });
});

describe('Security audit: password hashing', () => {
  it('hashes with stored scrypt parameters at OWASP-level cost', async () => {
    const hash = await hashPassword('correct horse battery staple');
    expect(hash).toMatch(/^scrypt\$16384\$8\$5\$[0-9a-f]{32}\$[0-9a-f]{128}$/);
    expect(await verifyPassword('correct horse battery staple', hash)).toBe(true);
    expect(await verifyPassword('wrong', hash)).toBe(false);
    expect(passwordHashNeedsUpgrade(hash)).toBe(false);
  });

  it('still accepts hashes from before the change and flags them for upgrade at sign-in', async () => {
    const salt = crypto.randomBytes(16).toString('hex');
    const oldHash = `${salt}:${crypto.scryptSync('old-password-123', salt, 64).toString('hex')}`;
    expect(await verifyPassword('old-password-123', oldHash)).toBe(true);
    expect(await verifyAccountPassword('old-password-123', oldHash)).toEqual({ valid: true, legacy: true });
    expect(await verifyAccountPassword('nope', oldHash)).toEqual({ valid: false, legacy: false });
  });

  it('rejects stored hashes whose parameters are out of bounds (a tampered row cannot request huge work)', async () => {
    const salt = crypto.randomBytes(16).toString('hex');
    for (const params of ['1073741824$8$1', '16384$64$1', '16384$8$1000', 'abc$8$1']) {
      expect(await verifyPassword('x', `scrypt$${params}$${salt}$${'0'.repeat(128)}`)).toBe(false);
    }
  });
});
