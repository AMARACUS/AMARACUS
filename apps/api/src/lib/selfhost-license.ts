import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { prisma } from '@amaracus/database';
import { isTestEnv } from './runtime-config';
import { getLifetimeOperations } from './usage-ledger';
import { BILLING_PLANS } from './billing-plans';

/**
 * Self-hosted licensing: acceptance of the two licence documents, the lifetime free
 * allowance, and licence keys for use beyond it.
 *
 * Everything here is local. A licence key is verified offline against the public key below;
 * this module makes no network request and reports nothing to AMARACUS.
 *
 * The limit is disclosed (README, SELF_HOSTING.md, the Additional Commercial Terms) and it
 * never stops decryption, unwrapping or verification, so data protected earlier always stays
 * readable. It counts per installation; the legal allowance is per corporate group, which the
 * Additional Commercial Terms govern.
 */

/** Successful billable operations that are free, once, for the lifetime of the licensee. */
export const FREE_LIFETIME_OPERATIONS = 1000;

/** The self-hosted rate is the AMARACUS Cloud Pay As You Go rate. */
export const SELF_HOST_RATE_PER_1K_OPS_CENTS = BILLING_PLANS.PAYG.costPer1kOpsCents;
export const SELF_HOST_RATE_CURRENCY = 'USD';

export const SHIELD_TITLE = 'PolyForm Shield License 1.0.0';
export const COMMERCIAL_TITLE = 'AMARACUS Additional Commercial Terms';
const SHIELD_FILE = 'LICENSE';
const COMMERCIAL_FILE = 'AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md';

/**
 * Ed25519 public key (SPKI, base64) that AMARACUS licence keys are signed with. The private
 * key is held by AMARACUS and is not in any repository.
 */
const LICENSE_PUBLIC_KEY_SPKI_B64 = 'MCowBQYDK2VwAyEAhRl3lUX49+YPA0VvIivdVoL/rKg5pRoJlWRYbqRSgP8=';
const LICENSE_KEY_PREFIX = 'AMLIC1';

/** The embedded key, except under the test runner, where a test may supply its own signer. */
function defaultLicensePublicKey(): string {
  if (isTestEnv() && process.env.AMARACUS_TEST_LICENSE_PUBLIC_KEY) return process.env.AMARACUS_TEST_LICENSE_PUBLIC_KEY;
  return LICENSE_PUBLIC_KEY_SPKI_B64;
}

export interface LicenseDocument {
  title: string;
  text: string;
  sha256: string;
  version?: string;
}

export interface LicenseKeyPayload {
  /** Format version. */
  v: 1;
  licenseId: string;
  /** Legal name of the licensee (corporate group or individual). */
  licensee: string;
  /** Paid operations this key adds above the free allowance. */
  operations: number;
  issuedAt: string;
  expiresAt?: string | null;
}

export interface StoredLicenseKey {
  licenseId: string;
  licensee: string;
  operations: number;
  issuedAt: Date;
  expiresAt: Date | null;
  addedAt: Date;
}

export interface LicenseAcceptance {
  licensee: string;
  acceptedByUserId: string;
  acceptedByEmail: string;
  shieldSha256: string;
  commercialSha256: string;
  commercialVersion: string;
  ipAddress?: string | null;
  acceptedAt: Date;
}

export interface SelfHostUsage {
  lifetimeOperations: number;
  freeAllowance: number;
  licensedOperations: number;
  totalAllowance: number;
  remaining: number;
  licenseRequired: boolean;
  ratePer1kOpsCents: number;
  currency: string;
}

export class LicenseError extends Error {
  constructor(public code: string, message: string, public status = 400) {
    super(message);
  }
}

// ---------------------------------------------------------------------------
// Licence documents
// ---------------------------------------------------------------------------

let cachedDocs: { shield: LicenseDocument; commercial: LicenseDocument } | null = null;

function findLicenseDir(): string | null {
  const candidates: string[] = [];
  if (process.env.AMARACUS_LICENSE_DIR) candidates.push(process.env.AMARACUS_LICENSE_DIR);
  let dir = __dirname;
  for (let i = 0; i < 7; i++) {
    candidates.push(dir);
    dir = path.dirname(dir);
  }
  candidates.push(process.cwd());
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, SHIELD_FILE)) && fs.existsSync(path.join(c, COMMERCIAL_FILE))) return c;
  }
  return null;
}

function sha256(text: string): string {
  // Line endings are normalized so a checkout on Windows hashes the same as one on Linux.
  return crypto.createHash('sha256').update(text.replace(/\r\n/g, '\n'), 'utf8').digest('hex');
}

/** The two licence texts shipped with this source tree. Throws when they are missing. */
export function getLicenseDocuments(): { shield: LicenseDocument; commercial: LicenseDocument } {
  if (cachedDocs) return cachedDocs;
  const dir = findLicenseDir();
  if (!dir) {
    throw new LicenseError(
      'LICENSE_FILES_MISSING',
      `${SHIELD_FILE} and ${COMMERCIAL_FILE} were not found next to the application. They ship with the source; set AMARACUS_LICENSE_DIR to the folder that holds them.`,
      500
    );
  }
  const shieldText = fs.readFileSync(path.join(dir, SHIELD_FILE), 'utf8');
  const commercialText = fs.readFileSync(path.join(dir, COMMERCIAL_FILE), 'utf8');
  const version = /^\*{0,2}Version:?\*{0,2}:?\s*([0-9]+\.[0-9]+\.[0-9]+)/im.exec(commercialText)?.[1] || 'unversioned';
  cachedDocs = {
    shield: { title: SHIELD_TITLE, text: shieldText, sha256: sha256(shieldText) },
    commercial: { title: COMMERCIAL_TITLE, text: commercialText, sha256: sha256(commercialText), version },
  };
  return cachedDocs;
}

export function licenseFilesPresent(): boolean {
  return findLicenseDir() !== null;
}

// ---------------------------------------------------------------------------
// Acceptance
// ---------------------------------------------------------------------------

const mem = {
  acceptances: [] as LicenseAcceptance[],
  keys: [] as StoredLicenseKey[],
};

export function resetSelfHostLicenseForTests(): void {
  if (!isTestEnv()) throw new Error('resetSelfHostLicenseForTests is only available under the test runner.');
  mem.acceptances.length = 0;
  mem.keys.length = 0;
  cachedDocs = null;
}

/** The latest acceptance, or null when nobody has accepted the licences on this installation. */
export async function getAcceptance(): Promise<LicenseAcceptance | null> {
  if (isTestEnv()) return mem.acceptances[mem.acceptances.length - 1] || null;
  const row = await prisma.selfHostLicenseAcceptance.findFirst({ orderBy: { acceptedAt: 'desc' } });
  return row ? { ...row } : null;
}

/**
 * True when the current licence texts have been accepted. A changed text (new version of the
 * terms shipped with an upgrade) needs a new acceptance.
 */
export async function isActivated(): Promise<boolean> {
  const acceptance = await getAcceptance();
  if (!acceptance) return false;
  const docs = getLicenseDocuments();
  return acceptance.shieldSha256 === docs.shield.sha256 && acceptance.commercialSha256 === docs.commercial.sha256;
}

export async function recordAcceptance(input: {
  acceptShield: unknown;
  acceptCommercialTerms: unknown;
  licensee: unknown;
  shieldSha256: unknown;
  commercialSha256: unknown;
  userId: string;
  userEmail: string;
  ipAddress?: string | null;
}): Promise<LicenseAcceptance> {
  if (input.acceptShield !== true || input.acceptCommercialTerms !== true) {
    throw new LicenseError('ACCEPTANCE_INCOMPLETE', 'Both licence documents must be accepted.');
  }
  const licensee = typeof input.licensee === 'string' ? input.licensee.trim() : '';
  if (licensee.length < 2 || licensee.length > 200) {
    throw new LicenseError('LICENSEE_REQUIRED', 'Enter the legal name of the company, corporate group or person accepting the licences.');
  }
  const docs = getLicenseDocuments();
  if (input.shieldSha256 !== docs.shield.sha256 || input.commercialSha256 !== docs.commercial.sha256) {
    throw new LicenseError(
      'LICENSE_TEXT_MISMATCH',
      'The licence texts you were shown are not the ones shipped with this installation. Reload the page and read them again.',
      409
    );
  }
  const acceptance: LicenseAcceptance = {
    licensee,
    acceptedByUserId: input.userId,
    acceptedByEmail: input.userEmail,
    shieldSha256: docs.shield.sha256,
    commercialSha256: docs.commercial.sha256,
    commercialVersion: docs.commercial.version || 'unversioned',
    ipAddress: input.ipAddress || null,
    acceptedAt: new Date(),
  };
  if (isTestEnv()) {
    mem.acceptances.push(acceptance);
    return acceptance;
  }
  const row = await prisma.selfHostLicenseAcceptance.create({ data: acceptance });
  return { ...row };
}

// ---------------------------------------------------------------------------
// Licence keys
// ---------------------------------------------------------------------------

function b64urlDecode(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/**
 * Verifies a licence key offline. `publicKeySpkiB64` exists for tests; production code always
 * uses the embedded AMARACUS key.
 */
export function verifyLicenseKey(token: string, publicKeySpkiB64: string = defaultLicensePublicKey()): LicenseKeyPayload {
  const parts = String(token || '').trim().split('.');
  if (parts.length !== 3 || parts[0] !== LICENSE_KEY_PREFIX) {
    throw new LicenseError('INVALID_LICENSE_KEY', 'This is not an AMARACUS licence key.');
  }
  let payload: LicenseKeyPayload;
  let valid = false;
  try {
    const publicKey = crypto.createPublicKey({ key: Buffer.from(publicKeySpkiB64, 'base64'), format: 'der', type: 'spki' });
    valid = crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8'), publicKey, b64urlDecode(parts[2]));
    payload = JSON.parse(b64urlDecode(parts[1]).toString('utf8'));
  } catch {
    throw new LicenseError('INVALID_LICENSE_KEY', 'The licence key could not be read.');
  }
  if (!valid) {
    throw new LicenseError('INVALID_LICENSE_KEY', 'The licence key signature is not valid.');
  }
  if (
    payload?.v !== 1 ||
    typeof payload.licenseId !== 'string' ||
    !payload.licenseId ||
    typeof payload.licensee !== 'string' ||
    !Number.isSafeInteger(payload.operations) ||
    payload.operations <= 0 ||
    Number.isNaN(Date.parse(payload.issuedAt))
  ) {
    throw new LicenseError('INVALID_LICENSE_KEY', 'The licence key content is not valid.');
  }
  if (payload.expiresAt && Number.isNaN(Date.parse(payload.expiresAt))) {
    throw new LicenseError('INVALID_LICENSE_KEY', 'The licence key content is not valid.');
  }
  return payload;
}

/** Signs a licence key. Used by AMARACUS's private issuing tool and by tests. */
export function signLicenseKey(payload: LicenseKeyPayload, privateKeyPem: string | crypto.KeyObject): string {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signingInput = `${LICENSE_KEY_PREFIX}.${body}`;
  const key = typeof privateKeyPem === 'string' ? crypto.createPrivateKey(privateKeyPem) : privateKeyPem;
  const signature = crypto.sign(null, Buffer.from(signingInput, 'utf8'), key).toString('base64url');
  return `${signingInput}.${signature}`;
}

export async function listLicenseKeys(): Promise<StoredLicenseKey[]> {
  if (isTestEnv()) return [...mem.keys];
  const rows = await prisma.selfHostLicenseKey.findMany({ orderBy: { addedAt: 'asc' } });
  return rows.map((r) => ({
    licenseId: r.licenseId,
    licensee: r.licensee,
    operations: Number(r.operations),
    issuedAt: r.issuedAt,
    expiresAt: r.expiresAt,
    addedAt: r.addedAt,
  }));
}

export async function addLicenseKey(token: string, publicKeySpkiB64?: string): Promise<StoredLicenseKey> {
  const payload = verifyLicenseKey(token, publicKeySpkiB64);
  if (payload.expiresAt && new Date(payload.expiresAt) < new Date()) {
    throw new LicenseError('LICENSE_KEY_EXPIRED', 'This licence key has expired.');
  }
  const existing = (await listLicenseKeys()).find((k) => k.licenseId === payload.licenseId);
  if (existing) {
    throw new LicenseError('LICENSE_KEY_ALREADY_ADDED', 'This licence key has already been added to this installation.', 409);
  }
  const stored: StoredLicenseKey = {
    licenseId: payload.licenseId,
    licensee: payload.licensee,
    operations: payload.operations,
    issuedAt: new Date(payload.issuedAt),
    expiresAt: payload.expiresAt ? new Date(payload.expiresAt) : null,
    addedAt: new Date(),
  };
  if (isTestEnv()) {
    mem.keys.push(stored);
    return stored;
  }
  await prisma.selfHostLicenseKey.create({
    data: { ...stored, operations: BigInt(stored.operations), token: token.trim() },
  });
  return stored;
}

// ---------------------------------------------------------------------------
// Allowance
// ---------------------------------------------------------------------------

/**
 * Operations bought so far. A key keeps counting after its expiry date: operations that were
 * paid for are not taken back, an expired key just cannot be added to a new installation.
 */
export async function getLicensedOperations(): Promise<number> {
  return (await listLicenseKeys()).reduce((sum, k) => sum + k.operations, 0);
}

export async function getSelfHostUsage(): Promise<SelfHostUsage> {
  const [lifetimeOperations, licensedOperations] = await Promise.all([getLifetimeOperations(), getLicensedOperations()]);
  const totalAllowance = FREE_LIFETIME_OPERATIONS + licensedOperations;
  return {
    lifetimeOperations,
    freeAllowance: FREE_LIFETIME_OPERATIONS,
    licensedOperations,
    totalAllowance,
    remaining: Math.max(0, totalAllowance - lifetimeOperations),
    licenseRequired: lifetimeOperations >= totalAllowance,
    ratePer1kOpsCents: SELF_HOST_RATE_PER_1K_OPS_CENTS,
    currency: SELF_HOST_RATE_CURRENCY,
  };
}

/**
 * Operations that read or check data protected earlier. They are never blocked, with or
 * without a licence key, so a customer can always get their data back. They are still
 * billable operations and are recorded in the ledger.
 */
const RECOVERY_OPERATIONS = new Set([
  'decrypt',
  'unwrap',
  'unwrapkey',
  'unwrap-key',
  'unwrap_key',
  'verify',
  'decapsulate',
  'decaps',
  'open',
  'unseal',
]);

export function isRecoveryOperationName(name: unknown): boolean {
  if (typeof name !== 'string') return false;
  const n = name.trim().toLowerCase().replace(/^crypto[.:]/, '');
  if (RECOVERY_OPERATIONS.has(n)) return true;
  // Compound names such as "pqc-verify", "fhe_decrypt", "hmac.verify" or "zk-verify".
  const lastPart = n.split(/[-_.:/]/).pop() || '';
  return RECOVERY_OPERATIONS.has(lastPart);
}

/**
 * The operation a request performs, decided the way the route itself decides it: the last path
 * segment (for example /v1/decrypt or /keys/:id/verify), or, for the three generic dispatcher
 * routes, the one body field that route executes. Other body fields are ignored, so a caller
 * cannot label an encrypt call as "verify" to get past the gate.
 */
export function requestOperationName(req: { baseUrl?: string; path?: string; body?: any }): string {
  const full = `${req.baseUrl || ''}${req.path || ''}`.toLowerCase().replace(/\/+$/, '');
  const last = full.split('/').pop() || '';
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  // POST /v1/operations (routes/v1/operations.ts): body.type ?? body.operationType
  if (/\/operations$/.test(full) && /\/v1\/operations$/.test(full)) {
    return String(body.type ?? body.operationType ?? 'ENCRYPT');
  }
  // POST .../crypto/execute (routes/crypto.ts): body.type || body.operationType
  if (last === 'execute') return String(body.type || body.operationType || 'ENCRYPT');
  // POST .../keys/:keyId/operations (routes/byok.ts): body.operation
  if (last === 'operations') return String(body.operation || '');
  return last;
}

/** True for decrypt, unwrap, decapsulate and verify calls, which are never blocked. */
export function isRecoveryRequest(req: { baseUrl?: string; path?: string; body?: any }): boolean {
  return isRecoveryOperationName(requestOperationName(req));
}

/**
 * Under the test runner the gate is off unless a test turns it on, so suites that are not
 * about licensing run as before. It has no effect anywhere else.
 */
export function selfHostGateEnforced(): boolean {
  if (!isTestEnv()) return true;
  return process.env.AMARACUS_TEST_ENFORCE_SELFHOST_GATE === '1';
}
