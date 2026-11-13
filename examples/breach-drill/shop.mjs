/**
 * A small demo shop that keeps customer details encrypted with AMARACUS.
 *
 * Each personal field (name, email, phone, address) is sent to POST /v1/encrypt and
 * only the returned envelope is stored. The customer id and field name are bound to
 * each envelope as additional authenticated data (AAD), so an envelope copied into
 * another row or field will not decrypt. If AMARACUS cannot be reached, the shop
 * refuses to save rather than storing plain text ("fail closed").
 *
 * NaiveShop stores the same data in plain text, for comparison in the drill.
 * Uses Node's built-in SQLite (Node 22.5 or later).
 */
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';

const FIELDS = ['name', 'email', 'phone', 'address'];

export class AmaracusClient {
  /** sourceIp: drill only, sent as X-Forwarded-For to play a given machine. */
  constructor({ baseUrl, apiKey, timeoutMs = 5000, sourceIp }) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
    this.sourceIp = sourceIp;
  }

  async call(path, body) {
    let res;
    try {
      res = await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
          ...(this.sourceIp ? { 'X-Forwarded-For': this.sourceIp } : {}),
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      const e = new Error(`AMARACUS unreachable: ${err.cause?.code || err.name || err.message}`);
      e.status = 0;
      throw e;
    }
    const json = await res.json().catch(() => ({}));
    if (!res.ok) {
      const e = new Error(`AMARACUS ${path} returned ${res.status} ${json?.error?.code || ''}`.trim());
      e.status = res.status;
      e.code = json?.error?.code;
      throw e;
    }
    return json.data;
  }

  async encrypt(keyId, plaintext, aad) {
    const data = await this.call('/v1/encrypt', { key: keyId, data: plaintext, aad });
    return data.envelope;
  }

  async decrypt(keyId, envelope, expectedAad) {
    // /v1/decrypt uses the AAD stored inside a string envelope and ignores an "aad" sent
    // alongside it, so the app checks the envelope's AAD itself before decrypting.
    if (expectedAad !== undefined && envelopeAad(envelope) !== expectedAad) {
      const e = new Error('Envelope belongs to a different record (AAD mismatch); refusing to decrypt');
      e.status = 0;
      e.code = 'AAD_MISMATCH';
      throw e;
    }
    const data = await this.call('/v1/decrypt', { key: keyId, envelope, aad: expectedAad });
    return data.plaintext;
  }
}

/** The AAD that ties an envelope to one customer and one field. */
export const aadFor = (customerId, field) => `customer:${customerId}:${field}`;

/** Reads the AAD out of an AMARACUS envelope (base64 JSON whose "aad" is base64url). */
export function envelopeAad(envelope) {
  try {
    const parsed = JSON.parse(Buffer.from(envelope, 'base64').toString('utf8'));
    return parsed.aad === undefined || parsed.aad === null ? undefined : Buffer.from(parsed.aad, 'base64url').toString('utf8');
  } catch {
    return undefined;
  }
}

export class Shop {
  /**
   * @param writer client used when customers sign up (needs only crypto:encrypt)
   * @param reader client used by staff screens that show details (needs crypto:decrypt)
   */
  constructor({ dbPath, keyId, writer, reader }) {
    this.db = new DatabaseSync(dbPath);
    this.keyId = keyId;
    this.writer = writer;
    this.reader = reader;
    this.db.exec(`CREATE TABLE IF NOT EXISTS customers (
      id TEXT PRIMARY KEY, name TEXT, email TEXT, phone TEXT, address TEXT, created_at TEXT)`);
  }

  async addCustomer(customer) {
    const id = crypto.randomUUID();
    const sealed = {};
    // Encrypt every field first: if any call fails, nothing is written.
    for (const field of FIELDS) {
      sealed[field] = await this.writer.encrypt(this.keyId, customer[field], aadFor(id, field));
    }
    this.db
      .prepare('INSERT INTO customers (id, name, email, phone, address, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, sealed.name, sealed.email, sealed.phone, sealed.address, new Date().toISOString());
    return id;
  }

  async getCustomer(id) {
    const row = this.db.prepare('SELECT * FROM customers WHERE id = ?').get(id);
    if (!row) return null;
    const out = { id };
    for (const field of FIELDS) out[field] = await this.reader.decrypt(this.keyId, row[field], aadFor(id, field));
    return out;
  }

  count() {
    return this.db.prepare('SELECT COUNT(*) AS n FROM customers').get().n;
  }

  close() {
    this.db.close();
  }
}

export class NaiveShop {
  constructor({ dbPath }) {
    this.db = new DatabaseSync(dbPath);
    this.db.exec(`CREATE TABLE IF NOT EXISTS customers (
      id TEXT PRIMARY KEY, name TEXT, email TEXT, phone TEXT, address TEXT, created_at TEXT)`);
  }

  addCustomer(c) {
    const id = crypto.randomUUID();
    this.db
      .prepare('INSERT INTO customers (id, name, email, phone, address, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, c.name, c.email, c.phone, c.address, new Date().toISOString());
    return id;
  }

  close() {
    this.db.close();
  }
}

/** Made-up customers. Deterministic, so a drill run can be repeated. */
export function fakeCustomers(n) {
  const first = ['Asha', 'Liam', 'Mei', 'Noah', 'Priya', 'Sofia', 'Omar', 'Elena', 'Ravi', 'Hannah'];
  const last = ['Kumar', 'Schmidt', 'Rossi', 'Novak', 'Haddad', 'Larsen', 'Moreau', 'Ito', 'Silva', 'Brennan'];
  const out = [];
  for (let i = 0; i < n; i++) {
    const f = first[i % first.length];
    const l = last[Math.floor(i / first.length) % last.length];
    out.push({
      name: `${f} ${l} ${i}`,
      email: `${f.toLowerCase()}.${l.toLowerCase()}${i}@drill-customer.example`,
      phone: `+49 151 ${String(5550000 + i).padStart(7, '0')}`,
      address: `${10 + i} Drill Street, Testville`,
    });
  }
  return out;
}
