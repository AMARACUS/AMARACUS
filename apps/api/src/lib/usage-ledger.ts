import crypto from 'crypto';
import { prisma } from '@amaracus/database';
import { isTestEnv } from './runtime-config';

/**
 * Self-hosted usage ledger.
 *
 * Every billable cryptographic operation of a self-hosted installation is appended here, once
 * (the operation ID is unique, so an idempotent retry adds nothing). Each entry carries the
 * running lifetime total and the SHA-256 of the previous entry, so a removed, reordered or
 * edited entry breaks the chain and `verifyLedger` reports where.
 *
 * Limits, stated plainly: this is tamper-EVIDENT, not tamper-proof. Whoever controls the
 * server and database can rebuild the whole chain or run modified code. The ledger is the
 * customer's own record under the AMARACUS Additional Commercial Terms; nothing in it is
 * ever sent to AMARACUS by this software.
 */

export const LEDGER_GENESIS_HASH = '0'.repeat(64);
/** Arbitrary constant: serializes appends so the chain has one writer at a time. */
const LEDGER_ADVISORY_LOCK = 7420016;

export interface LedgerEntry {
  seq: number;
  timestamp: Date;
  organizationId: string;
  operationId: string;
  operationType: string;
  quantity: number;
  cumulativeTotal: number;
  prevHash: string;
  entryHash: string;
}

export interface LedgerAppendInput {
  organizationId: string;
  operationId: string;
  operationType: string;
  quantity: number;
  timestamp?: Date;
}

export interface LedgerVerification {
  valid: boolean;
  entriesChecked: number;
  cumulativeTotal: number;
  firstBrokenSeq: number | null;
}

export function computeEntryHash(e: Omit<LedgerEntry, 'seq' | 'entryHash'>): string {
  const canonical = [
    e.prevHash,
    new Date(e.timestamp).toISOString(),
    e.organizationId,
    e.operationId,
    e.operationType,
    String(e.quantity),
    String(e.cumulativeTotal),
  ].join('|');
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/** Checks a run of entries, oldest first, starting from the given previous hash and total. */
export function verifyEntries(
  entries: LedgerEntry[],
  startPrevHash: string = LEDGER_GENESIS_HASH,
  startTotal = 0
): LedgerVerification {
  let prevHash = startPrevHash;
  let total = startTotal;
  let checked = 0;
  for (const e of entries) {
    const expectedTotal = total + e.quantity;
    const ok =
      e.prevHash === prevHash &&
      e.quantity > 0 &&
      e.cumulativeTotal === expectedTotal &&
      e.entryHash === computeEntryHash(e);
    if (!ok) {
      return { valid: false, entriesChecked: checked, cumulativeTotal: total, firstBrokenSeq: e.seq };
    }
    prevHash = e.entryHash;
    total = expectedTotal;
    checked++;
  }
  return { valid: true, entriesChecked: checked, cumulativeTotal: total, firstBrokenSeq: null };
}

function fromRow(row: any): LedgerEntry {
  return {
    seq: Number(row.seq),
    timestamp: new Date(row.timestamp),
    organizationId: row.organizationId,
    operationId: row.operationId,
    operationType: row.operationType,
    quantity: Number(row.quantity),
    cumulativeTotal: Number(row.cumulativeTotal),
    prevHash: row.prevHash,
    entryHash: row.entryHash,
  };
}

/** Test-runner store. Outside tests Postgres is the only store. */
const memory: LedgerEntry[] = [];

export function resetLedgerForTests(): void {
  if (!isTestEnv()) throw new Error('resetLedgerForTests is only available under the test runner.');
  memory.length = 0;
}

/** Test helper: direct access to the in-memory rows, to simulate tampering. */
export function ledgerMemoryForTests(): LedgerEntry[] {
  if (!isTestEnv()) throw new Error('ledgerMemoryForTests is only available under the test runner.');
  return memory;
}

export async function appendLedgerEntry(input: LedgerAppendInput): Promise<{ created: boolean; entry: LedgerEntry }> {
  const quantity = Math.max(1, Math.floor(input.quantity || 1));
  // Millisecond precision, the same as the database column, so the hash is reproducible.
  const timestamp = new Date(Math.floor((input.timestamp || new Date()).getTime()));

  if (isTestEnv()) {
    const existing = memory.find((e) => e.operationId === input.operationId);
    if (existing) return { created: false, entry: existing };
    const head = memory[memory.length - 1];
    const base = {
      timestamp,
      organizationId: input.organizationId,
      operationId: input.operationId,
      operationType: input.operationType,
      quantity,
      cumulativeTotal: (head?.cumulativeTotal || 0) + quantity,
      prevHash: head?.entryHash || LEDGER_GENESIS_HASH,
    };
    const entry: LedgerEntry = { seq: (head?.seq || 0) + 1, ...base, entryHash: computeEntryHash(base) };
    memory.push(entry);
    return { created: true, entry };
  }

  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(${LEDGER_ADVISORY_LOCK})`;
    const existing = await tx.usageLedgerEntry.findUnique({ where: { operationId: input.operationId } });
    if (existing) return { created: false, entry: fromRow(existing) };
    const head = await tx.usageLedgerEntry.findFirst({ orderBy: { seq: 'desc' } });
    const base = {
      timestamp,
      organizationId: input.organizationId,
      operationId: input.operationId,
      operationType: input.operationType,
      quantity,
      cumulativeTotal: Number(head?.cumulativeTotal || 0) + quantity,
      prevHash: head?.entryHash || LEDGER_GENESIS_HASH,
    };
    const created = await tx.usageLedgerEntry.create({
      data: { ...base, cumulativeTotal: BigInt(base.cumulativeTotal), entryHash: computeEntryHash(base) },
    });
    return { created: true, entry: fromRow(created) };
  });
}

export async function getLedgerHead(): Promise<LedgerEntry | null> {
  if (isTestEnv()) return memory[memory.length - 1] || null;
  const head = await prisma.usageLedgerEntry.findFirst({ orderBy: { seq: 'desc' } });
  return head ? fromRow(head) : null;
}

/** Lifetime billable operations recorded by this installation. */
export async function getLifetimeOperations(): Promise<number> {
  return (await getLedgerHead())?.cumulativeTotal || 0;
}

export async function listLedgerEntries(afterSeq = 0, limit = 100): Promise<LedgerEntry[]> {
  const take = Math.min(Math.max(1, limit), 5000);
  if (isTestEnv()) return memory.filter((e) => e.seq > afterSeq).slice(0, take);
  const rows = await prisma.usageLedgerEntry.findMany({
    where: { seq: { gt: BigInt(afterSeq) } },
    orderBy: { seq: 'asc' },
    take,
  });
  return rows.map(fromRow);
}

/** Walks the whole chain in pages and reports the first entry that does not fit. */
export async function verifyLedger(): Promise<LedgerVerification> {
  let afterSeq = 0;
  let prevHash = LEDGER_GENESIS_HASH;
  let total = 0;
  let checked = 0;
  for (;;) {
    const page = await listLedgerEntries(afterSeq, 5000);
    if (page.length === 0) break;
    const result = verifyEntries(page, prevHash, total);
    checked += result.entriesChecked;
    total = result.cumulativeTotal;
    if (!result.valid) {
      return { valid: false, entriesChecked: checked, cumulativeTotal: total, firstBrokenSeq: result.firstBrokenSeq };
    }
    const last = page[page.length - 1];
    prevHash = last.entryHash;
    afterSeq = last.seq;
  }
  return { valid: true, entriesChecked: checked, cumulativeTotal: total, firstBrokenSeq: null };
}
