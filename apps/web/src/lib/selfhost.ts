/** Types for the self-hosted edition endpoints (GET/POST /v1/selfhost/*). */

export interface SelfHostLicenseRef {
  title: string;
  sha256: string;
}

export interface SelfHostAcceptance {
  acceptedAt: string;
  acceptedByEmail: string;
  licensee: string;
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

export interface SelfHostLicenseKey {
  licenseId: string;
  licensee: string;
  operations: number;
  issuedAt: string;
  addedAt: string;
}

export interface SelfHostStatus {
  edition: 'selfhosted';
  activated: boolean;
  licenses: {
    shield: SelfHostLicenseRef;
    commercial: SelfHostLicenseRef & { version: string };
  };
  acceptance: SelfHostAcceptance | null;
  usage?: SelfHostUsage;
  licenseKeys?: SelfHostLicenseKey[];
}

export interface SelfHostLicenseTexts {
  shield: { title: string; text: string; sha256: string };
  commercial: { title: string; version: string; text: string; sha256: string };
}

export interface SelfHostLedgerEntry {
  seq: number;
  timestamp: string;
  organizationId: string;
  operationId: string;
  operationType: string;
  quantity: number;
  cumulativeTotal: number;
  prevHash: string;
  entryHash: string;
}

export interface SelfHostLedgerPage {
  entries: SelfHostLedgerEntry[];
  head: { seq: number; cumulativeTotal: number; entryHash: string } | null;
}

export interface SelfHostLedgerVerification {
  valid: boolean;
  entriesChecked: number;
  cumulativeTotal: number;
  firstBrokenSeq: number | null;
}
