# Changelog

All notable changes to self-hosted AMARACUS. Dates are UTC.

## 1.0.0 (unreleased): first source-available release

### Licensing
- Published under the PolyForm Shield License 1.0.0 (unmodified) together with the AMARACUS Additional
  Commercial Terms 1.0.0. Source-available, not OSI open source.
- Client SDKs and CLI (`packages/sdk-ts`, `packages/sdk-py`, `packages/cli`) stay under Apache-2.0.

### Self-hosted edition
- `AMARACUS_EDITION=selfhosted`: runs entirely on customer infrastructure with customer credentials. No
  telemetry and no requests to AMARACUS.
- Activation screen: an administrator accepts both licence documents before any cryptographic operation runs;
  the acceptance and the SHA-256 of each text are stored locally.
- Usage ledger: append-only, hash-chained record of billable operations in the customer's database, with
  verification and JSON Lines export in the console.
- Lifetime allowance of 1,000 free operations, then offline-verified licence keys. Decrypt, unwrap,
  decapsulate and verify are never blocked.
- Start-up validation rejects missing configuration, placeholder secrets and AMARACUS-owned addresses.
- Docker Compose for Postgres, API and console; `SELF_HOSTING.md`.

### Removed from the public source
- AMARACUS Cloud billing (subscriptions, checkout, payment webhooks), hosted-site pages (marketing, legal,
  hackathon, reviews), hosted agents and AMARACUS's deployment configuration.
