# Security policy

## Reporting a vulnerability

Email **security@amaracus.tech** with a description, the affected version or commit, and steps to reproduce.
Please do not open a public issue for a vulnerability and do not test against other people's installations
or against AMARACUS Cloud without written permission.

We aim to acknowledge reports within 5 working days. We do not promise a fix time, a bounty or continued
maintenance (see section 12 of the
[AMARACUS Additional Commercial Terms](AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md)). Fixes, when released, are
listed in [CHANGELOG.md](CHANGELOG.md).

## What AMARACUS does and does not claim

- The cryptography uses Node.js `crypto` and the `@noble` libraries. AMARACUS is **not** a FIPS 140-3
  validated module.
- AMARACUS has **no** security certification and has **not** had an independent security audit.
- Key material of the default provider is wrapped by a master key used inside the API process; that is not
  an HSM boundary. The Azure Key Vault and Managed HSM providers wrap data keys inside the vault.
- Zero-knowledge, FHE, MPC and threshold features are previews and are not for production.
- The self-hosted usage ledger is tamper-evident, not tamper-proof.

## Operating a self-hosted installation securely

See section 15 of [SELF_HOSTING.md](SELF_HOSTING.md).

## Rules for contributors

- Never commit secrets, credentials, private keys, `.env` files, database dumps or personal data.
- Validate every API input and enforce authorization in the API, per organization.
- Never store key material or secrets in plain text in the database.
- Never add telemetry, outbound requests to AMARACUS, tracking or a remote kill switch.
- Add tests for security-relevant changes, including tenant isolation.
