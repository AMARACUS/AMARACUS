# AMARACUS

**A cryptographic control plane you can run yourself.** Managed keys with versions and rotation, envelope
encryption, signing, hashing, post-quantum key encapsulation and signatures (ML-KEM, ML-DSA), a small PKI,
policies, an audit log, organizations with scoped API keys, and a web console, behind one HTTP API.

> **Source-available, not open source.** AMARACUS is published under the
> [PolyForm Shield License 1.0.0](LICENSE) **together with** the
> [AMARACUS Additional Commercial Terms](AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md). It is not licensed under
> an OSI-approved licence. Read both documents before you use it; the installation asks you to accept them.

## Two ways to use AMARACUS

| | Self-hosted (this repository) | AMARACUS Cloud |
| --- | --- | --- |
| Who runs it | You, on your own servers or cloud accounts | AMARACUS, at [amaracus.tech](https://amaracus.tech) |
| Infrastructure and credentials | Yours: database, email, Azure, storage | AMARACUS's |
| Price | 10,000 operations free for life, then USD 0.15 per 1,000 | Starter, Pro, Business or Pay As You Go |
| Free plan | The 10,000-operation lifetime allowance | None |
| Data and keys | Never leave your infrastructure | Held by AMARACUS Cloud |

The self-hosted allowance and licence keys do not carry over to Cloud, and Cloud plans do not cover
self-hosted use. Full prices: [AMARACUS-PRICING.md](AMARACUS-PRICING.md).

### Self-hosted: 10,000 operations free for life, then paid

- The first **10,000 successful billable cryptographic operations** are free, **once, for the lifetime** of
  your corporate group. The allowance is cumulative, not monthly.
- It is the same for individuals, students, startups, companies, banks and enterprises.
- **One corporate group, one allowance**: every employee, subsidiary, affiliate, project, environment,
  installation and server shares it. Reinstalling or adding servers does not reset it.
- From operation **10,001**, operations are paid for at **USD 0.15 per 1,000** (the Cloud Pay As You Go
  rate), by buying a licence key and adding it in the console (**Billing**). Teams can instead buy a
  **Team licence**: USD 1,200 a year for 10,000,000 operations and email support.
- Billable operations are defined precisely in section 5 of the
  [Additional Commercial Terms](AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md). Failed operations, health checks,
  console visits and idempotent retries are not counted.

**The built-in limit, disclosed:** when an installation's ledger reaches its allowance (10,000 plus any
licence keys), new protective operations (encrypt, sign, wrap, key generation and similar) return
`402 SELF_HOST_LICENSE_REQUIRED`. **Decrypt, unwrap, decapsulate and verify always keep working**, so data
you protected earlier is never locked away. The limit runs entirely on your own systems.

### AMARACUS Cloud: four plans

Starter (USD 9/month, 50,000 operations), Pro (USD 49/month, 500,000), Business (USD 299/month, 3,000,000),
each also yearly with two months free, and Pay As You Go (USD 0.15 per 1,000). There is no hosted free plan. Sign up at
[amaracus.tech](https://amaracus.tech).

## No telemetry

- The software sends **nothing** to AMARACUS: no usage, logs, keys, data, configuration or identity.
- No hidden tracking, no undisclosed outbound requests, no remote kill switch, no backdoor.
- It connects only to services **you** configure: your Postgres, your email provider, your Azure Key Vault or
  Managed HSM, and webhook endpoints your users register.
- Licence keys are verified offline against a public key in the code.
- You keep your own **usage ledger**: an append-only, hash-chained table in your database. You can verify and
  export it from the console. It is tamper-evident, not tamper-proof: whoever controls a server can change
  what runs on it. That is why the licence makes accurate records a legal obligation and gives AMARACUS a
  right to a usage statement and, with confidentiality safeguards, an independent audit (sections 6 and 7 of
  the terms). There are no routine reports.

## Competition restriction

You may use AMARACUS for anything except **offering a product that competes with AMARACUS**: for example a
rebranded fork, a fork with a feature or two added, a KMS, a cryptographic control plane or a managed
cryptographic API built from this code, including rewrites in other languages or behind other interfaces.
Using AMARACUS inside your own bank, company or application is fine. Building a competitor from scratch
without this code is fine. Details and examples: [AMARACUS-COMPETITION-POLICY.md](AMARACUS-COMPETITION-POLICY.md).

## Architecture

```
Browser ──> web console (apps/web, Next.js; static export or Node server)
               │  fetch, absolute URL (NEXT_PUBLIC_API_URL)
               ▼
            API (apps/api, Express, Node 20+) ──> PostgreSQL (Prisma; keys, versions, audit, usage ledger)
               │
               ├── crypto engine (packages/crypto-core): Node crypto + @noble, policies, key resolver
               ├── key providers: LOCAL (wrapped by your master key) │ Azure Key Vault │ Azure Managed HSM
               ├── customer BYOK: each organization's own Azure vault, with its own credentials
               ├── email: Resend or any SMTP server (yours)
               └── outbound webhooks to endpoints your users register
```

- **Control plane**: organizations, projects, environments, members and roles, scoped API keys (with
  optional IP allowlists), key lifecycle (create, rotate, disable, revoke, destroy), policies, audit log.
- **Data plane**: `/v1/encrypt`, `/v1/decrypt`, `/v1/sign`, `/v1/verify`, `/v1/hash`, `/v1/pqc/*`,
  `/v1/pki/*`, advanced (preview) schemes under `/v1/advanced/*`.
- **Key custody**: each key version is stored encrypted under your master key (`AMARACUS_LOCAL_MASTER_KEY`, or
  sealed by a key in your Azure Key Vault). With the Azure providers, data keys are wrapped inside your vault
  or HSM. The master key is used in the API process; it is not an HSM boundary.
- **Honest limits**: the cryptography runs on Node.js `crypto` and the `@noble` libraries. It is **not** a
  FIPS 140-3 validated module, has no security certification and has not had an independent security audit.
  Zero-knowledge, FHE, MPC and threshold features are previews.

**Cloud providers.** Azure Key Vault and Azure Managed HSM are supported as key providers. There is no
AWS KMS or AWS CloudHSM provider in this version. AMARACUS runs on AWS (EC2, ECS, EKS, RDS for Postgres),
Azure, Google Cloud or your own hardware like any Node.js service with Postgres.

## Install

Requirements: Docker with Compose, **or** Node.js 20+ with pnpm 10.22 and PostgreSQL 14+.

```bash
cp .env.example .env      # fill in your own values
docker compose up -d --build
```

Then open the console (port 3000), create an account, and accept the two licences on the activation screen.
The full guide, including email, Azure, migrations, backups, upgrades and troubleshooting, is
[SELF_HOSTING.md](SELF_HOSTING.md).

## Repository layout

| Path | What it is |
| --- | --- |
| `apps/api` | Express API (TypeScript) |
| `apps/web` | Next.js web console |
| `packages/crypto-core` | Cryptographic engine, key providers, policy engine |
| `packages/database` | Prisma schema and SQL migrations |
| `packages/sdk-ts`, `packages/sdk-py`, `packages/cli` | Client SDKs and CLI (Apache-2.0) |
| `examples/` | Integration examples |

The client SDKs and CLI default to AMARACUS Cloud's API address. Point them at your own API with their
`baseUrl` option (or `--base-url` / `AMARACUS_BASE_URL` for the CLI).

## Development and tests

```bash
pnpm install
pnpm --filter @amaracus/types --filter @amaracus/crypto-core --filter @amaracus/database --filter @amaracus/sdk build
cd apps/api && NODE_ENV=test npx jest --ci
```

Tests run in memory, never send email and make no outbound requests.

## Licensing in one paragraph

Both documents apply to every copy, modification and fork: [LICENSE](LICENSE) (PolyForm Shield 1.0.0,
unmodified) and [AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md](AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md). If you
redistribute, pass on both, plus [NOTICE](NOTICE). How the two fit together, and what has not been tested in
court, is explained in [docs/LICENSING.md](docs/LICENSING.md). Commercial licensing and licence keys:
legal@amaracus.tech.

## No guarantee of continued maintenance

AMARACUS is provided "as is" and "as available". The maintainers are not obliged to keep developing it,
maintain this repository, release updates or security patches, fix bugs, keep compatibility with future
platforms, provide support, keep downloads available, or keep operating AMARACUS Cloud. Keep your own copy of
the source, your own backups and your own key-recovery procedures. Section 12 of the
[Additional Commercial Terms](AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md) has the full text, including its
limits under mandatory law.

## More

[SELF_HOSTING.md](SELF_HOSTING.md) · [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md) ·
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [CHANGELOG.md](CHANGELOG.md) ·
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
