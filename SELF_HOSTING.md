# Self-hosting AMARACUS

This guide runs AMARACUS entirely on infrastructure you control, with credentials you own. Nothing in it uses
AMARACUS Cloud, and the software makes no request to AMARACUS.

Before you start, read [LICENSE](LICENSE) and
[AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md](AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md). The installation asks
you to accept both before it runs any cryptographic operation.

Contents: [What you need](#1-what-you-need) · [Quick start with Docker](#2-quick-start-with-docker-compose) ·
[Manual install](#3-manual-install-without-docker) · [Configuration](#4-configuration) ·
[Database and migrations](#5-database-and-migrations) · [Accounts and administrators](#6-accounts-administrators-and-activation) ·
[Email](#7-email) · [Storage](#8-storage) · [Azure Key Vault and Managed HSM](#9-azure-key-vault-and-managed-hsm) ·
[AWS and other clouds](#10-aws-and-other-clouds) · [Licence keys and the usage ledger](#11-licence-keys-and-the-usage-ledger) ·
[Backups and recovery](#12-backups-and-recovery) · [Upgrades](#13-upgrades) ·
[Troubleshooting](#14-troubleshooting) · [Security recommendations](#15-security-recommendations)

---

## 1. What you need

| | Minimum |
| --- | --- |
| Runtime | Docker 24+ with Compose v2, **or** Node.js 20+ (24 tested) and pnpm 10.22 |
| Database | PostgreSQL 14+ (the Compose file runs 16). Any managed Postgres works: AWS RDS, Azure Database for PostgreSQL, Google Cloud SQL, Supabase, Neon, your own server |
| Email | A Resend account **or** any SMTP server, with a sender address on a domain you control |
| Network | HTTPS in front of the API and the console (a reverse proxy or load balancer) |
| Optional | An Azure subscription with a Key Vault or Managed HSM |

Build note: the web console's build downloads its fonts from Google Fonts (`next/font`). Builds need internet
access; the running console does not.

## 2. Quick start with Docker Compose

```bash
git clone <your copy of this repository> amaracus && cd amaracus
cp .env.example .env
```

Edit `.env`. At minimum set:

- `POSTGRES_PASSWORD`: a long random password for the bundled database.
- `API_SECRET`, `UNSUBSCRIBE_SECRET`, `AMARACUS_LOCAL_MASTER_KEY`: each one generated with
  `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"` (or `openssl rand -base64 32`).
- `APP_URL` and `NEXT_PUBLIC_APP_URL`: the public URL of your console, e.g. `https://kms.example.com`.
- `API_URL` and `NEXT_PUBLIC_API_URL`: the public URL of your API, e.g. `https://kms-api.example.com`.
  For a first try on one machine use `http://localhost:3000` and `http://localhost:4000`.
- `PLATFORM_ADMIN_EMAILS`: your own email address.
- Email: `RESEND_API_KEY` + `EMAIL_FROM_DEFAULT`, **or** `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`,
  `SMTP_FROM` (see [Email](#7-email)).

You can leave `DATABASE_URL` and `DIRECT_URL` as they are: Compose sets them for its own database.

```bash
docker compose up -d --build
docker compose logs -f api
```

The `migrate` service applies the database migrations and exits; then the API starts. You should see:

```
[Amaracus API] Edition: selfhosted
[Amaracus API] listening on http://localhost:4000
```

Open the console at `http://localhost:3000`, create an account (you will get a sign-up code by email), and
accept the two licences on the activation screen.

Check the API: `curl http://localhost:4000/health/ready` should answer `"ready": true`.

## 3. Manual install (without Docker)

```bash
pnpm install --frozen-lockfile
cp .env.example .env            # fill in your values, including DATABASE_URL and DIRECT_URL
pnpm --filter @amaracus/types --filter @amaracus/crypto-core --filter @amaracus/database --filter @amaracus/sdk build
pnpm --filter @amaracus/database db:deploy        # apply migrations
pnpm --filter api build
cd apps/api && node dist/index.js                 # the API; run it under systemd, pm2 or your process manager
```

The API reads `.env` from the repository root.

Web console, as static files (serve `apps/web/out` with nginx, Caddy, S3 + CloudFront, Azure Static Web Apps or
any static host):

```bash
cd apps/web
NEXT_PUBLIC_API_URL=https://kms-api.example.com NEXT_PUBLIC_APP_URL=https://kms.example.com pnpm build
```

Or as a Node server: build with `NEXT_OUTPUT_STANDALONE=true` and run the standalone `server.js` that
Next.js writes under `.next/standalone`; `apps/web/Dockerfile` shows the exact layout.

`NEXT_PUBLIC_*` values are compiled into the console when it is built. Changing them later needs a rebuild.

## 4. Configuration

All configuration is environment variables. [`.env.example`](.env.example) lists every variable the code
reads, with comments. The API checks its configuration at start-up and **refuses to start** with a clear list
of problems if, for example:

- `DATABASE_URL` is missing;
- a secret is missing, shorter than 32 characters, or still the placeholder from `.env.example`;
- both or neither form of the master key is set;
- `APP_URL` or `API_URL` is missing, invalid, or points at `amaracus.tech`;
- email is configured but has no sender, or the sender is an `amaracus.tech` address;
- an Azure client secret is set without its tenant and client ID.

There are no built-in defaults that point at AMARACUS's servers, mailboxes or accounts.

## 5. Database and migrations

- Create an empty database and a user that owns it. `DATABASE_URL` is used by the API; `DIRECT_URL` by
  migrations (use a direct connection there if you put PgBouncer or another pooler in front).
- Apply migrations with `pnpm --filter @amaracus/database db:deploy` (Compose does this in the `migrate`
  service). Check status with `pnpm --filter @amaracus/database db:status`.
- Migration `6_self_host_ledger` creates the usage ledger and makes it append-only with a trigger. It also
  creates the licence acceptance and licence key tables.
- On Supabase-style Postgres the migrations enable row-level security on their tables and revoke access from
  the `anon` and `authenticated` roles; on plain Postgres those steps do nothing.

## 6. Accounts, administrators and activation

- People create accounts in the console with email and password. A one-time code is emailed to confirm the
  address, so email must work before anyone can sign up (in production mode).
- Sign-up creates an organization. Members, roles and API keys are managed per organization in the console.
- **Administrators**: list your administrators' emails in `PLATFORM_ADMIN_EMAILS`. Only they can accept the
  licences, add licence keys and read or export the usage ledger. If the variable is empty, any signed-in
  user can do those things; the API logs a warning at start-up.
- **Activation**: until someone accepts PolyForm Shield 1.0.0 and the AMARACUS Additional Commercial Terms
  on the activation screen, the API answers `403 LICENSE_ACCEPTANCE_REQUIRED` to cryptographic operations
  (decrypt, unwrap and verify excepted). The acceptance (who, when, for which legal entity, and the SHA-256 of
  each text) is stored in your database only. If an upgrade changes either text, the screen appears again.

## 7. Email

Use your own provider and a sender on a domain you control.

- **Resend**: set `RESEND_API_KEY` and `EMAIL_FROM_DEFAULT` (optionally `EMAIL_FROM_VERIFY`,
  `EMAIL_FROM_RECOVERY`). Verify your sending domain in Resend first. Resend uses HTTPS, so it works on hosts
  that block outbound SMTP.
- **SMTP** (any provider: Amazon SES, Azure Communication Services, Postmark, Mailgun, Microsoft 365, your own
  server): leave `RESEND_API_KEY` empty and set `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`,
  `SMTP_PASS`, `SMTP_FROM`. Separate mailboxes for sign-up codes (`VERIFY_SMTP_*`) and password resets
  (`RECOVERY_SMTP_*`) are optional.
- Set `ORGANIZATION_LEGAL_NAME`, `ORGANIZATION_POSTAL_ADDRESS` and `SUPPORT_EMAIL`: they appear in email
  footers in place of anything about AMARACUS.
- Publish SPF, DKIM and DMARC records for your sending domain, as your provider explains.

## 8. Storage

- Uploaded files go to `SECURE_UPLOADS_DIR` (default `apps/api/storage/secure_uploads`; a Docker volume in
  Compose). Put it on persistent storage and include it in backups. Object storage (S3, Azure Blob, R2) is not
  built in; mount it as a filesystem if you need it there.
- Everything else (keys, versions, audit log, usage ledger) is in Postgres.

## 9. Azure Key Vault and Managed HSM

Optional. Two separate uses:

**Your installation's own vault** (the `AZURE_KEY_VAULT` and `AZURE_MANAGED_HSM` key providers, and sealing
the master key):

1. In your Azure subscription create a Key Vault (Premium for HSM-protected keys) or a Managed HSM.
2. Create a service principal (or use a managed identity) and give it the key permissions get, create, wrap
   key, unwrap key, sign, verify (Key Vault RBAC role "Key Vault Crypto Officer", or the Managed HSM local
   role "Managed HSM Crypto User").
3. Set `AZURE_KEY_VAULT_URL` and/or `AZURE_MANAGED_HSM_URL`. For a service principal also set
   `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`; for a managed identity leave them empty
   (or set only `AZURE_CLIENT_ID` for a user-assigned identity).
4. Organizations can then create managed keys with provider `AZURE_KEY_VAULT` or `AZURE_MANAGED_HSM`: data is
   encrypted with AES-256-GCM and its data key is wrapped inside your vault.

**Sealing the master key** in your vault, so the server's environment holds only ciphertext: run
`apps/api/scripts/recovery/phase8-seal-master-key.ts` and replace `AMARACUS_LOCAL_MASTER_KEY` with the two
values it prints (`AMARACUS_MASTER_KEY_WRAPPED`, `AMARACUS_MASTER_KEY_KEK_ID`). The API unwraps it at start-up.

**Customer BYOK** (preview): each organization can register its own Azure Key Vault or Managed HSM with its
own service principal in the console. Those credentials are stored encrypted under `API_SECRET` and are never
mixed with the installation's own identity. BYOK has been tested against a simulated vault, not a live one.

What this is not: the master key is used inside the API process, so this is not an HSM boundary for managed
keys on the default provider. AMARACUS is not FIPS 140-3 validated.

## 10. AWS and other clouds

There is no AWS KMS or AWS CloudHSM key provider in this version. You can still run AMARACUS on AWS (or any
cloud) with your own account:

- API and console: ECS/Fargate, EKS, EC2 or App Runner with the two Dockerfiles; or the console as static files
  on S3 + CloudFront.
- Database: Amazon RDS or Aurora for PostgreSQL.
- Email: Amazon SES through SMTP.
- Secrets: put the environment variables in AWS Secrets Manager or SSM Parameter Store and inject them.

The same pattern works on Azure (Container Apps, App Service, Azure Database for PostgreSQL) and Google Cloud
(Cloud Run, Cloud SQL).

## 11. Licence keys and the usage ledger

- Every successful billable operation (section 5 of the terms) is appended to the ledger table
  `usage_ledger_entry`, with the running lifetime total and a SHA-256 hash chain. A database trigger rejects
  updates and deletes. Failed operations and repeated idempotency keys are not added.
- **Console → Billing** shows lifetime operations, the free allowance (1,000), licensed operations and what
  remains; verifies the hash chain; downloads the ledger as JSON Lines; and accepts licence keys.
- After 1,000 lifetime operations, new protective operations return `402 SELF_HOST_LICENSE_REQUIRED` until you
  add a licence key. Decrypt, unwrap, decapsulate and verify are never blocked.
- Buy licence keys from legal@amaracus.tech (price: [AMARACUS-PRICING.md](AMARACUS-PRICING.md)). A key is
  verified offline; adding it sends nothing anywhere.
- The legal allowance is per **corporate group**, across all your installations. If you run several
  installations, the operations in all their ledgers count together, and keys bought for the group must not be
  reused to cover more operations than were bought.
- Keep the ledger for 7 years, including for installations you shut down: export it before you delete a
  database (section 6.3 of the terms). There are no scheduled reports; AMARACUS may ask for a usage statement,
  which you produce from these exports.
- The ledger is tamper-evident, not tamper-proof. Whoever administers the database can disable the trigger or
  rebuild rows. The terms, not the software, are what make accurate records an obligation.

## 12. Backups and recovery

Back up, separately and regularly:

1. **The master key** (`AMARACUS_LOCAL_MASTER_KEY`, or the sealed pair and access to the Azure key that seals
   it). Without it every managed key in the database is unrecoverable. Keep an offline copy (for example a
   printed or hardware-token copy in a safe), never only on the same server.
2. **`API_SECRET`**: needed to read stored BYOK credentials and webhook secrets.
3. **The database**: `pg_dump --format=custom "$DIRECT_URL" > amaracus-$(date +%F).dump`, or your managed
   service's point-in-time recovery. Encrypt backups; they contain wrapped key material and the audit log.
4. **Uploaded files** (`SECURE_UPLOADS_DIR`).
5. **Ledger exports** (Console → Billing → Download usage ledger), kept for 7 years.

Restore: create an empty database, `pg_restore --clean --no-owner -d "$DIRECT_URL" amaracus.dump`, start the
API with the **same** master key and `API_SECRET`, then run `pnpm --filter @amaracus/database db:deploy`.
Restoring an older backup does not reset your usage count under the terms (section 4.4): keep the ledger
exports made after the backup.

Test a restore on a separate machine at least once before you rely on it.

## 13. Upgrades

1. Read `CHANGELOG.md` for the new version. If `LICENSE` or the Additional Commercial Terms changed, an
   administrator will be asked to accept them again.
2. Back up (section 12).
3. Docker: `git pull && docker compose up -d --build` (the `migrate` service applies new migrations first).
   Manual: `git pull`, `pnpm install --frozen-lockfile`, rebuild the packages and the API, run
   `pnpm --filter @amaracus/database db:deploy`, restart the API, rebuild the console.
4. Check `/health/ready` and the API log.

Migrations only move forward. To roll back, restore the backup taken in step 2 and run the old version.

**Rotating the master key**: `apps/api/scripts/recovery/phase9-rewrap-master-key.ts` re-wraps every key version
under a new master key while `AMARACUS_PREVIOUS_MASTER_KEY` holds the old one.

## 14. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| API exits with `Refusing to start: invalid configuration` | Read the list printed under it; each line names the variable and the problem. |
| `the platform master key could not be unsealed` | The sealed master key needs Azure: check the Azure identity variables, network access to the vault, and that the identity can unwrap with that key. |
| `403 LICENSE_ACCEPTANCE_REQUIRED` | Nobody has accepted the licences yet, or an upgrade changed them. Sign in as an administrator and accept them on the activation screen. |
| `403 INSTALLATION_ADMIN_REQUIRED` on the activation screen | Your email is not in `PLATFORM_ADMIN_EMAILS`. |
| `402 SELF_HOST_LICENSE_REQUIRED` | The installation reached its allowance. Add a licence key in Console → Billing. Decrypt and verify still work. |
| `INVALID_LICENSE_KEY` | The key was mistyped or truncated, or was not issued by AMARACUS. Paste the whole key on one line. |
| Sign-up says the email could not be sent (`503 EMAIL_UNAVAILABLE`) | Check the email settings and the API log. With SMTP, check that your host allows outbound ports 587/465; if not, use Resend. |
| Console loads but every request fails (CORS or network error) | `NEXT_PUBLIC_API_URL` was wrong at build time (rebuild the console), or the console's origin is not `APP_URL` or in `CORS_ALLOWED_ORIGINS`. |
| Rate limits hit the proxy's address for every user | Set `TRUST_PROXY_HOPS` to the number of proxies in front of the API. |
| Ledger verification reports `valid: false` and a `firstBrokenSeq` | The ledger row with that number, or one before it, was changed or removed outside the application. Restore from backup or keep the evidence; the terms require accurate records. |
| `/health/ready` reports `database_unavailable` | Check `DATABASE_URL`, network access and that migrations ran. |

## 15. Security recommendations

- Terminate TLS in front of both the API and the console; never expose them over plain HTTP outside a test
  machine. Keep `NODE_ENV=production` (it is the default).
- Do not publish Postgres to the internet. Use a dedicated database user and encrypted connections.
- Generate every secret randomly; never reuse the values of another installation. Store them in a secrets
  manager, not in the repository. `.env` is git-ignored: keep it that way.
- Seal the master key with your own Azure Key Vault if you can (section 9), and keep an offline copy.
- Set `PLATFORM_ADMIN_EMAILS`. Give API keys only the scopes they need, and use per-key IP allowlists.
- Leave the decrypt alert and automatic key lock on (`DECRYPT_ALERT_PER_HOUR`, `DECRYPT_AUTO_LOCK`).
- Protect `/metrics` with `METRICS_TOKEN` (without it the route does not exist).
- Apply updates, and watch [SECURITY.md](SECURITY.md) for how vulnerabilities are reported and fixed. AMARACUS
  has no independent security audit and no FIPS 140-3 validation; assess it against your own requirements
  before relying on it for regulated data.
