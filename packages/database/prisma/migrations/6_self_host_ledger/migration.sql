-- Self-hosted edition: usage ledger, licence acceptance and licence keys.
-- AMARACUS Cloud never writes to these tables; applying the migration there is harmless.

-- CreateTable
CREATE TABLE "usage_ledger_entry" (
    "seq" BIGSERIAL NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "organizationId" TEXT NOT NULL,
    "operationId" TEXT NOT NULL,
    "operationType" TEXT NOT NULL,
    "quantity" INTEGER NOT NULL DEFAULT 1,
    "cumulativeTotal" BIGINT NOT NULL,
    "prevHash" TEXT NOT NULL,
    "entryHash" TEXT NOT NULL,

    CONSTRAINT "usage_ledger_entry_pkey" PRIMARY KEY ("seq")
);

-- CreateTable
CREATE TABLE "self_host_license_acceptance" (
    "id" TEXT NOT NULL,
    "licensee" TEXT NOT NULL,
    "acceptedByUserId" TEXT NOT NULL,
    "acceptedByEmail" TEXT NOT NULL,
    "shieldSha256" TEXT NOT NULL,
    "commercialSha256" TEXT NOT NULL,
    "commercialVersion" TEXT NOT NULL,
    "ipAddress" TEXT,
    "acceptedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "self_host_license_acceptance_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "self_host_license_key" (
    "licenseId" TEXT NOT NULL,
    "licensee" TEXT NOT NULL,
    "operations" BIGINT NOT NULL,
    "issuedAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3),
    "token" TEXT NOT NULL,
    "addedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "self_host_license_key_pkey" PRIMARY KEY ("licenseId")
);

-- CreateIndex
CREATE UNIQUE INDEX "usage_ledger_entry_operationId_key" ON "usage_ledger_entry"("operationId");

-- CreateIndex
CREATE INDEX "usage_ledger_entry_timestamp_idx" ON "usage_ledger_entry"("timestamp");

-- CreateIndex
CREATE INDEX "self_host_license_acceptance_acceptedAt_idx" ON "self_host_license_acceptance"("acceptedAt");

-- The ledger is append-only: rows can be inserted, never changed or removed, through the
-- application's database role. This makes tampering evident, not impossible: whoever
-- controls the database server can drop the trigger. The hash chain then shows the break.
CREATE OR REPLACE FUNCTION usage_ledger_entry_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'usage_ledger_entry is append-only (% is not allowed)', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER usage_ledger_entry_no_update_delete
  BEFORE UPDATE OR DELETE ON "usage_ledger_entry"
  FOR EACH ROW EXECUTE FUNCTION usage_ledger_entry_append_only();

CREATE TRIGGER usage_ledger_entry_no_truncate
  BEFORE TRUNCATE ON "usage_ledger_entry"
  FOR EACH STATEMENT EXECUTE FUNCTION usage_ledger_entry_append_only();

-- Row-level security, as in 3_enable_row_level_security: the API reaches these tables through
-- Prisma as their owner, so RLS with no policies only closes Supabase's REST API to them.
ALTER TABLE "usage_ledger_entry" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "self_host_license_acceptance" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "self_host_license_key" ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE
  api_role text;
BEGIN
  FOREACH api_role IN ARRAY ARRAY['anon', 'authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = api_role) THEN
      EXECUTE format('REVOKE ALL ON TABLE public.usage_ledger_entry FROM %I', api_role);
      EXECUTE format('REVOKE ALL ON TABLE public.self_host_license_acceptance FROM %I', api_role);
      EXECUTE format('REVOKE ALL ON TABLE public.self_host_license_key FROM %I', api_role);
    END IF;
  END LOOP;
END $$;
