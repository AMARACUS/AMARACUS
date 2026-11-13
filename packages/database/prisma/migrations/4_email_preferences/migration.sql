-- CreateTable
CREATE TABLE "user_communication_preference" (
    "userId" TEXT NOT NULL,
    "marketingEmails" BOOLEAN NOT NULL DEFAULT false,
    "telemetryOptIn" BOOLEAN NOT NULL DEFAULT true,
    "cookieConsentStatus" TEXT NOT NULL DEFAULT 'essential_only',
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user_communication_preference_pkey" PRIMARY KEY ("userId")
);

-- CreateTable
CREATE TABLE "email_suppression" (
    "email" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "suppressedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "email_suppression_pkey" PRIMARY KEY ("email")
);

-- AddForeignKey
ALTER TABLE "user_communication_preference" ADD CONSTRAINT "user_communication_preference_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- Row-level security, as in 3_enable_row_level_security: the API reaches these tables through
-- Prisma as their owner, so RLS with no policies only closes Supabase's REST API to them.
ALTER TABLE "user_communication_preference" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "email_suppression" ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE
  api_role text;
BEGIN
  FOREACH api_role IN ARRAY ARRAY['anon', 'authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = api_role) THEN
      EXECUTE format('REVOKE ALL ON TABLE public.user_communication_preference FROM %I', api_role);
      EXECUTE format('REVOKE ALL ON TABLE public.email_suppression FROM %I', api_role);
    END IF;
  END LOOP;
END $$;
