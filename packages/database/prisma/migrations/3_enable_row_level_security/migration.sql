-- Supabase serves every table in the public schema through its REST API (PostgREST) to the
-- `anon` and `authenticated` roles. AMARACUS never uses that API: the API server reaches
-- Postgres only through Prisma, as the role that owns these tables, and row-level security does
-- not apply to a table's owner. Enabling RLS with no policies, and revoking the API roles'
-- grants, therefore closes the REST API to these tables without changing what the app can do.
--
-- Runs on any Postgres: the role checks skip the grant changes where the Supabase roles do not
-- exist (local development, CI).

DO $$
DECLARE
  t record;
  api_role text;
BEGIN
  FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t.tablename);
  END LOOP;

  FOREACH api_role IN ARRAY ARRAY['anon', 'authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = api_role) THEN
      EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', api_role);
      EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM %I', api_role);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM %I', api_role);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM %I', api_role);
    END IF;
  END LOOP;
END $$;
