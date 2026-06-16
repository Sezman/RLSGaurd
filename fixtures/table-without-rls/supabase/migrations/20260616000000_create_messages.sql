-- A messages table created in the public schema with no RLS.
-- Expected finding: SUPA-RLS-001 (critical).
create table public.messages (
  id bigint primary key,
  body text
);
