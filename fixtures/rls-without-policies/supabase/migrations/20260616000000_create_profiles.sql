-- RLS is enabled but no policies are defined.
-- Expected finding: SUPA-RLS-002 (medium). Should NOT trigger SUPA-RLS-001.
create table public.profiles (
  id uuid primary key,
  email text
);

alter table public.profiles enable row level security;
