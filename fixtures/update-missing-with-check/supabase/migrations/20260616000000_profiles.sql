-- UPDATE policy with USING but no WITH CHECK.
-- Expected finding: SUPA-RLS-004 (high). Not 001/002/003.
create table public.profiles (
  id uuid primary key references auth.users,
  bio text
);

alter table public.profiles enable row level security;

create policy "update own profile"
  on public.profiles
  for update
  using (auth.uid() = id);
