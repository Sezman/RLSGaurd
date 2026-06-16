-- UPDATE policy with both USING and WITH CHECK. Should NOT trigger SUPA-RLS-004.
create table public.profiles (
  id uuid primary key references auth.users,
  bio text
);

alter table public.profiles enable row level security;

create policy "update own profile"
  on public.profiles
  for update
  using (auth.uid() = id)
  with check (auth.uid() = id);
