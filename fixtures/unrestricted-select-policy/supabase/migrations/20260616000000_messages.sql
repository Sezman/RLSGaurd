-- SELECT policy using (true) on a table with sensitive data.
-- Expected finding: SUPA-RLS-003 (high). Not 001 (RLS on) or 002 (has policy).
create table public.messages (
  id bigint primary key,
  user_id uuid references auth.users,
  body text
);

alter table public.messages enable row level security;

create policy "anyone can read messages"
  on public.messages
  for select
  using (true);
