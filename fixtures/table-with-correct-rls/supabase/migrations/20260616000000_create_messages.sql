-- A messages table with RLS enabled AND a policy.
-- Should NOT trigger SUPA-RLS-001 (RLS on) or SUPA-RLS-002 (has a policy).
create table public.messages (
  id bigint primary key,
  user_id uuid references auth.users,
  body text
);

alter table public.messages enable row level security;

create policy "select own messages"
  on public.messages
  for select
  using (auth.uid() = user_id);
