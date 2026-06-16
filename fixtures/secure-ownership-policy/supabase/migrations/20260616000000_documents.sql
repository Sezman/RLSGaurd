-- Read policy scoped to the owner via auth.uid() = user_id.
-- Should NOT trigger SUPA-RLS-005.
create table public.documents (
  id bigint primary key,
  user_id uuid references auth.users,
  content text
);

alter table public.documents enable row level security;

create policy "read own documents"
  on public.documents
  for select
  using (auth.uid() = user_id);
