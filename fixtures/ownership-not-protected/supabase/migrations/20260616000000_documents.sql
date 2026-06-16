-- Table with an ownership column (user_id -> auth.users), but the read policy
-- does not scope rows to the owner.
-- Expected finding: SUPA-RLS-005 (medium). Not 001/002/003/004.
create table public.documents (
  id bigint primary key,
  user_id uuid references auth.users,
  content text
);

alter table public.documents enable row level security;

create policy "read all documents"
  on public.documents
  for select
  using (auth.role() = 'authenticated');
