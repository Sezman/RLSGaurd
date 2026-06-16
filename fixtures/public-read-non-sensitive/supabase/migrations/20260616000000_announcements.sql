-- Public read on a non-sensitive table. SUPA-RLS-003 should flag this only as
-- MEDIUM (review-worthy), not high — we don't claim every public read is a vuln.
create table public.announcements (
  id bigint primary key,
  title text,
  published_at timestamptz
);

alter table public.announcements enable row level security;

create policy "announcements are public"
  on public.announcements
  for select
  using (true);
