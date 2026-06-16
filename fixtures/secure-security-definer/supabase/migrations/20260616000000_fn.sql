-- SECURITY DEFINER function, but hardened: explicit search_path and an auth
-- check, no dynamic SQL. Still surfaced by SUPA-FUNC-001, but at lower
-- severity/confidence (manual review, fewer risk signals).
create function public.get_own_profile()
returns setof public.profiles
language sql
security definer
set search_path = ''
as $$
  select * from public.profiles where id = auth.uid();
$$;
