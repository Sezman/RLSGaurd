-- SECURITY DEFINER function with no search_path, dynamic SQL, and no auth check.
-- Expected finding: SUPA-FUNC-001 (high, manual review required).
create function public.delete_user_data(target text)
returns void
language plpgsql
security definer
as $$
begin
  execute 'delete from ' || target;
end;
$$;
