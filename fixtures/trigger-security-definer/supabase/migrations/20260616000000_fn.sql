-- SECURITY DEFINER *trigger* function with no search_path. Because it is only
-- invoked by triggers (not callable directly via the API/RPC), SUPA-FUNC-001
-- reports it at a lower severity than a directly callable function.
create function public.on_row_change()
returns trigger
language plpgsql
security definer
as $$
begin
  insert into public.audit_log(event) values (tg_op);
  return new;
end;
$$;

create trigger row_change_audit
  after insert or update on public.habits
  for each row execute function public.on_row_change();
