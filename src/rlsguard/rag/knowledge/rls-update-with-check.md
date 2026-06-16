---
title: UPDATE policies need both USING and WITH CHECK
url: https://supabase.com/docs/guides/database/postgres/row-level-security#policies
rule_ids: SUPA-RLS-004
---
An UPDATE policy has two expressions. USING decides which existing rows a user
may update; WITH CHECK validates the new row values after the update. When you
omit WITH CHECK, PostgreSQL reuses the USING expression as the implicit check,
so an UPDATE policy is not always exploitable without it - but relying on that
fallback is fragile.

Define WITH CHECK explicitly, typically matching USING, so a user cannot move a
row outside their own scope (for example, reassigning ownership to another
user), and so the policy stays correct if USING is later changed:

    create policy "update own profile" on public.profiles
      for update
      using (auth.uid() = id)
      with check (auth.uid() = id);
