---
title: Avoid unrestricted (USING true) policies
url: https://supabase.com/docs/guides/database/postgres/row-level-security#policies
rule_ids: SUPA-RLS-003
---
A policy whose expression is simply `true` places no restriction on the rows it
applies to. `USING (true)` on a SELECT policy exposes every row to any anon or
authenticated client; `WITH CHECK (true)` on a write lets a client write
arbitrary rows. This is occasionally intentional (genuinely public data) but is
frequently a mistake on tables that hold per-user or sensitive information.

Prefer a policy that ties access to the current user, for example:

    create policy "select own rows" on public.<table>
      for select using (auth.uid() = user_id);

If a table really is meant to be world-readable (for example a public catalog),
confirm that every column is safe to expose before relying on `using (true)`.
Treat unrestricted write policies (INSERT/UPDATE/DELETE/ALL) as high risk, since
they allow any permitted role to modify rows they do not own.
