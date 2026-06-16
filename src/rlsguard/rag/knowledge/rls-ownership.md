---
title: Scope policies to the row owner with auth.uid()
url: https://supabase.com/docs/guides/database/postgres/row-level-security#authenticated-and-unauthenticated-roles
rule_ids: SUPA-RLS-005
---
In a multi-tenant application, rows usually belong to a user. The owner is
typically stored in a column such as `user_id`, `owner_id`, `created_by`,
`author_id`, or `account_id`, often a foreign key to `auth.users`. To restrict
access to the owner, a policy must compare the current user, `auth.uid()`, to
that ownership column:

    create policy "select own rows" on public.<table>
      for select using (auth.uid() = user_id);

A policy that does not reference both `auth.uid()` and the ownership column may
let a user reach other users' rows. Common mistakes: a read policy that only
checks `auth.role() = 'authenticated'` (every logged-in user sees everyone's
rows), or a policy that compares `auth.uid()` to the wrong column. Such cases
are a likely multi-tenant authorization weakness and should be reviewed, though
a deliberately shared/public feed can be a legitimate exception.
