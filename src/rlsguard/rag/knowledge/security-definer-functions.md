---
title: Hardening SECURITY DEFINER functions
url: https://supabase.com/docs/guides/database/functions
rule_ids: SUPA-FUNC-001
---
A function declared SECURITY DEFINER runs with the privileges of the function's
owner (often a highly privileged role) rather than the caller, and it can bypass
Row Level Security. This is sometimes necessary, but each such function needs
review to ensure it cannot be abused to escalate privileges or read data the
caller should not see.

Harden SECURITY DEFINER functions:

- Pin the search path so a caller cannot shadow objects with their own schema:
  `alter function <fn> set search_path = '';` (reference objects fully
  qualified, e.g. `public.table`).
- Restrict who can run it: `revoke execute on function <fn> from public;` then
  grant execute only to the roles that need it. New functions are executable by
  PUBLIC by default.
- Add explicit authorization checks inside the function (for example, compare
  `auth.uid()` to the owner of the affected rows).
- Avoid dynamic SQL (EXECUTE / string building); if unavoidable, use `format()`
  with `%I`/`%L` and validate inputs.
