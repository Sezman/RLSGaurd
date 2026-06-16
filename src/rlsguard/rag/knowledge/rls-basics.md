---
title: Enabling Row Level Security and writing policies
url: https://supabase.com/docs/guides/database/postgres/row-level-security
rule_ids: SUPA-RLS-001, SUPA-RLS-002
---
Tables in the `public` schema are exposed through Supabase's auto-generated API.
Any client holding the anon or authenticated key can query them unless Row Level
Security (RLS) restricts access. You should enable RLS on every table in an
API-exposed schema:

    alter table public.<table> enable row level security;

Enabling RLS alone denies all access. PostgreSQL applies a default-deny: until
you create policies, no rows are returned to anon or authenticated roles. This
typically breaks features rather than leaking data, but it means you have not
yet defined any intended access path. After enabling RLS, create an explicit
policy for each operation the application performs (SELECT, INSERT, UPDATE,
DELETE), scoping each to the rows the current user is allowed to touch.

A policy has a USING expression (which rows are visible / affected) and, for
writes, a WITH CHECK expression (what new row values are allowed).
