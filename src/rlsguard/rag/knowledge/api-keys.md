---
title: Supabase API keys - keep the service_role key secret
url: https://supabase.com/docs/guides/api/api-keys
rule_ids: SUPA-KEY-001
---
Supabase projects have a publishable (anon) key and a secret (service_role)
key. The anon / publishable key is designed to be shipped in client code; it is
constrained by Row Level Security. The service_role key (and newer `sb_secret_`
keys) bypass RLS entirely and have full read/write access to your database.

Never expose the service_role key, database password, JWT secret, or a Postgres
connection string in client-accessible code or in a committed `.env` file. If
such a credential leaks, anyone can read and modify all of your data regardless
of RLS. Use the service_role key only on a trusted server (Edge Functions,
backend), loaded from a server-side environment variable.

If a secret is exposed, rotate it immediately in the Supabase dashboard - treat
the old value as compromised - and ensure `.env` files are listed in
`.gitignore`. In the client, use only the publishable / anon key.
