import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = "https://abcdefghijklmno.supabase.co";

// BUG: the service_role key bypasses RLS and must never be in client code.
const SUPABASE_SERVICE_ROLE_KEY =
  "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAic3VwYWJhc2UiLCAicm9sZSI6ICJzZXJ2aWNlX3JvbGUiLCAiaWF0IjogMTcwMDAwMDAwMH0.c2lnbmF0dXJlX2RvX25vdF91c2VfdGhpc19rZXk";

export const adminClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
