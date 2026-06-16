import { createClient } from "@supabase/supabase-js";

// All of these are safe to ship to the client and must NOT be flagged:
// the project URL, the anon (publishable) JWT, and the sb_publishable_ key.
const SUPABASE_URL = "https://abcdefghijklmno.supabase.co";

const SUPABASE_ANON_KEY =
  "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAic3VwYWJhc2UiLCAicm9sZSI6ICJhbm9uIiwgImlhdCI6IDE3MDAwMDAwMDB9.c2lnbmF0dXJlX2RvX25vdF91c2VfdGhpc19rZXk";

const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_abc123DEF456ghi789";

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
