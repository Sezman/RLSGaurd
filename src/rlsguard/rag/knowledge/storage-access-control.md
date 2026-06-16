---
title: Storage access control - verify ownership, not just the bucket
url: https://supabase.com/docs/guides/storage/security/access-control
rule_ids: SUPA-STORAGE-001
---
Supabase Storage enforces access through RLS policies on the `storage.objects`
table. A policy that checks only `bucket_id` lets every permitted user reach
every file in that bucket - fine for a deliberately public bucket, but a leak
for per-user private files.

To scope access to the file's owner, store each user's files under a folder
named for their user id and check the first path segment with
`storage.foldername`:

    create policy "read own files" on storage.objects
      for select using (
        bucket_id = 'private-documents'
        and (storage.foldername(name))[1] = auth.uid()::text
      );

Apply the same ownership check to write operations (INSERT/UPDATE/DELETE), since
a bucket-only write policy lets any permitted user overwrite or delete other
users' files.
