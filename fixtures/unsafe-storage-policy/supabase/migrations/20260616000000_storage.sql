-- Storage policy that only checks the bucket, not file ownership.
-- Expected finding: SUPA-STORAGE-001 (medium).
create policy "read private documents"
  on storage.objects
  for select
  using (bucket_id = 'private-documents');
