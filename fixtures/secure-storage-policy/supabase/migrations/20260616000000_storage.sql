-- Storage policy scoped to the user's own folder. Should NOT trigger
-- SUPA-STORAGE-001.
create policy "read own files"
  on storage.objects
  for select
  using (
    bucket_id = 'private-documents'
    and (storage.foldername(name))[1] = auth.uid()::text
  );
