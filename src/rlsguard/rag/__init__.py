"""Optional RAG layer: retrieve Supabase docs and explain findings.

The retrieval half is fully offline and deterministic. Generation (an LLM
synthesis) is optional and only runs when explicitly requested and an API key is
available; otherwise each finding's predefined explanation is the fallback.
"""
