"""Supabase Storage rules (SUPA-STORAGE-001)."""

from __future__ import annotations

import re

from rlsguard.models.finding import Finding
from rlsguard.models.policy import Policy
from rlsguard.rules.policies import _governing_expression
from rlsguard.scanner.sql_analyzer import SchemaState

_STORAGE_DOCS = "https://supabase.com/docs/guides/storage/security/access-control"

_AUTH_UID_RE = re.compile(r"auth\s*\.\s*uid\s*\(\s*\)", re.IGNORECASE)
# The canonical Supabase per-user folder check.
_FOLDERNAME_RE = re.compile(r"storage\s*\.\s*foldername", re.IGNORECASE)
_OWNER_RE = re.compile(r"\bowner(?:_id)?\b", re.IGNORECASE)
_WRITE_OPS = {"INSERT", "UPDATE", "DELETE", "ALL"}


def _normalize(expr: str) -> str:
    e = expr.strip().lower()
    while e.startswith("(") and e.endswith(")"):
        e = e[1:-1].strip()
    return e


def supa_storage_001(state: SchemaState) -> list[Finding]:
    """SUPA-STORAGE-001 — storage.objects policy that doesn't verify ownership.

    A storage policy that gates access only on ``bucket_id`` (or role) without
    checking the file's owner — typically via ``(storage.foldername(name))[1] =
    auth.uid()::text`` — lets every permitted user reach every file in the
    bucket. Reported at medium severity (read) / high (write) as a review item,
    since fully shared buckets are sometimes intentional.
    """
    table = state.tables.get(("storage", "objects"))
    if table is None:
        return []

    findings: list[Finding] = []
    for policy in table.policies:
        finding = _evaluate(policy)
        if finding is not None:
            findings.append(finding)
    return findings


def _evaluate(policy: Policy) -> Finding | None:
    expr = _governing_expression(policy).strip()
    if not expr:
        return None
    norm = _normalize(expr)
    if norm == "false":  # denies everything; not a risk
        return None

    if _AUTH_UID_RE.search(expr) or _FOLDERNAME_RE.search(expr) or _OWNER_RE.search(expr):
        return None  # ownership is verified in some form

    op = (policy.operation or "ALL").upper()
    bucket_only = "bucket_id" in norm

    if op in _WRITE_OPS:
        severity = "high"
        action = "create, overwrite, or delete"
    else:
        severity = "medium"
        action = "read"

    scope = (
        "only checks the bucket (bucket_id) and not which user owns the file"
        if bucket_only
        else "does not restrict access to the file's owner"
    )

    return Finding(
        rule_id="SUPA-STORAGE-001",
        title=f"storage.objects {op} policy does not verify file ownership",
        severity=severity,
        confidence="medium",
        file=policy.file,
        line=policy.line,
        evidence=(
            f'CREATE POLICY "{policy.name}" ON storage.objects FOR {op} '
            f"-- expression: {expr}"
        ),
        explanation=(
            f"The {op} policy \"{policy.name}\" on storage.objects {scope}. As written, "
            f"any role the policy applies to can {action} every file in the bucket, not "
            "just their own. If this bucket is meant to hold per-user private files, "
            "this is an access-control gap; if the bucket is intentionally shared, "
            "confirm that is the intent."
        ),
        remediation=(
            "Scope the policy to the owner's folder, e.g.:\n\n"
            f'CREATE POLICY "{policy.name}" ON storage.objects\n'
            f"  FOR {op} USING (\n"
            "    bucket_id = 'your-bucket'\n"
            "    and (storage.foldername(name))[1] = auth.uid()::text\n"
            "  );"
        ),
        references=[_STORAGE_DOCS],
    )


RULES = [supa_storage_001]
