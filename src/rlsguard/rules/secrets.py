"""Secret/credential detection (SUPA-KEY-001).

Unlike the RLS rules, this operates on source/env file *text* rather than the
reconstructed schema. The headline technique: when a JWT is found, decode its
payload and read the ``role`` claim. A ``service_role`` token is flagged; an
``anon`` token is explicitly treated as safe. This distinguishes a privileged
key from the publishable/anon key precisely, instead of guessing.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass

from rlsguard.models.finding import Finding

_KEYS_DOCS = "https://supabase.com/docs/guides/api/api-keys"

# Folders whose contents ship to / are reachable by the client.
_CLIENT_DIRS = {"src", "app", "pages", "components", "public", "mobile"}

# A JWT: header.payload.signature, each base64url.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
# New-style Supabase secret key (NOT the publishable `sb_publishable_` prefix).
_SB_SECRET_RE = re.compile(r"sb_secret_[A-Za-z0-9_\-]{8,}")
# Postgres connection string carrying an inline password.
_PG_CONN_RE = re.compile(r"postgres(?:ql)?://[^\s:/@]+:(?P<pw>[^\s:/@]+)@", re.IGNORECASE)
# Assignment of a privileged secret to a known env var.
_ENV_ASSIGN_RE = re.compile(
    r"(?P<var>SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY|SUPABASE_JWT_SECRET|"
    r"JWT_SECRET|SUPABASE_DB_PASSWORD|DATABASE_PASSWORD|DB_PASSWORD|"
    r"POSTGRES_PASSWORD|PGPASSWORD)\s*[:=]\s*['\"]?(?P<val>[^\s'\"#]+)",
    re.IGNORECASE,
)

_PLACEHOLDER_HINTS = (
    "your", "xxx", "changeme", "change-me", "example", "placeholder",
    "redacted", "dummy", "todo", "<", "}", "...",
)
_ENV_REFERENCE_PREFIXES = (
    "process.env", "import.meta", "deno.env", "os.environ", "${", "env.", "$env",
)


@dataclass(frozen=True)
class SecretMatch:
    line: int
    secret_type: str
    confidence: str
    evidence: str


def _jwt_role(token: str) -> str | None:
    """Decode a JWT payload and return its ``role`` claim, if any."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(payload))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    role = data.get("role") if isinstance(data, dict) else None
    return role if isinstance(role, str) else None


def _redact_token(token: str) -> str:
    return token[:10] + "...<redacted>"


def _is_placeholder(value: str) -> bool:
    lv = value.lower()
    return len(value) < 8 or any(h in lv for h in _PLACEHOLDER_HINTS)


def _is_reference(value: str) -> bool:
    lv = value.lower()
    return any(lv.startswith(p) for p in _ENV_REFERENCE_PREFIXES)


def _match_line(line: str) -> SecretMatch | None:
    """Return the single strongest secret match on a line, if any."""
    for jm in _JWT_RE.finditer(line):
        role = _jwt_role(jm.group(0))
        if role == "service_role":
            return SecretMatch(0, "Supabase service_role key (JWT)", "high",
                               _redact_token(jm.group(0)))
        if role == "anon":
            # Explicitly safe: the publishable/anon key is meant to be public.
            return None

    sm = _SB_SECRET_RE.search(line)
    if sm:
        return SecretMatch(0, "Supabase secret key (sb_secret_)", "high",
                           _redact_token(sm.group(0)))

    pm = _PG_CONN_RE.search(line)
    if pm:
        redacted = line[: pm.start("pw")].strip() + "<redacted>@..."
        return SecretMatch(0, "PostgreSQL connection string with password", "high", redacted)

    em = _ENV_ASSIGN_RE.search(line)
    if em:
        val = em.group("val")
        if _is_reference(val) or _is_placeholder(val):
            return None
        return SecretMatch(0, f"Privileged secret assigned to {em.group('var')}",
                           "medium", f"{em.group('var')}=<redacted>")
    return None


def find_secret_matches(text: str) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    for i, line in enumerate(text.splitlines(), start=1):
        m = _match_line(line)
        if m is not None:
            matches.append(SecretMatch(i, m.secret_type, m.confidence, m.evidence))
    return matches


def client_accessible(rel_path: str) -> bool:
    return any(part in _CLIENT_DIRS for part in rel_path.split("/"))


def build_finding(rel_path: str, match: SecretMatch) -> Finding:
    in_client = client_accessible(rel_path)
    severity = "critical" if in_client else "high"
    if in_client:
        explanation = (
            f"A privileged credential ({match.secret_type}) was found in {rel_path}, "
            "which is in a client-accessible folder. Anything bundled here can be "
            "extracted by any user of the app, giving them full, RLS-bypassing access "
            "to your database. This key must never reach the client."
        )
    else:
        explanation = (
            f"A privileged credential ({match.secret_type}) was found in {rel_path}. "
            "If this file is committed to version control or bundled into a build, the "
            "key is exposed. Service-role keys and database passwords bypass Row Level "
            "Security and must stay server-side only."
        )
    return Finding(
        rule_id="SUPA-KEY-001",
        title=f"Privileged Supabase credential exposed in {rel_path}",
        severity=severity,
        confidence=match.confidence,
        file=rel_path,
        line=match.line,
        evidence=match.evidence,
        explanation=explanation,
        remediation=(
            "Remove the secret from this file and rotate it immediately in the "
            "Supabase dashboard (it should be considered compromised). Load it only "
            "from a server-side environment variable, never in client code. Ensure "
            ".env files are listed in .gitignore. Use the publishable/anon key in the "
            "client instead."
        ),
        references=[_KEYS_DOCS],
    )
