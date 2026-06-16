"""Optional Anthropic-backed synthesis for finding explanations.

This module degrades gracefully: if the ``anthropic`` package is not installed
or no API key is configured, ``generate_explanation`` returns ``None`` and the
caller falls back to the finding's predefined explanation. The LLM only ever
*explains* an already-decided finding; it never decides whether one exists.
"""

from __future__ import annotations

import os

from rlsguard.models.finding import Citation, Finding

_DEFAULT_MODEL = "claude-haiku-4-5-20251001"

_SYSTEM = (
    "You explain an already-confirmed security finding to a beginner developer "
    "using only the provided Supabase documentation context. Do NOT decide or "
    "question whether the issue is real - it has already been detected by a "
    "deterministic scanner. Write 2-4 short sentences: what the issue means and "
    "how to fix it, in plain language. Ground every claim in the provided "
    "context and do not invent APIs. Do not include a preamble."
)


def is_available() -> bool:
    """True if an API key is configured and the SDK can be imported."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def generate_explanation(finding: Finding, citations: list[Citation]) -> str | None:
    """Generate a beginner-friendly explanation, or None if unavailable."""
    if not is_available():
        return None

    import anthropic

    context = "\n\n".join(
        f"[{c.title}]\n{c.snippet}\nSource: {c.url}" for c in citations
    )
    user = (
        f"Finding: {finding.title}\n"
        f"Rule: {finding.rule_id} (severity: {finding.severity})\n"
        f"Scanner explanation: {finding.explanation}\n\n"
        f"Documentation context:\n{context or '(none)'}\n\n"
        "Explain this finding and its fix for a beginner."
    )

    model = os.environ.get("RLSGUARD_EXPLAIN_MODEL", _DEFAULT_MODEL)
    try:
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=model,
            max_tokens=400,
            system=_SYSTEM,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(
            block.text for block in resp.content if getattr(block, "type", None) == "text"
        ).strip() or None
    except Exception:
        # Any API/network error falls back to the deterministic explanation.
        return None
