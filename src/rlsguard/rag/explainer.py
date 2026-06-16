"""Enrich findings with retrieved documentation and optional LLM synthesis."""

from __future__ import annotations

from rlsguard.models.finding import Citation, Finding
from rlsguard.rag import llm
from rlsguard.rag.retriever import retrieve


def _query_for(finding: Finding) -> str:
    """Build a retrieval query from a finding's most descriptive fields."""
    return f"{finding.title} {finding.explanation}"


def explain_finding(finding: Finding, *, use_llm: bool = True) -> Finding:
    """Attach doc citations (always) and an LLM explanation (if available)."""
    docs = retrieve(_query_for(finding), rule_id=finding.rule_id, k=2)
    citations = [Citation(title=d.title, url=d.url, snippet=d.snippet) for d in docs]

    generated = None
    if use_llm and citations:
        generated = llm.generate_explanation(finding, citations)

    return finding.model_copy(
        update={"citations": citations, "generated_explanation": generated}
    )


def explain_findings(findings: list[Finding], *, use_llm: bool = True) -> list[Finding]:
    """Return a new list of findings enriched with retrieval (and maybe LLM)."""
    return [explain_finding(f, use_llm=use_llm) for f in findings]
