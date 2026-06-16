"""Tests for the RAG layer (offline: retrieval, citations, fallback)."""

from pathlib import Path

from rlsguard.models.finding import Finding
from rlsguard.rag.corpus import load_corpus
from rlsguard.rag.explainer import explain_finding, explain_findings
from rlsguard.rag.retriever import retrieve

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_corpus_loads_with_rule_tags():
    corpus = load_corpus()
    assert corpus  # non-empty
    all_rule_ids = {rid for c in corpus for rid in c.rule_ids}
    # Every implemented rule should have at least one doc.
    for rid in ("SUPA-RLS-001", "SUPA-RLS-003", "SUPA-KEY-001", "SUPA-FUNC-001"):
        assert rid in all_rule_ids


def test_retrieval_surfaces_rule_specific_doc():
    docs = retrieve("service role key exposed in frontend", rule_id="SUPA-KEY-001", k=1)
    assert docs
    assert "SUPA-KEY-001" in docs[0].rule_ids


def test_explain_attaches_citations_without_llm():
    finding = Finding(
        rule_id="SUPA-RLS-001",
        title="public.messages has RLS disabled",
        severity="critical",
        confidence="high",
        explanation="RLS is disabled on an exposed table.",
    )
    # use_llm=False guarantees no network/API dependency.
    enriched = explain_finding(finding, use_llm=False)

    assert enriched.citations
    assert enriched.citations[0].url.startswith("https://")
    assert enriched.generated_explanation is None  # fallback to predefined
    # Original finding is unchanged (model_copy returns a new object).
    assert finding.citations == []


def test_explain_findings_is_offline_safe():
    # The relevant doc for RLS-001 should be among the citations.
    findings = explain_findings(
        [
            Finding(
                rule_id="SUPA-STORAGE-001",
                title="storage.objects policy does not verify ownership",
                severity="medium",
                confidence="medium",
            )
        ],
        use_llm=False,
    )
    titles = " ".join(c.title for c in findings[0].citations).lower()
    assert "storage" in titles
