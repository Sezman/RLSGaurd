"""Lightweight, dependency-free BM25 retrieval over the doc corpus.

The corpus is tiny (a handful of curated docs), so a pure-Python BM25 with a
rule-id boost is more than enough and keeps the install free of heavy ML deps.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from functools import lru_cache

from rlsguard.rag.corpus import DocChunk, load_corpus

_TOKEN_RE = re.compile(r"[a-z0-9_]+")
_STOPWORDS = {
    "the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "is", "are",
    "be", "by", "it", "this", "that", "with", "as", "at", "from", "not", "no",
    "you", "your", "can", "if", "so", "but", "should", "which", "every", "any",
}
_K1 = 1.5
_B = 0.75
_RULE_BOOST = 3.0  # added to score when a doc is tagged with the finding's rule


def _tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]


@dataclass
class _Index:
    chunks: tuple[DocChunk, ...]
    doc_tokens: list[list[str]]
    doc_len: list[int]
    avg_len: float
    idf: dict[str, float]


@lru_cache(maxsize=1)
def _build_index() -> _Index:
    chunks = load_corpus()
    doc_tokens = [_tokenize(c.title + " " + c.text) for c in chunks]
    doc_len = [len(toks) for toks in doc_tokens]
    avg_len = (sum(doc_len) / len(doc_len)) if doc_len else 0.0

    n = len(chunks)
    df: dict[str, int] = {}
    for toks in doc_tokens:
        for term in set(toks):
            df[term] = df.get(term, 0) + 1
    idf = {
        term: math.log(1 + (n - freq + 0.5) / (freq + 0.5))
        for term, freq in df.items()
    }
    return _Index(chunks, doc_tokens, doc_len, avg_len, idf)


def retrieve(query: str, *, rule_id: str | None = None, k: int = 2) -> list[DocChunk]:
    """Return the top-k documents most relevant to ``query``.

    Docs tagged with ``rule_id`` get a score boost so the canonical doc for a
    rule reliably surfaces even when query wording differs.
    """
    index = _build_index()
    if not index.chunks:
        return []

    q_terms = _tokenize(query)
    scored: list[tuple[float, int]] = []
    for i, chunk in enumerate(index.chunks):
        score = _bm25(index, i, q_terms)
        if rule_id and rule_id in chunk.rule_ids:
            score += _RULE_BOOST
        scored.append((score, i))

    scored.sort(key=lambda s: (-s[0], s[1]))
    return [index.chunks[i] for score, i in scored[:k] if score > 0]


def _bm25(index: _Index, doc_i: int, q_terms: list[str]) -> float:
    tokens = index.doc_tokens[doc_i]
    if not tokens:
        return 0.0
    tf: dict[str, int] = {}
    for t in tokens:
        tf[t] = tf.get(t, 0) + 1
    length = index.doc_len[doc_i]
    score = 0.0
    for term in q_terms:
        if term not in tf:
            continue
        idf = index.idf.get(term, 0.0)
        freq = tf[term]
        denom = freq + _K1 * (1 - _B + _B * length / (index.avg_len or 1))
        score += idf * (freq * (_K1 + 1)) / denom
    return score
