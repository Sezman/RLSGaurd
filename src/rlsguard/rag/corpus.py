"""Load the bundled Supabase documentation corpus.

Each markdown file under ``knowledge/`` is one document with a small frontmatter
block (title, url, rule_ids). We parse it without a YAML dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"


@dataclass(frozen=True)
class DocChunk:
    """One unit of documentation that can be retrieved and cited."""

    id: str
    title: str
    url: str
    rule_ids: tuple[str, ...]
    text: str

    @property
    def snippet(self) -> str:
        """A short, single-paragraph preview for citations."""
        para = self.text.strip().split("\n\n", 1)[0]
        para = " ".join(para.split())
        return para if len(para) <= 240 else para[:237] + "..."


def _parse_frontmatter(raw: str) -> tuple[dict[str, str], str]:
    """Split a ``---`` frontmatter block from the body. Returns (meta, body)."""
    if not raw.startswith("---"):
        return {}, raw
    parts = raw.split("---", 2)
    if len(parts) < 3:
        return {}, raw
    meta: dict[str, str] = {}
    for line in parts[1].strip().splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            meta[key.strip().lower()] = value.strip()
    return meta, parts[2].strip()


@lru_cache(maxsize=1)
def load_corpus() -> tuple[DocChunk, ...]:
    """Load and cache all bundled documentation chunks."""
    chunks: list[DocChunk] = []
    for path in sorted(_KNOWLEDGE_DIR.glob("*.md")):
        meta, body = _parse_frontmatter(path.read_text(encoding="utf-8"))
        rule_ids = tuple(
            r.strip() for r in meta.get("rule_ids", "").split(",") if r.strip()
        )
        chunks.append(
            DocChunk(
                id=path.stem,
                title=meta.get("title", path.stem),
                url=meta.get("url", ""),
                rule_ids=rule_ids,
                text=body,
            )
        )
    return tuple(chunks)
