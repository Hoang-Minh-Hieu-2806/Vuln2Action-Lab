"""Shared lightweight text normalisation for lexical retrieval."""

from __future__ import annotations

import re

from vuln2action.domain import KnowledgeDocument

# Compact English function-word list. Kept in-repo so the keyword baseline stays
# dependency-free and both lexical backends normalise text the same way.
STOPWORDS = frozenset(
    [
        "a",
        "about",
        "above",
        "after",
        "again",
        "against",
        "all",
        "also",
        "am",
        "an",
        "and",
        "any",
        "are",
        "as",
        "at",
        "be",
        "because",
        "been",
        "before",
        "being",
        "below",
        "between",
        "both",
        "but",
        "by",
        "can",
        "cannot",
        "could",
        "did",
        "do",
        "does",
        "doing",
        "down",
        "during",
        "each",
        "few",
        "for",
        "from",
        "further",
        "had",
        "has",
        "have",
        "having",
        "he",
        "her",
        "here",
        "hers",
        "herself",
        "him",
        "himself",
        "his",
        "how",
        "i",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "itself",
        "just",
        "may",
        "me",
        "might",
        "more",
        "most",
        "must",
        "my",
        "myself",
        "no",
        "nor",
        "not",
        "now",
        "of",
        "off",
        "on",
        "once",
        "only",
        "or",
        "other",
        "our",
        "ours",
        "ourselves",
        "out",
        "over",
        "own",
        "same",
        "shall",
        "she",
        "should",
        "so",
        "some",
        "such",
        "than",
        "that",
        "the",
        "their",
        "theirs",
        "them",
        "themselves",
        "then",
        "there",
        "these",
        "they",
        "this",
        "those",
        "through",
        "to",
        "too",
        "under",
        "until",
        "up",
        "very",
        "via",
        "per",
        "etc",
        "was",
        "we",
        "were",
        "what",
        "when",
        "where",
        "which",
        "while",
        "who",
        "whom",
        "why",
        "will",
        "with",
        "would",
        "you",
        "your",
        "yours",
        "yourself",
        "yourselves",
    ]
)


_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def split_camel_case(text: str) -> str:
    """Split product-style concatenations such as ``ShellShock``.

    CVE descriptions often contain names written as one token while the CWE
    catalog describes the underlying mechanism with separate words. Splitting
    the boundary is a cheap, deterministic way to align both vocabularies.
    """
    return _CAMEL_BOUNDARY.sub(" ", text)


def tokenize(text: str) -> list[str]:
    """Lowercase content tokens, dropping the shared stopword list."""
    return [token for token in re.findall(r"[a-z0-9]+", text.lower()) if token not in STOPWORDS]


def document_text(document: KnowledgeDocument, name_weight: int = 2) -> str:
    """Build the indexed text with a simple field boost for the record name.

    Corpus documents already include the name inside ``text``. Repeating the
    name ahead of the body is a cheap field weighting that keeps the title
    signal from being diluted by long descriptions.
    """
    if name_weight < 1:
        raise ValueError("name_weight must be at least 1")
    name = document.name.strip()
    if not name:
        return document.text
    return " ".join([name] * name_weight + [document.text])
