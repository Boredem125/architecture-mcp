"""The phase-2 student: a distilled injection classifier that runs in-process.

It reads text once (no per-question re-reads, no model server): TF-IDF over
word 1-2 grams and character 2-5 grams, then a linear layer. This is a pure
Python re-implementation of the scikit-learn pipeline trained by
benchmarks/distill/train.py, so the gateway needs no ML dependency and a hook
subprocess can load it in milliseconds.

Model file (gzipped JSON, written by ``train.py --export``)::

    {"threshold": float, "intercept": float,
     "word": {"vocab": {term: [idf, weight]}}, "char": {"vocab": {...}}}

Only terms the training kept are stored; each carries its IDF and its
logistic-regression weight, which is all a sparse dot product needs.
"""
from __future__ import annotations

import gzip
import json
import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

_WORD = re.compile(r"(?u)\b\w\w+\b")
_SPACES = re.compile(r"\s\s+")


def _word_terms(text: str) -> Counter[str]:
    toks = _WORD.findall(text.lower())
    return Counter(toks + [f"{a} {b}" for a, b in zip(toks, toks[1:])])


def _char_terms(text: str) -> Counter[str]:
    """scikit-learn's ``char_wb`` analyzer, n = 2..5."""
    out: Counter[str] = Counter()
    for word in _SPACES.sub(" ", text.lower()).split():
        w = f" {word} "
        for n in range(2, 6):
            for i in range(len(w) - n + 1):
                out[w[i:i + n]] += 1
            if len(w) < n:  # sklearn stops once the word is shorter than n
                break
    return out


def _block(terms: Counter[str], vocab: dict[str, list[float]]) -> float:
    """Dot product of one l2-normalised sublinear TF-IDF block with its weights."""
    num, norm = 0.0, 0.0
    for term, tf in terms.items():
        entry = vocab.get(term)
        if entry is None:
            continue
        v = (1.0 + math.log(tf)) * entry[0]
        norm += v * v
        num += v * entry[1]
    return num / math.sqrt(norm) if norm else 0.0


class Student:
    def __init__(self, model: dict) -> None:
        self.threshold = float(model["threshold"])
        self.intercept = float(model["intercept"])
        self.word = model["word"]["vocab"]
        self.char = model["char"]["vocab"]

    @classmethod
    def load(cls, path: str | Path) -> Student:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return cls(json.load(f))

    def probability(self, text: str) -> float:
        z = self.intercept + _block(_word_terms(text), self.word) + _block(_char_terms(text), self.char)
        return 1.0 / (1.0 + math.exp(-z)) if z > -30 else 0.0

    def flags(self, text: str) -> bool:
        return self.probability(text) >= self.threshold


DEFAULT_MODEL = Path(__file__).with_name("student-injection.json.gz")


@lru_cache(maxsize=1)
def default() -> Student | None:
    """The bundled model, or None if it isn't shipped (callers then skip it)."""
    return Student.load(DEFAULT_MODEL) if DEFAULT_MODEL.exists() else None
