"""Train the single-pass student and score it on the held-out sets.

    python benchmarks/distill/train.py                    # dataset labels
    python benchmarks/distill/train.py --labels groq      # labeller-corrected labels
    python benchmarks/distill/train.py --exclude-source repo   # transfer: no repo-file training rows

The student is TF-IDF (word 1-2 grams + char 2-5 grams) into logistic
regression: it reads the text once, runs in well under a millisecond, and
needs no model download. The threshold is picked on a validation slice of the
training pool, never on a held-out set.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, make_pipeline

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "benchmarks" / "injection"))

import run as bench  # noqa: E402
from sandbox.semantic import scan as pipeline  # noqa: E402
from sandbox.semantic.redact import redact  # noqa: E402

POOL = bench.CACHE / "distill-pool.jsonl"
LABELS = bench.CACHE / "distill-groq-labels.jsonl"
QUEUE = bench.CACHE / "distill-label-queue.jsonl"


def load_pool(labels: str) -> list[dict]:
    """The training pool. With labels="groq", disputed rows take the labeller's
    answer and the labelled documentation lines are added."""
    rows = [json.loads(line) for line in POOL.read_text(encoding="utf-8").splitlines() if line.strip()]
    if labels == "groq":
        groq = {}
        for line in LABELS.read_text(encoding="utf-8").splitlines():
            if line.strip():
                g = json.loads(line)
                groq[g["id"]] = int(g["injection"])
        for r in rows:
            r["label"] = groq.get(r["id"], r["label"])
        queue = [json.loads(line) for line in QUEUE.read_text(encoding="utf-8").splitlines() if line.strip()]
        rows += [{"id": q["id"], "source": "docs", "text": q["text"], "label": groq[q["id"]]}
                 for q in queue if q["kind"] == "docs" and q["id"] in groq]
    return rows


def build() -> object:
    feats = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, max_features=200_000)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=3, sublinear_tf=True,
                                 max_features=300_000)),
    ])
    return make_pipeline(feats, LogisticRegression(C=4.0, max_iter=3000, class_weight="balanced"))


def export(model: object, threshold: float, path: Path, keep: int) -> None:
    """Write the gateway's model file (see src/sandbox/semantic/student.py).

    Only the ``keep`` terms with the largest absolute weight are stored; the
    rest are dropped from both the dot product and the norm, so the shipped
    model is re-scored with the runtime student rather than assumed equal.
    """
    import gzip

    union, lr = model.steps[0][1], model.steps[1][1]
    coef = lr.coef_[0]
    cut = np.sort(np.abs(coef))[-keep] if keep < len(coef) else 0.0
    out = {"threshold": threshold, "intercept": float(lr.intercept_[0])}
    offset = 0
    for name, vec in union.transformer_list:
        vocab = {}
        for term, j in vec.vocabulary_.items():
            w = coef[offset + j]
            if abs(w) >= cut:
                vocab[term] = [round(float(vec.idf_[j]), 5), round(float(w), 5)]
        offset += len(vec.vocabulary_)
        out[name] = {"vocab": vocab}
    with gzip.open(path, "wt", encoding="utf-8") as f:
        json.dump(out, f, separators=(",", ":"))


def held_out() -> dict[str, list[dict]]:
    deepset = bench.load_deepset()
    return {
        "repo files, 600-row sample (held out)": bench.load_repo_files(),
        "deepset test (held out)": deepset,
        "deepset test, genuine attacks only": bench.genuine_view(deepset),
        "neuralchemy test (held out)": bench.load_neuralchemy(),
        "agent_set (dev, hand-written)": bench.load_agent_set(),
        "embedded in a README (dev)": bench.load_embedded(),
    }


def score(model: object, text: str, per_segment: bool) -> float:
    segs = pipeline.prepare(text) if per_segment else [text]
    segs = [redact(s) for s in segs] or [""]
    return float(model.predict_proba(segs)[:, 1].max())


class _RuntimeAdapter:
    """Lets score() run the exported pure-Python student, so reported numbers
    are the shipped model's."""

    def __init__(self, student: object) -> None:
        self.student = student

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        p = np.array([self.student.probability(t) for t in texts])
        return np.stack([1 - p, p], axis=1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", choices=["dataset", "groq"], default="dataset")
    ap.add_argument("--exclude-source", default="",
                    help="train without this pool source (repo, neuralchemy, deepset) to measure transfer")
    ap.add_argument("--export", default="", help="also write the gateway model file here")
    ap.add_argument("--keep", type=int, default=100_000, help="terms kept in the exported model")
    ap.add_argument("--out", default=str(HERE / "results.json"))
    args = ap.parse_args()

    rows = [r for r in load_pool(args.labels) if r["source"] != args.exclude_source]
    rng = np.random.default_rng(20261001)
    val_mask = rng.random(len(rows)) < 0.15
    train = [r for r, v in zip(rows, val_mask) if not v]
    val = [r for r, v in zip(rows, val_mask) if v]

    model = build().fit([r["text"] for r in train], [r["label"] for r in train])
    # Threshold: the lowest one that reaches validation precision >= 0.9 (false
    # alarms cost approvals), falling back to 0.5.
    p = model.predict_proba([r["text"] for r in val])[:, 1]
    y = np.array([r["label"] for r in val])
    threshold = 0.5
    for t in np.arange(0.3, 0.95, 0.01):
        flag = p >= t
        if flag.sum() and (y[flag].mean() >= 0.9):
            threshold = round(float(t), 2)
            break
    print(f"train {len(train)}, val {len(val)}, threshold {threshold}")

    runtime = None
    if args.export:
        from sandbox.semantic.student import Student

        export(model, threshold, Path(args.export), args.keep)
        runtime = Student.load(args.export)
        model = _RuntimeAdapter(runtime)

    report = {"labels": args.labels, "excluded_source": args.exclude_source or None, "threshold": threshold, "results": {}}
    for name, data in held_out().items():
        labels = [r["label"] for r in data]
        res = {}
        for mode in (False, True):
            flags = [score(model, r["text"], mode) >= threshold for r in data]
            res["per segment" if mode else "whole text"] = bench.metrics(flags, labels)
        report["results"][name] = res
        print(f"\n== {name} (n={len(data)})")
        for mode, m in res.items():
            print(f"   student, {mode:12} caught {m['caught']:>9}  FA {m['false_alarms']:>9}  "
                  f"precision {m['precision']:.2f}  F1 {m['f1']:.2f}")
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
