"""Train one small classifier per governance clause (see README.md).

    python benchmarks/governance/train.py

Training data: benchmarks/.cache/governance-train.jsonl (generate.py train:
written by gpt-oss-120b, labelled by qwen; near copies of test commands
dropped). Each clause gets a binary TF-IDF + logistic-regression model on
"description + command" (the injection student's pipeline and runtime). The
threshold maximises F1 on a held-back 30% of the training data, never on the
benchmark. Models are written to src/sandbox/governance/examples/students/.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "benchmarks" / "distill"), str(ROOT / "benchmarks" / "injection")]

import importlib.util  # noqa: E402

from sandbox.governance.policy import example_policy_path, load  # noqa: E402


def _load(name: str, path: Path):
    # By path: train.py and run.py exist under several benchmark folders.
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


distill = _load("distill_train", ROOT / "benchmarks" / "distill" / "train.py")  # build, export
text_of = _load("governance_run", HERE / "run.py").text_of

TRAIN = ROOT / "benchmarks" / ".cache" / "governance-train.jsonl"
OUT = ROOT / "src" / "sandbox" / "governance" / "examples" / "students"


def main() -> None:
    rows = [json.loads(x) for x in TRAIN.read_text(encoding="utf-8").splitlines() if x.strip()]
    rng = np.random.default_rng(20261002)
    held = rng.random(len(rows)) < 0.3
    OUT.mkdir(parents=True, exist_ok=True)
    for clause in load(example_policy_path()).clauses:
        y = np.array([clause.id in r["violates"] for r in rows], dtype=int)
        texts = [text_of(r) for r in rows]
        tr = [i for i in range(len(rows)) if not held[i]]
        va = [i for i in range(len(rows)) if held[i]]
        model = distill.build().fit([texts[i] for i in tr], y[tr])
        p = model.predict_proba([texts[i] for i in va])[:, 1]
        best = (0.0, 0.5)
        for t in np.arange(0.2, 0.9, 0.02):
            flag = p >= t
            tp = int((flag & (y[va] == 1)).sum())
            prec = tp / flag.sum() if flag.sum() else 0.0
            rec = tp / max(1, (y[va] == 1).sum())
            f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
            if f1 > best[0]:
                best = (f1, round(float(t), 2))
        # Final model on all training rows, with the threshold chosen above.
        final = distill.build().fit(texts, y)
        path = OUT / f"{clause.id}.json.gz"
        distill.export(final, best[1], path, keep=60_000)
        print(f"{clause.id}: {int(y.sum())} positive of {len(rows)}; validation F1 {best[0]:.2f} at "
              f"threshold {best[1]}; wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
