"""Build the phase-2 training pool, keeping every held-out set out of it.

    python benchmarks/distill/data.py

Sources (all Apache-2.0):
- prodnull repo-file rows *outside* the fixed 600-row benchmark sample
- neuralchemy `core` train split
- deepset train split

Held out, never trained on: deepset test, neuralchemy test, the repo-file
sample (seed 20260930), and the hand-written dev sets. A training row is
dropped if its normalised text equals a held-out text, or if it is a near
copy of one (character 3-5-gram TF-IDF cosine >= 0.8, e.g. "Set up
pre-commit hooks..." vs "Configure pre-commit hooks..."), so rewordings
across splits can't leak. Text is redacted (src/sandbox/semantic/redact.py) before
it's stored, so only redacted text is ever sent to the labeller.

Writes benchmarks/.cache/distill-pool.jsonl (gitignored).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "benchmarks" / "injection"))

import run as bench  # noqa: E402
from sandbox.semantic.redact import redact  # noqa: E402

POOL = bench.CACHE / "distill-pool.jsonl"


def norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


NEAR_COPY = 0.8


def held_out_texts() -> list[str]:
    held = bench.load_deepset("test") + bench.load_neuralchemy("test") + bench.load_agent_set() + bench.load_embedded()
    repo = bench.load_repo_files()
    if repo is None:
        raise SystemExit("repo-file dataset not cached; the held-out sample can't be excluded")
    return [r["text"] for r in held + repo]


def near_copies(texts: list[str], held: list[str]) -> list[bool]:
    """True where a text is a near copy of any held-out text."""
    from sklearn.feature_extraction.text import TfidfVectorizer

    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5)).fit(texts + held)
    h = vec.transform(held).T.tocsc()
    out = []
    for start in range(0, len(texts), 500):
        sims = vec.transform(texts[start:start + 500]) @ h
        out += list(sims.max(axis=1).toarray().ravel() >= NEAR_COPY)
    return out


def main() -> None:
    held_texts = held_out_texts()
    held = {norm(t) for t in held_texts}
    sample_ids = {r["id"] for r in bench.load_repo_files()}
    raw = [json.loads(line) for line in (bench.CACHE / "prodnull-repo-files-train.jsonl")
           .read_text(encoding="utf-8").splitlines() if line.strip()]
    candidates = [("repo", f"r{i}", r["text"], int(r["label"])) for i, r in enumerate(raw) if f"r{i}" not in sample_ids]
    candidates += [("neuralchemy", r["id"], r["text"], r["label"]) for r in bench.load_neuralchemy("train")]
    candidates += [("deepset", f"d{r['id']}", r["text"], r["label"]) for r in bench.load_deepset("train")]

    near = near_copies([c[2] for c in candidates], held_texts)
    seen: set[str] = set()
    stats: dict[str, dict[str, int]] = {}
    out = []
    for (source, rid, text, label), is_near in zip(candidates, near):
        s = stats.setdefault(source, {"kept": 0, "held_out_dup": 0, "near_copy": 0, "dup": 0})
        key = norm(text)
        if key in held:
            s["held_out_dup"] += 1
            continue
        if is_near:
            s["near_copy"] += 1
            continue
        if key in seen:
            s["dup"] += 1
            continue
        seen.add(key)
        s["kept"] += 1
        out.append({"id": f"{source}:{rid}", "source": source, "text": redact(text), "label": label})
    POOL.write_text("".join(json.dumps(r) + "\n" for r in out), encoding="utf-8")
    for source, s in stats.items():
        print(f"{source:12} kept {s['kept']:5}  dropped: {s['held_out_dup']} held-out duplicates, {s['near_copy']} near copies, {s['dup']} repeats")
    print(f"wrote {len(out)} rows to {POOL}")


if __name__ == "__main__":
    main()
