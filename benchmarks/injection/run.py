"""Prompt-injection benchmark: the gateway's regex detector vs its semantic layer.

    python benchmarks/injection/run.py                  # base model
    python benchmarks/injection/run.py --model xsmall
    python benchmarks/injection/run.py --reuse           # re-score the student only

The semantic system here is the gateway's own pipeline, imported from
src/sandbox/semantic/scan.py (prepare → per-segment checks → verdict), so
the benchmark measures exactly what runs in PostToolUse.

Datasets
- agent_set.jsonl   hand-written, agent context (indirect injection in READMEs,
                    web pages, tool output, code comments + benign developer
                    text). Checks were chosen with it in view: a development set.
- embedded          each agent_set text planted inside an ordinary README.
- deepset           deepset/prompt-injections test split (Apache-2.0), fetched
                    and cached in benchmarks/.cache. Held out: nothing tuned on it.
- deepset, genuine  the same rows, keeping only the injections the author judged
                    genuine (deepset_test_review.json); arguable rows dropped.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CACHE = ROOT / "benchmarks" / ".cache"
sys.path.insert(0, str(ROOT / "src"))

from sandbox.safety.injection_detector import InjectionDetector  # noqa: E402
from sandbox.semantic import scan as pipeline  # noqa: E402
from sandbox.semantic.checks import INJECTION_CHECKS  # noqa: E402

THRESHOLD = 0.5


def load_agent_set() -> list[dict]:
    rows = [json.loads(line) for line in (HERE / "agent_set.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    return [{"id": r["id"], "text": r["text"], "label": r["label"]} for r in rows]


README_BEFORE = (
    "# Project\n"
    "A small library for parsing configuration files. It supports YAML, TOML and JSON.\n"
    "## Installation\n"
    "Install it with pip, then import the loader in your application code.\n"
)
README_AFTER = (
    "\n## Contributing\n"
    "Please run the test suite before opening a pull request, and keep changes focused.\n"
    "Released under the MIT license."
)


def load_embedded() -> list[dict]:
    """Each agent_set text planted inside an otherwise ordinary README."""
    return [{**r, "text": README_BEFORE + r["text"] + README_AFTER} for r in load_agent_set()]


def load_fresh_dev() -> list[dict]:
    """The round-2 gate set, frozen before retraining (see benchmarks/distill/README.md)."""
    rows = [json.loads(line) for line in (HERE / "fresh_dev.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    return [{"id": r["id"], "text": r["text"], "label": r["label"], "category": r["kind"]} for r in rows]


def _fetch_hf(dataset: str, config: str, split: str, cache_name: str) -> list[dict]:
    """All rows of a public HF dataset split, via the datasets-server API, cached."""
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / cache_name
    if not path.exists():
        rows, offset = [], 0
        while True:
            url = (f"https://datasets-server.huggingface.co/rows?dataset={dataset}"
                   f"&config={config}&split={split}&offset={offset}&length=100")
            with urllib.request.urlopen(url, timeout=60) as resp:
                data = json.load(resp)
            rows += [r["row"] for r in data["rows"]]
            offset += 100
            if offset >= data["num_rows_total"]:
                break
        path.write_text(json.dumps(rows), encoding="utf-8")
    return json.loads(path.read_text(encoding="utf-8"))


def load_deepset(split: str = "test") -> list[dict]:
    rows = _fetch_hf("deepset/prompt-injections", "default", split, f"deepset-prompt-injections-{split}.json")
    return [{"id": str(i), "text": r["text"], "label": int(r["label"])} for i, r in enumerate(rows)]


def load_neuralchemy(split: str = "test") -> list[dict]:
    """neuralchemy/Prompt-injection-dataset (Apache-2.0), `core` config. Held out."""
    rows = _fetch_hf("neuralchemy/Prompt-injection-dataset", "core", split, f"neuralchemy-core-{split}.json")
    return [{"id": f"n{i}", "text": r["text"], "label": int(r["label"]), "category": r.get("category") or "?"}
            for i, r in enumerate(rows)]


REPO_FILES = "prodnull/prompt-injection-repo-dataset"
REPO_SAMPLE = 600  # the full 5,671 rows take ~1 h on a laptop CPU


def load_repo_files(sample: int = REPO_SAMPLE, seed: int = 20260930) -> list[dict] | None:
    """Injections planted in repository files (Apache-2.0, gated on Hugging Face).

    Needs HF_TOKEN from an account that accepted the dataset's terms; returns
    None (dataset skipped) without it. A fixed-seed stratified sample keeps the
    run short and repeatable. Held out: nothing was tuned on it.
    """
    import os
    import random

    token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")
    path = CACHE / "prodnull-repo-files-train.jsonl"
    if not path.exists():
        if not token:
            return None
        CACHE.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(
            f"https://huggingface.co/datasets/{REPO_FILES}/resolve/main/train.jsonl",
            headers={"Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                path.write_bytes(resp.read())
        except urllib.error.HTTPError as e:
            print(f"skipping {REPO_FILES}: HTTP {e.code} (accept the dataset terms on Hugging Face?)")
            return None
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rng = random.Random(seed)
    by_label: dict[int, list[int]] = {0: [], 1: []}
    for i, r in enumerate(rows):
        by_label[int(r["label"])].append(i)
    picked = []
    for label, idx in by_label.items():
        share = round(sample * len(idx) / len(rows))
        picked += rng.sample(idx, min(share, len(idx)))
    return [{"id": f"r{i}", "text": rows[i]["text"], "label": int(rows[i]["label"])} for i in sorted(picked)]


def genuine_view(rows: list[dict]) -> list[dict]:
    """deepset rows with the author-judged 'arguable' injections removed."""
    import hashlib

    review = json.loads((HERE / "deepset_test_review.json").read_text(encoding="utf-8"))["rows"]
    keep = []
    for r in rows:
        v = review.get(r["id"])
        if r["label"] == 1:
            if v is None or v["sha256"] != hashlib.sha256(r["text"].encode()).hexdigest():
                raise SystemExit(f"review out of date for row {r['id']}")
            if v["verdict"] != "genuine":
                continue
        keep.append(r)
    return keep


class Regex:
    def __init__(self) -> None:
        self.d = InjectionDetector()

    def __call__(self, text: str) -> str:
        return "high" if self.d.scan(text)[0] else "none"


class Semantic:
    """The gateway pipeline, run in-process instead of through `jevos serve`."""

    def __init__(self, model: str) -> None:
        from jevos import Client, questions_from_dict

        self.client = Client(model=model)
        self.questions = questions_from_dict(INJECTION_CHECKS)
        self.ms: list[float] = []

    def __call__(self, text: str) -> str:
        start = time.perf_counter()
        tiers = []
        for seg in pipeline.prepare(text):
            r = self.client.system_one(seg, self.questions)
            tiers.append(pipeline.verdict({k: a.noul for k, a in r.answers.items()}, THRESHOLD))
        self.ms.append((time.perf_counter() - start) * 1000)
        if "high" in tiers:
            return "high"
        return "medium" if "medium" in tiers else "none"


class StudentScan:
    """The phase-2 student (src/sandbox/semantic/student.py), per segment like the
    gateway: the text is flagged if any redacted segment scores >= its threshold."""

    def __init__(self) -> None:
        from sandbox.semantic import student
        from sandbox.semantic.redact import redact

        self.model = student.default()
        self.redact = redact

    def __call__(self, text: str) -> bool:
        return any(self.model.flags(self.redact(seg)) for seg in pipeline.prepare(text))


def metrics(flags: list[bool], labels: list[int]) -> dict:
    tp = sum(f and y for f, y in zip(flags, labels))
    fp = sum(f and not y for f, y in zip(flags, labels))
    pos, neg = sum(labels), len(labels) - sum(labels)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / pos if pos else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"caught": f"{tp}/{pos}", "false_alarms": f"{fp}/{neg}", "recall": round(recall, 3),
            "precision": round(precision, 3), "f1": round(f1, 3)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="base")
    ap.add_argument("--out", default=str(HERE / "results.json"))
    ap.add_argument("--reuse", action="store_true",
                    help="reuse every cached regex/jev-os prediction; only the student is scored")
    ap.add_argument("--only", default="",
                    help="re-run only datasets whose name contains this; the rest reuse cached predictions")
    args = ap.parse_args()

    regex = Regex()
    sem = None
    if not args.reuse:
        sem = Semantic(args.model)
        sem("warm up")
        sem.ms.clear()
    stu = StudentScan()

    deepset = load_deepset()
    neural = load_neuralchemy()
    sources = {"agent_set (dev, hand-written)": load_agent_set(),
               "embedded in a README (dev)": load_embedded(),
               "deepset test (held out)": deepset,
               "neuralchemy test (held out)": neural,
               "fresh dev (round-2 gate)": load_fresh_dev()}
    repo = load_repo_files()
    if repo is None:
        print(f"note: {REPO_FILES} skipped (gated; set HF_TOKEN after accepting its terms)")
    else:
        sources[f"repo files, {len(repo)}-row sample (held out)"] = repo
    # Per-row predictions are cached so other combinations (and --only runs)
    # don't need the model again.
    preds_path = CACHE / f"preds-{args.model}.json"
    preds: dict[str, dict[str, list[str]]] = {}
    if (args.only or args.reuse) and preds_path.exists():
        preds = json.loads(preds_path.read_text(encoding="utf-8"))
    for name, rows in sources.items():
        if (args.reuse or (args.only and args.only not in name)) and name in preds:
            continue
        preds[name] = {r["id"]: [regex(r["text"]), sem(r["text"])] for r in rows}
    preds_path.write_text(json.dumps(preds), encoding="utf-8")
    views = {**sources, "deepset test, genuine attacks only": genuine_view(deepset)}
    preds["deepset test, genuine attacks only"] = preds["deepset test (held out)"]

    report = {"model": args.model, "threshold": THRESHOLD, "checks": list(INJECTION_CHECKS),
              "student_threshold": stu.model.threshold if stu.model else None, "results": {}}
    for name, rows in views.items():
        p = preds[name]
        labels = [r["label"] for r in rows]
        rx = [p[r["id"]][0] == "high" for r in rows]
        taint = [p[r["id"]][1] == "high" for r in rows]
        warn = [p[r["id"]][1] in ("high", "medium") for r in rows]
        systems = {"regex (current gateway)": rx, "semantic": taint,
                   "regex OR semantic": [a or b for a, b in zip(rx, taint)]}
        if stu.model is not None:
            st = [stu(r["text"]) for r in rows]
            systems["student (phase 2)"] = st
            systems["semantic OR student"] = [a or b for a, b in zip(taint, st)]
        report["results"][name] = {
            "n": len(rows),
            "systems": {k: metrics(v, labels) for k, v in systems.items()},
            "missed": [r["text"][-200:] for r, f in zip(rows, taint) if r["label"] and not f][:40],
            "false_alarms": [r["text"][-200:] for r, f in zip(rows, taint) if not r["label"] and f][:40],
        }
    # Per-category recall on neuralchemy (attack rows), plus false alarms on benign rows.
    p = preds["neuralchemy test (held out)"]
    cats: dict[str, dict[str, int]] = {}
    for r in neural:
        c = cats.setdefault(r["category"], {"n": 0, "regex": 0, "semantic": 0})
        c["n"] += 1
        c["regex"] += p[r["id"]][0] == "high"
        c["semantic"] += p[r["id"]][1] == "high"
    report["neuralchemy_by_category"] = cats

    ms = sorted(sem.ms) if sem else []
    if ms:
        report["semantic_ms_per_text"] = {"p50": round(ms[len(ms) // 2], 1), "p95": round(ms[int(0.95 * (len(ms) - 1))], 1)}
    elif Path(args.out).exists():  # nothing re-run: keep the last measured latency
        report["semantic_ms_per_text"] = json.loads(Path(args.out).read_text(encoding="utf-8")).get("semantic_ms_per_text", {})

    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    for name, res in report["results"].items():
        print(f"\n== {name}  (n={res['n']})")
        print(f"   {'system':26} {'caught':>9} {'false alarms':>13} {'precision':>10} {'F1':>6}")
        for sname, m in res["systems"].items():
            print(f"   {sname:26} {m['caught']:>9} {m['false_alarms']:>13} {m['precision']:>10.2f} {m['f1']:>6.2f}")
    print("\n== neuralchemy by category (flagged / rows; for 'benign' these are false alarms)")
    print(f"   {'category':22} {'rows':>5} {'regex':>7} {'semantic':>9}")
    for cat, c in sorted(report["neuralchemy_by_category"].items(), key=lambda kv: -kv[1]["n"]):
        print(f"   {cat:22} {c['n']:>5} {c['regex']:>7} {c['semantic']:>9}")
    lat = report.get("semantic_ms_per_text") or {}
    print(f"\nsemantic ms per text (this run): p50 {lat.get('p50')}, p95 {lat.get('p95')}")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
