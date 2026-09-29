"""Prompt-injection benchmark: the gateway's regex detector vs jev-os (semantic).

    python benchmarks/injection/run.py                  # both datasets, base model
    python benchmarks/injection/run.py --model xsmall

Datasets
- agent_set.jsonl  hand-written, agent-context (indirect injection in READMEs,
                   web pages, tool output, code comments + benign developer text).
                   The jev-os statements were chosen with this set in view, so
                   treat it as a development set.
- deepset          deepset/prompt-injections, test split (Apache-2.0), fetched
                   from Hugging Face and cached in benchmarks/.cache. Held out:
                   nothing was tuned on it. Note its labels are broad (role-play
                   requests such as "act as an interviewer" count as injection)
                   and some rows are German.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CACHE = ROOT / "benchmarks" / ".cache"
sys.path.insert(0, str(ROOT / "src"))

from sandbox.safety.injection_detector import InjectionDetector  # noqa: E402
from sandbox.semantic.checks import INJECTION_CHECKS  # noqa: E402

THRESHOLD = 0.5


def load_agent_set() -> list[dict]:
    rows = [json.loads(line) for line in (HERE / "agent_set.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    return [{"text": r["text"], "label": r["label"], "group": r["channel"]} for r in rows]


def load_deepset(split: str = "test") -> list[dict]:
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / f"deepset-prompt-injections-{split}.json"
    if not path.exists():
        rows, offset = [], 0
        while True:
            url = ("https://datasets-server.huggingface.co/rows?dataset=deepset/prompt-injections"
                   f"&config=default&split={split}&offset={offset}&length=100")
            with urllib.request.urlopen(url, timeout=60) as resp:
                data = json.load(resp)
            rows += [r["row"] for r in data["rows"]]
            offset += 100
            if offset >= data["num_rows_total"]:
                break
        path.write_text(json.dumps(rows), encoding="utf-8")
    rows = json.loads(path.read_text(encoding="utf-8"))
    return [{"text": r["text"], "label": int(r["label"]), "group": "deepset"} for r in rows]


class RegexDetector:
    name = "regex (current gateway)"

    def __init__(self) -> None:
        self.d = InjectionDetector()

    def __call__(self, text: str) -> tuple[bool, float]:
        start = time.perf_counter()
        flagged = self.d.scan(text)[0]
        return flagged, (time.perf_counter() - start) * 1000


class JevDetector:
    def __init__(self, model: str) -> None:
        from jevos import Client, questions_from_dict

        self.client = Client(model=model)
        self.questions = questions_from_dict(INJECTION_CHECKS)
        self.name = f"jev-os ({model})"

    def scores(self, text: str) -> tuple[dict[str, float], float]:
        r = self.client.system_one(text, self.questions)
        return {k: a.noul for k, a in r.answers.items()}, r.latency_ms

    def __call__(self, text: str) -> tuple[bool, float]:
        s, ms = self.scores(text)
        return max(s.values()) >= THRESHOLD, ms


def metrics(preds: list[bool], labels: list[int]) -> dict:
    tp = sum(p and y for p, y in zip(preds, labels))
    fp = sum(p and not y for p, y in zip(preds, labels))
    fn = sum((not p) and y for p, y in zip(preds, labels))
    tn = sum((not p) and not y for p, y in zip(preds, labels))
    pos, neg = tp + fn, fp + tn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / pos if pos else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"caught": f"{tp}/{pos}", "false_alarms": f"{fp}/{neg}", "recall": recall,
            "fpr": fp / neg if neg else 0.0, "precision": precision, "f1": f1}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="base")
    ap.add_argument("--out", default=str(HERE / "results.json"))
    args = ap.parse_args()

    datasets = {"agent_set (dev, hand-written)": load_agent_set(), "deepset test (held out)": load_deepset()}
    regex, jev = RegexDetector(), JevDetector(args.model)
    jev("warm up")

    report = {"model": args.model, "threshold": THRESHOLD, "results": {}}
    for dname, rows in datasets.items():
        labels = [r["label"] for r in rows]
        rx = [regex(r["text"]) for r in rows]
        jv = [jev(r["text"]) for r in rows]
        rx_p, jv_p = [p for p, _ in rx], [p for p, _ in jv]
        systems = {
            "regex (current gateway)": rx_p,
            f"jev-os {args.model}": jv_p,
            "regex OR jev-os": [a or b for a, b in zip(rx_p, jv_p)],
        }
        lat = sorted(ms for _, ms in jv)
        report["results"][dname] = {
            "n": len(rows),
            "systems": {k: metrics(v, labels) for k, v in systems.items()},
            "jev_latency_ms": {"p50": round(statistics.median(lat), 1), "p95": round(lat[int(0.95 * (len(lat) - 1))], 1)},
            "misses": {
                "jev_false_negatives": [r["text"][:120] for r, p in zip(rows, jv_p) if r["label"] and not p][:15],
                "jev_false_positives": [r["text"][:120] for r, p in zip(rows, jv_p) if not r["label"] and p][:15],
            },
        }

    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    for dname, res in report["results"].items():
        print(f"\n== {dname}  (n={res['n']}, jev-os latency p50 {res['jev_latency_ms']['p50']} ms, p95 {res['jev_latency_ms']['p95']} ms)")
        print(f"   {'system':26} {'caught':>9} {'false alarms':>13} {'precision':>10} {'F1':>6}")
        for name, m in res["systems"].items():
            print(f"   {name:26} {m['caught']:>9} {m['false_alarms']:>13} {m['precision']:>10.2f} {m['f1']:>6.2f}")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
