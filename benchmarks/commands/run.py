"""Benchmark command exfiltration detection.

Compares three deterministic detectors on the synthetic set (generate.py):
  - risk sensitive-path : does risk.py already score the command sensitive?
                          (band >= escalate). This is the current gateway.
  - exfil rule          : safety/exfil.detect — sensitive source AND egress.
  - both                : exfil rule OR risk band critical.

    python benchmarks/commands/run.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sandbox.connector.risk import assess  # noqa: E402
from sandbox.safety.exfil import detect  # noqa: E402


def load() -> list[dict]:
    return [json.loads(line) for line in (HERE / "commands.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def risk_flags_sensitive(command: str) -> bool:
    # The current gateway signal: does the risk score treat this command as
    # sensitive enough to raise the tier? (shell base is 45 = escalate already;
    # we ask whether a *sensitive-resource* factor was added.)
    a = assess(trigger="shell", command=command)
    return any(f.name == "sensitive-resource" for f in a.factors)


def metrics(preds: list[bool], labels: list[int]) -> dict:
    tp = sum(p and y for p, y in zip(preds, labels))
    fp = sum(p and not y for p, y in zip(preds, labels))
    pos, neg = sum(labels), len(labels) - sum(labels)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / pos if pos else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"caught": f"{tp}/{pos}", "false_alarms": f"{fp}/{neg}", "precision": round(prec, 3), "f1": round(f1, 3)}


def main() -> None:
    rows = load()
    labels = [r["label"] for r in rows]
    sens = [risk_flags_sensitive(r["command"]) for r in rows]
    exf = [detect(r["command"]) is not None for r in rows]
    systems = {
        "risk sensitive-path (current)": sens,
        "exfil rule (sensitive + egress)": exf,
        "both": [a or b for a, b in zip(sens, exf)],
    }
    print(f"{len(rows)} commands ({sum(labels)} exfil, {len(labels)-sum(labels)} benign)\n")
    print(f"{'system':34} {'caught':>9} {'false alarms':>13} {'precision':>10} {'F1':>6}")
    for name, preds in systems.items():
        m = metrics(preds, labels)
        print(f"{name:34} {m['caught']:>9} {m['false_alarms']:>13} {m['precision']:>10.2f} {m['f1']:>6.2f}")

    fp = [r for r, p in zip(rows, exf) if p and not r["label"]]
    fn = [r for r, p in zip(rows, exf) if r["label"] and not p]
    if fp:
        print("\nexfil-rule false alarms:")
        for r in fp:
            print(f"  [{r['kind']}] {r['command']}")
    if fn:
        print("\nexfil-rule missed:")
        for r in fn:
            print(f"  {r['command']}")


if __name__ == "__main__":
    main()
