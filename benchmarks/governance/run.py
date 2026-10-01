"""Score governance clauses on escalated shell commands (see README.md).

    python benchmarks/governance/run.py              # dev half
    python benchmarks/governance/run.py --split test # the one test run

Per (command, clause) pair, on "description + command" as the hook evaluates it:
  baseline     today's evaluate(): clause check AND requires_actions gate
  student      the clause's distilled classifier (benchmarks/governance/train.py) AND the gate
  either       baseline OR student
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sandbox.governance.evaluate import _gate_ok  # noqa: E402
from sandbox.governance.policy import example_policy_path, load  # noqa: E402


def rows(split: str) -> list[dict]:
    out = [json.loads(x) for x in (HERE / "commands.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    odd = {"dev": 0, "test": 1}[split]
    return [r for r in out if int(hashlib.sha256(r["id"].encode()).hexdigest(), 16) % 2 == odd]


def text_of(r: dict) -> str:
    # What hook_eval._evaluate_governance passes: the description, then the command.
    return " ".join(x for x in (r["description"], r["command"]) if x)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["dev", "test"], default="dev")
    ap.add_argument("--model", default="base")
    args = ap.parse_args()
    from jevos import Client, questions_from_dict

    from sandbox.governance.student import load_students

    policy = load(example_policy_path())
    clauses = {c.id: c for c in policy.clauses}
    students = load_students(policy)
    client = Client(model=args.model)
    questions = questions_from_dict({c.id: c.question() for c in policy.clauses})
    data = rows(args.split)

    pairs = []
    for r in data:
        text = text_of(r)
        scores = {k: a.noul for k, a in client.system_one(text, questions).answers.items()}
        for cid, c in clauses.items():
            gate = _gate_ok(c, r["command"])
            check = scores[cid] >= c.threshold
            stu = students[cid].flags(text) if cid in students else False
            pairs.append({"id": r["id"], "clause": cid, "truth": cid in r["violates"], "benign": not r["violates"],
                          "baseline": gate and check, "student": gate and stu, "either": gate and (check or stu)})

    benign = [r for r in data if not r["violates"]]
    report = {"split": args.split, "commands": len(data), "benign_commands": len(benign), "systems": {}}
    print(f"{args.split}: {len(data)} commands, {len(benign)} benign; students for {sorted(students)}")
    print(f"   {'system':9} {'recall':>12} {'benign flagged':>15}  per clause (caught/pos, false alarms)")
    for name in ("baseline", "student", "either"):
        pos = [p for p in pairs if p["truth"]]
        caught = sum(p[name] for p in pos)
        fa = {p["id"] for p in pairs if p[name] and p["benign"]}
        per = {cid: {"caught": sum(p[name] for p in pairs if p["clause"] == cid and p["truth"]),
                     "positives": sum(p["truth"] for p in pairs if p["clause"] == cid),
                     "false_alarms": sum(p[name] for p in pairs if p["clause"] == cid and not p["truth"])}
               for cid in clauses}
        report["systems"][name] = {"caught": caught, "positives": len(pos), "recall": round(caught / len(pos), 3),
                                   "benign_flagged": len(fa), "per_clause": per}
        per_txt = "  ".join(f"{k[3:7]} {v['caught']}/{v['positives']},{v['false_alarms']}" for k, v in per.items())
        print(f"   {name:9} {caught:>3}/{len(pos):<3} {caught / len(pos):.2f} {len(fa):>7}/{len(benign):<6}  {per_txt}")
    (HERE / f"results-{args.split}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
