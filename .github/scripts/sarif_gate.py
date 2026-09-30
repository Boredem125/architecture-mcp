"""Fail the build when a SARIF file has results at or above a severity level.

    python .github/scripts/sarif_gate.py semgrep.sarif:error gitleaks.sarif:note

Levels, lowest to highest: note < warning < error. Each tool's SARIF maps its
own severities onto them (Semgrep ERROR -> error, Trivy HIGH/CRITICAL ->
error, ZAP High -> error via zap_to_sarif.py). Gitleaks sets no level, so its
results default to "warning"; gate it at "note" to fail on any secret.

A result's level is its own ``level``, else its rule's
``defaultConfiguration.level``, else "warning" (the SARIF default).
Suppressed results (``suppressions``) don't count.
"""
from __future__ import annotations

import json
import sys

RANK = {"none": 0, "note": 1, "warning": 2, "error": 3}


def results_at_or_above(path: str, minimum: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        sarif = json.load(f)
    hits = []
    for run in sarif.get("runs", []):
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        tool = run.get("tool", {}).get("driver", {}).get("name", path)
        for res in run.get("results", []):
            if res.get("suppressions"):
                continue
            rule = rules.get(res.get("ruleId"), {})
            level = res.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
            if RANK.get(level, 2) >= RANK[minimum]:
                loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
                where = f"{loc.get('artifactLocation', {}).get('uri', '?')}:{loc.get('region', {}).get('startLine', '?')}"
                hits.append(f"[{tool}] {level}: {res.get('ruleId')} at {where}")
    return hits


def main() -> int:
    failed = False
    for arg in sys.argv[1:]:
        path, _, minimum = arg.rpartition(":")
        if minimum not in RANK:
            raise SystemExit(f"bad level in {arg!r}; use note, warning or error")
        hits = results_at_or_above(path, minimum)
        print(f"{path}: {len(hits)} result(s) at or above {minimum}")
        for h in hits:
            print(f"  {h}")
        failed |= bool(hits)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
