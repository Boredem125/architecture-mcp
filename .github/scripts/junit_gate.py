"""Summarise a pytest --junitxml report and fail on any failure or error.

    python .github/scripts/junit_gate.py report.xml [--label NAME] [--min-tests N]

Prints passed / failed / errors / skipped (xfail counts as skipped in JUnit),
appends the same line to $GITHUB_STEP_SUMMARY when set, and exits 1 if any
test failed or errored, or if fewer than --min-tests ran (default 1, so an
empty collection never passes). Counts are recorded, not pinned: new tests
must not break CI; the frozen gate numbers live in M0_BASELINE.md.

Failing tests are also emitted as ``::error`` workflow annotations (one list of
node ids, then details for the first few), because annotations are readable
through the public API while job logs need a token.
"""
from __future__ import annotations

import argparse
import os
import sys
from defusedxml.ElementTree import parse  # installed by tests.yml next to the test runner

CR, LF = chr(13), chr(10)


def totals(path: str) -> dict[str, int]:
    root = parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    t = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    for s in suites:
        for k in t:
            t[k] += int(s.get(k, 0))
    t["passed"] = t["tests"] - t["failures"] - t["errors"] - t["skipped"]
    return t


def _escape(text: str) -> str:
    return text.replace("%", "%25").replace(CR, "%0D").replace(LF, "%0A")


def failing(path: str) -> list[tuple[str, str]]:
    out = []
    for case in parse(path).getroot().iter("testcase"):
        for tag in ("failure", "error"):
            el = case.find(tag)
            if el is not None:
                node = f"{case.get('classname', '')}::{case.get('name', '')}"
                detail = (el.get("message") or "") + LF + (el.text or "")
                out.append((node, detail.strip()))
    return out


def annotate(label: str, fails: list[tuple[str, str]]) -> None:
    # GitHub keeps at most 10 error annotations per step: 1 list + 9 details.
    nodes = LF.join(node for node, _ in fails)
    print(f"::error title={label}: {len(fails)} failing::{_escape(nodes[:6000])}")
    for node, detail in fails[:9]:
        print(f"::error title={_escape(node)[:200]}::{_escape(detail[-2500:])}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--label", default="pytest")
    ap.add_argument("--min-tests", type=int, default=1)
    args = ap.parse_args()

    t = totals(args.report)
    line = (f"{args.label}: {t['tests']} run, {t['passed']} passed, {t['failures']} failed, "
            f"{t['errors']} errors, {t['skipped']} skipped (incl. xfail)")
    print(line)
    print(f"::notice title={args.label} counts::{line}")  # readable via the public API
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"- {line}\n")

    if t["failures"] or t["errors"]:
        annotate(args.label, failing(args.report))
        print("FAIL: failures or errors in the report", file=sys.stderr)
        return 1
    if t["tests"] < args.min_tests:
        print(f"FAIL: only {t['tests']} tests ran (minimum {args.min_tests})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
