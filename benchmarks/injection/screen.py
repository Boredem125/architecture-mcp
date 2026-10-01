"""Benchmark the optional two-stage screen (xsmall screens, base decides).

    python benchmarks/injection/screen.py

The gateway's screen (src/sandbox/semantic/scan.py: screened) sends only the
sentences whose top xsmall score reaches ``screen_threshold`` on to the base
model. A sentence it drops is never seen by base, so the screen can only lose
catches (and false alarms); this measures how many, and the time saved.

Every sentence is scored once by each model and cached in
benchmarks/.cache/segscores-{model}.json, so each screen threshold is
evaluated from the cache. Timings are the measured per-sentence model times:
two-stage = xsmall on every sentence + base on the kept ones.

0.2 is the shipped default. Any other threshold would be chosen on the dev
sets only; held-out sets are reported, not tuned on.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run as bench  # noqa: E402
from sandbox.semantic import scan as pipeline  # noqa: E402
from sandbox.semantic.checks import INJECTION_CHECKS  # noqa: E402

THRESHOLDS = [0.05, 0.1, 0.2, 0.3, 0.5]


def segment_scores(model: str, texts: list[str]) -> dict[str, dict]:
    """{segment: {"scores": {...}, "ms": float}} for every segment, cached."""
    path = bench.CACHE / f"segscores-{model}.json"
    cache = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    todo = sorted({s for t in texts for s in pipeline.prepare(t)} - cache.keys())
    if todo:
        from jevos import Client, questions_from_dict

        client = Client(model=model)
        questions = questions_from_dict(INJECTION_CHECKS)
        client.system_one("warm up", questions)
        for i, seg in enumerate(todo, 1):
            start = time.perf_counter()
            r = client.system_one(seg, questions)
            cache[seg] = {"scores": {k: a.noul for k, a in r.answers.items()},
                          "ms": (time.perf_counter() - start) * 1000}
            if i % 200 == 0 or i == len(todo):
                path.write_text(json.dumps(cache), encoding="utf-8")
                print(f"  {model}: {i}/{len(todo)} new segments", flush=True)
    return cache


def judge(text: str, xs: dict, base: dict, screen: float | None) -> tuple[bool, float, int, int]:
    """(flagged, ms, segments sent to base, segments) for one text. screen=None: base only."""
    segs = pipeline.prepare(text)
    keep = segs if screen is None else [s for s in segs if max(xs[s]["scores"].values()) >= screen]
    ms = sum(base[s]["ms"] for s in keep) + (0 if screen is None else sum(xs[s]["ms"] for s in segs))
    flagged = any(pipeline.verdict(base[s]["scores"], bench.THRESHOLD) == "high" for s in keep)
    return flagged, ms, len(keep), len(segs)


def main() -> None:
    deepset = bench.load_deepset()
    sources = {"agent_set (dev, hand-written)": bench.load_agent_set(),
               "embedded in a README (dev)": bench.load_embedded(),
               "deepset test (held out)": deepset,
               "deepset test, genuine attacks only": bench.genuine_view(deepset),
               "neuralchemy test (held out)": bench.load_neuralchemy()}
    repo = bench.load_repo_files()
    if repo is not None:
        sources[f"repo files, {len(repo)}-row sample (held out)"] = repo
    texts = [r["text"] for rows in sources.values() for r in rows]
    xs = segment_scores("xsmall", texts)
    base = segment_scores("base", texts)

    report: dict = {"thresholds": THRESHOLDS, "results": {}}
    for name, rows in sources.items():
        labels = [r["label"] for r in rows]
        res = {}
        for screen in [None, *THRESHOLDS]:
            out = [judge(r["text"], xs, base, screen) for r in rows]
            ms = sorted(o[1] for o in out)
            m = bench.metrics([o[0] for o in out], labels)
            m.update({"base_share": round(sum(o[2] for o in out) / max(1, sum(o[3] for o in out)), 3),
                      "ms_p50": round(ms[len(ms) // 2], 1), "ms_p95": round(ms[int(0.95 * (len(ms) - 1))], 1)})
            res["base only" if screen is None else f"screen {screen}"] = m
        report["results"][name] = res
        print(f"\n== {name}  (n={len(rows)})")
        print(f"   {'system':12} {'caught':>9} {'false alarms':>13} {'F1':>5} {'to base':>8} {'p50 ms':>7} {'p95 ms':>7}")
        for k, m in res.items():
            print(f"   {k:12} {m['caught']:>9} {m['false_alarms']:>13} {m['f1']:>5.2f} "
                  f"{m['base_share']:>8.0%} {m['ms_p50']:>7} {m['ms_p95']:>7}")
    (HERE / "screen_results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nwrote {HERE / 'screen_results.json'}")


if __name__ == "__main__":
    main()
