# Phase 2: a distilled injection student

A small local classifier (TF-IDF word + character n-grams → logistic
regression) trained on labelled examples, with an open-weight LLM on Groq
reviewing the hard cases. It reads text once, loads in ~0.1 s, scores a
300-character text in under 1 ms, and needs no ML library at runtime
(`src/sandbox/semantic/student.py`, a pure-Python re-implementation that
gives identical counts to scikit-learn).

**Status: benchmark result, not wired into the gateway.** See limitations.

## Pipeline

1. `data.py` builds the training pool: prodnull repo-file rows outside the
   600-row benchmark sample, neuralchemy `core` train, deepset train (all
   Apache-2.0). Rows equal to, or near copies of (char TF-IDF cosine ≥ 0.8),
   any held-out text are dropped: 575 near copies removed, 9,430 rows kept.
   Text is redacted (`src/sandbox/semantic/redact.py`) before storage.
2. `label.py` sends only redacted text to Groq, with a strict JSON schema
   (boolean + category per item):
   - 1,124 "disputed" pool rows (5-fold out-of-fold student disagrees with
     the dataset label, or p in 0.3–0.7) → `openai/gpt-oss-120b`
   - 1,500 lines of package READMEs from the local virtualenv, as benign
     developer text → `openai/gpt-oss-20b` (labelled 0/1,500 injection)
3. `train.py` trains, picks the threshold on a 15% validation slice of the
   pool (lowest threshold reaching precision ≥ 0.9), and scores the held-out
   sets.

Held out and never trained on: deepset test, neuralchemy test, the repo-file
sample (seed 20260930), and the hand-written dev sets.

## Label modes

| mode | disputed rows | docs lines |
|---|---|---|
| dataset | dataset label | not added |
| groq | labeller's answer | added |
| agree | dropped where labeller and dataset disagree | added |

On the disputed repo-file rows the labeller called 258 of 341 "injection"
rows benign. Some are fair (`Install dependencies with pip or npm`), others
are fragments that only make sense inside an attack (`IMPORTANT ANNOUNCEMENT
FROM THE TECH TEAM.`). The labeller is not ground truth either.

**Chosen: groq**, on the dev set only (fewest false alarms on agent_set:
10/24 vs 12 and 14). Held-out numbers for all three modes were also looked
at, so the choice is reported with all three below.

## Results (whole text; caught / false alarms)

| held-out set | current gateway (jev-os base) | dataset | **groq** | agree |
|---|---|---|---|---|
| repo files, 600 sample | 86/309, 8/291 | 301, 56 | **287, 39** | 292, 36 |
| deepset, genuine attacks | 26/39, 1/56 | 34, 7 | **33, 5** | 34, 5 |
| neuralchemy test | 324/552, 86/390 | 541, 33 | **542, 41** | 542, 40 |

| dev set | current | groq |
|---|---|---|
| agent_set (hand-written) | 19/24, 5/24 | 23/24, 10/24 |
| embedded in a README, whole text | 3/24, 1/24 | 0/24, 0/24 |
| embedded in a README, per sentence | 16/24, 5/24 | 24/24, 24/24 |

Full numbers: `results.json` (groq mode).

## Limitations

- **Recall rises a lot, precision falls.** On repo files and deepset the
  student raises 5–7× the false alarms of the zero-shot layer. In the gateway
  every false alarm is an approval prompt.
- **Mostly in-distribution learning.** Trained without repo-file rows it
  flags 286/291 benign repo rows. Gains on each set come largely from
  training on the same source's other rows.
- **Not usable per sentence.** Scored sentence by sentence it flags the
  plain README boilerplate itself (24/24 false alarms), and scored whole it
  misses an injection planted in a README (0/24). The gateway scans per
  sentence, so the student can't replace or join that path yet.
- **Benign developer instructions** (AGENTS.md style) still trigger 10/24;
  1,500 labelled README lines did not fix it.
- Labels for docs lines come from the smaller model; disputed labels from
  the larger one; neither was human-reviewed.

## Reproduce

    python benchmarks/distill/data.py
    python benchmarks/distill/label.py --select
    python benchmarks/distill/label.py --run --kind disputed
    python benchmarks/distill/label.py --run --kind docs --model openai/gpt-oss-20b --limit 1500
    python benchmarks/distill/train.py --labels groq
