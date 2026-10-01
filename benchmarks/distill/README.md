# Phase 2: a distilled injection student

A small local classifier (TF-IDF word + character n-grams → logistic
regression) trained on labelled examples, with open-weight LLMs on Groq
reviewing the hard cases. It reads text once, loads in ~0.1 s, scores a
sentence in under 1 ms, and needs no ML library at runtime
(`src/sandbox/semantic/student.py`, a pure-Python re-implementation that
gives identical counts to scikit-learn). The model ships as
`src/sandbox/semantic/student-injection.json.gz` (0.6 MB).

**Status: shipped opt-in (`semantic.student: true` in `.sandbox/policy.json`),
off by default.** It beat the zero-shot layer on all three held-out sets, but
missed the pre-registered false-alarm limit on the hand-written dev sets by
one (see Decision).

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
   - 4,000 lines of package READMEs from the local virtualenv, as benign
     developer text → `openai/gpt-oss-20b` (2 labelled injection)
3. `train.py` trains on the pool with the labeller's answers on disputed rows
   plus 70% of the docs lines. The other 30% (1,233 benign sentences) set the
   threshold: the lowest score at which at most 1% of them flag (0.6085).

Held out and never trained on: deepset test, neuralchemy test, the repo-file
sample (seed 20260930), and the hand-written dev sets.

### Why the threshold is calibrated on benign sentences

The first version picked the lowest threshold with 90% precision on a slice
of the training pool. That slice comes from the same datasets, so almost any
threshold passes; the rule bottomed out at 0.30, and scored sentence by
sentence (as the gateway scans) the student flagged plain README text: 24/24
false alarms on the embedded dev set. Calibrated on held-back benign
sentences, that fell to 2/24.

## Label modes

| mode | disputed rows | docs lines |
|---|---|---|
| dataset | dataset label | not added |
| groq | labeller's answer | added |
| agree | dropped where labeller and dataset disagree | added |

On the disputed repo-file rows the labeller called 258 of 341 "injection"
rows benign. Some are fair (`Install dependencies with pip or npm`), others
are fragments that only make sense inside an attack (`IMPORTANT ANNOUNCEMENT
FROM THE TECH TEAM.`). The labeller is not ground truth either. **groq** was
chosen on the dev set (fewest false alarms).

## Model selection without held-out data

Regularisation (C = 0.25, 1, 4) and features (word, char, both) were compared
on two measures that never touch a held-out set: F1 on the hand-written dev
sets, and **cross-source F1**: train without one dataset, score that
dataset's own (unseen, non-held-out) pool rows. The shipped settings (C = 4,
word + char) were best on cross-source F1: 0.54 with repo rows unseen, 0.70
with neuralchemy rows unseen.

## Decision rule (written before the held-out run)

The student joins the gateway's per-sentence scan as an OR with the jev-os
checks, so it can only add scrutiny. Adopt (on by default) only if, on the
held-out sets, *semantic OR student* raises F1 on at least two of three and
lowers it on none, **and** false alarms on the 48 benign dev texts rise by at
most 3.

## Results

Per sentence, as the gateway scans; from `benchmarks/injection/run.py`
(`results.json` there). Caught / false alarms, F1.

| held-out set | semantic (jev-os) | student | semantic OR student |
|---|---|---|---|
| repo files, 600 sample | 86/309, 8/291, 0.43 | 263/309, 8/291, 0.91 | 265/309, 15/291, 0.90 |
| deepset, genuine attacks | 26/39, 1/56, 0.79 | 30/39, 0/56, 0.87 | 33/39, 1/56, 0.90 |
| neuralchemy test | 324/552, 86/390, 0.67 | 524/552, 24/390, 0.95 | 531/552, 100/390, 0.90 |

| dev set | semantic | student | semantic OR student |
|---|---|---|---|
| agent_set (hand-written) | 19/24, 5/24 | 17/24, 5/24 | 22/24, 8/24 |
| embedded in a README | 16/24, 5/24 | 9/24, 2/24 | 19/24, 6/24 |

### Decision

- Held out: F1 up on all three sets. **Met.**
- Dev false alarms: 10/48 → 14/48, +4 against a limit of 3. **Missed.**

So the student is **not on by default**. The extra false alarms are benign
texts written to look like injections ("This tutorial shows how to build an
AI assistant…", "Previous instructions in v1 of this guide are out of
date…"), which the student scores above 0.9; a stricter threshold (0.5%
target) cut catches without removing them.

Turning it on is reasonable where missed injections cost more than approval
prompts, or where the jev-os service isn't running: the student also scans
when the service is down, where the gateway otherwise has no semantic layer.

## Limitations

- **Gains are largely in-distribution.** Each held-out set's dataset also
  supplied training rows (from its train split, or rows outside the sample).
  Cross-source F1 (0.54–0.70) is the better guide to novel sources.
- **Lexical model.** It keys on words and character patterns, so benign text
  that reads like an injection fools it, and paraphrases outside its training
  vocabulary can slip past.
- **Unreviewed labels.** Docs lines were labelled by the smaller model,
  disputed rows by the larger one; neither was human-reviewed.

## Reproduce

    python benchmarks/distill/data.py
    python benchmarks/distill/label.py --select
    python benchmarks/distill/label.py --run --kind disputed
    python benchmarks/distill/label.py --run --kind docs --model openai/gpt-oss-20b
    python benchmarks/distill/train.py --labels groq --export src/sandbox/semantic/student-injection.json.gz
    python benchmarks/injection/run.py --reuse      # student vs cached jev-os predictions
