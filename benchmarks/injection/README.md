# Prompt-injection benchmark

This compares the gateway's current rule-based `InjectionDetector` (regex) with a semantic detector built on [jev-os](https://github.com/Boredem125/jev-os): a local, CPU-only zero-shot NLI model that answers three yes/no questions from [`src/sandbox/semantic/checks.py`](../../src/sandbox/semantic/checks.py) and flags a text if any answer is ≥ 0.5.

```bash
pip install -e ".[dev]" "jev-os[server] @ git+https://github.com/Boredem125/jev-os"
python benchmarks/injection/run.py            # writes results.json
```

## Datasets

| Set | Rows | What it is | Caveat |
|---|---|---|---|
| `agent_set.jsonl` | 24 attacks + 24 benign | **Indirect** injection in agent context: instructions planted in READMEs, web pages, tool output, code comments, issues and emails. Benign developer text is full of trigger words ("act as a cache", "You are now ready…"), plus legitimate `AGENTS.md`-style instructions to AI agents | Hand-written by the author; the jev-os statements were chosen with it in view, so it's a **development set** |
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), test split | 60 injections + 56 benign | Public (Apache-2.0), mostly **direct** injection in chat prompts, some German | **Held out**, nothing tuned on it. Labels are broad: role-play ("act as a storyteller") and even "translate to polish" count as injections |

## Results (jev-os `base`, laptop CPU i7-1360P)

"Semantic" is the gateway's own PostToolUse pipeline ([`scan.py`](../../src/sandbox/semantic/scan.py)), imported by the benchmark: each text is split into sentences, each sentence gets the checks, and the worst sentence decides.

| Dataset | System | Caught | False alarms | Precision | F1 |
|---|---|---|---|---|---|
| agent_set (dev) | regex (current gateway) | 7/24 | 8/24 | 0.47 | 0.36 |
| | **semantic** | **19/24** | **5/24** | **0.79** | **0.79** |
| embedded in a README (dev) | regex (current gateway) | 7/24 | 8/24 | 0.47 | 0.36 |
| | **semantic** | **16/24** | **5/24** | **0.76** | **0.71** |
| deepset test (held out) | regex (current gateway) | 4/60 | 0/56 | 1.00 | 0.12 |
| | **semantic** | **31/60** | **1/56** | **0.97** | **0.67** |
| **deepset test, genuine attacks only** | regex (current gateway) | **0/39** | 0/56 | – | 0.00 |
| | **semantic** | **26/39** | **1/56** | **0.96** | **0.79** |

**Latency:** semantic 237 ms median per text, p95 766 ms (in-process, laptop CPU; 5 checks per sentence). Through `jevos serve` add HTTP overhead; a new 4-sentence README took ~1.2 s end to end.

**Why "genuine attacks only".** deepset labels many ordinary requests as injections ("act as a storyteller", "translate to polish", "tell me a joke"). The author reviewed all 60 labelled injections in [`deepset_test_review.json`](deepset_test_review.json): 39 are genuine (override instructions, extract the prompt, jailbreak or coerce the model) and 21 are arguable. Each row carries a reason and a hash of its text, so the review can be checked or changed. **All 4 of the regex's catches were arguable rows**, meaning it caught none of the genuine attacks.

**Why per sentence.** Judged as one document, an instruction planted in a README is drowned out by the benign text around it: embedded-set recall fell from 17/24 to 3/24. Judged per sentence it recovers to 15/24.

## How the decision rule was chosen

Rules were compared on cached per-sentence scores for 7 candidate checks, chosen on the dev sets only, and then checked once on held-out data:

- **Harm-gated rules** ("flag only if the text is also harmful") were tried to cut false alarms on legitimate `AGENTS.md`-style instructions. They cut recall by more than half, because the zero-shot model almost never says "harmful" (1/24 attacks), so they were dropped. Telling a harmless instruction to an agent from a harmful one needs a trained model, not zero-shot NLI.
- **"Asks for an action" alone** fires on every README ("install it with pip"), so it's useless alone.
- **Shipped:** any of override / instructs_ai / exfiltrate, **or** "addresses an AI" **and** "asks for an action" in the same sentence. That gave +3 caught on dev with 0 new false alarms, and no change either way on held-out deepset. deepset is direct chat injection, where every prompt addresses the AI, so that result is expected. The dev-set gain still needs confirming on a public **indirect**-injection benchmark.
- **Unwrapping** machine output (JSON string values, `/* */` and `<!-- -->` markers, `npm WARN` / `HTTP 200` chatter) made no measurable difference here and is kept for robustness. Line-comment markers (`#`, `//`) are deliberately kept: stripping them turned `# Forget the cached token…` into a false alarm.

## What the numbers say

- **On held-out public data, the semantic detector catches about 7× more injections than the regex** (27 vs 4) at nearly the same precision (1 false alarm in 56).
- **The regex is precise on chat prompts but noisy on developer text.** In agent context it fires on "act as a cache", "You are now ready…" and `system: linux`. In the gateway, every false alarm is an approval prompt, which feeds approval fatigue (threat model, Goal 6).
- **The semantic detector's misses** are mostly instructions wrapped in machine output ("SYSTEM NOTICE FOR ASSISTANT…", JSON tool responses, `npm WARN` lines).
- **Its false alarms** are mostly legitimate instructions to AI agents (`AGENTS.md` style) and text *about* AI. Separating *instructions to an AI* from *malicious* instructions is the open problem.
- **Neither is enough alone, which is why detection only ever raises scrutiny.** Authorization still decides what can run.

These are baseline numbers. The planned distilled single-pass model and the red-team loop have to beat them.
