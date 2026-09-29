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

## Results (jev-os `base`, laptop CPU i7-1360P, 30 Sep 2026)

| Dataset | System | Caught | False alarms | Precision | F1 |
|---|---|---|---|---|---|
| agent_set (dev) | regex (current gateway) | 7/24 | 8/24 | 0.47 | 0.36 |
| | **jev-os base** | **17/24** | **5/24** | **0.77** | **0.74** |
| | regex OR jev-os | 20/24 | 11/24 | 0.65 | 0.73 |
| deepset test (held out) | regex (current gateway) | 4/60 | 0/56 | 1.00 | 0.12 |
| | **jev-os base** | **27/60** | **1/56** | **0.96** | **0.61** |
| | regex OR jev-os | 31/60 | 1/56 | 0.97 | 0.67 |

The jev-os latency is 0.5–0.6 s median per text for the 3 checks, with p95 0.9–1.4 s. That's too slow to run on every tool call, so the gateway uses it selectively (on untrusted content and on actions already headed for escalation).

## What the numbers say

- **On held-out public data, the semantic detector catches about 7× more injections than the regex** (27 vs 4) at nearly the same precision (1 false alarm in 56).
- **The regex is precise on chat prompts but noisy on developer text.** In agent context it fires on "act as a cache", "You are now ready…" and `system: linux`. In the gateway, every false alarm is an approval prompt, which feeds approval fatigue (threat model, Goal 6).
- **The semantic detector's misses** are mostly instructions wrapped in machine output ("SYSTEM NOTICE FOR ASSISTANT…", JSON tool responses, `npm WARN` lines).
- **Its false alarms** are mostly legitimate instructions to AI agents (`AGENTS.md` style) and text *about* AI. Separating *instructions to an AI* from *malicious* instructions is the open problem.
- **Neither is enough alone, which is why detection only ever raises scrutiny.** Authorization still decides what can run.

These are baseline numbers. The planned distilled single-pass model and the red-team loop have to beat them.
