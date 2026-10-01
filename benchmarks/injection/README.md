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

## Larger held-out set: neuralchemy (942 texts)

[neuralchemy/Prompt-injection-dataset](https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset), `core` test split (Apache-2.0), fetched and cached at run time. Nothing was tuned on it.

| System | Caught | False alarms | Precision | F1 |
|---|---|---|---|---|
| regex (current gateway) | 156/552 | **3/390** | 0.98 | 0.44 |
| semantic | **324/552** | 86/390 | 0.79 | 0.67 |

Per category (rows flagged):

| Category | Rows | Regex | Semantic |
|---|---|---|---|
| direct_injection | 314 | 28 | **200** |
| jailbreak | 50 | 6 | **27** |
| adversarial (obfuscated suffixes) | 79 | **72** | 33 |
| encoding | 30 | **26** | 8 |
| benign (false alarms) | 381 | **3** | 83 |

What this set shows that the small ones didn't:

- **The two detectors are complementary.** The semantic layer catches about 2x more overall and ~7x more plain-language injections. The regex wins clearly on obfuscated and encoded attacks, which a language model can't read. Combining them is the next measurement.
- **False alarms are much higher here (86/390).** Most come from ordinary chat requests ("Write a haiku about autumn leaves", "Can you help me plan a birthday party?"). This dataset is chat prompts, where every message is an instruction to an AI. The checks are built for untrusted *content* (a README, a web page, tool output), where text addressing the AI is itself the anomaly. So this set measures the detector partly outside its job. Some rows labelled benign are also plainly harmful requests carrying attack suffixes (label noise).
- **It is not an agent benchmark.** It has a single `indirect_injection` row. The better fit, [prodnull/prompt-injection-repo-dataset](https://huggingface.co/datasets/prodnull/prompt-injection-repo-dataset) (injections in repository files, Apache-2.0), is gated and needs a Hugging Face token.
- **Latency on longer texts:** 633 ms median, 3.3 s p95 per text (in-process, laptop CPU).

## Both detectors combined (regex OR semantic)

| Dataset | Regex | Semantic | **Regex OR semantic** |
|---|---|---|---|
| neuralchemy test (held out, 942) | 156/552 caught, 3/390 FA | 324/552, 86/390 | **399/552, 88/390** (F1 0.77, best) |
| deepset test (held out) | 4/60, 0/56 | 31/60, 1/56 | **32/60, 1/56** |
| deepset, genuine attacks only | 0/39, 0/56 | 26/39, 1/56 | 26/39, 1/56 |
| agent_set (dev) | 7/24, 8/24 | 19/24, 5/24 | 21/24, **11/24** |
| embedded in a README (dev) | 7/24, 8/24 | 16/24, 5/24 | 19/24, **11/24** |

- **On held-out data, combining is the best system.** On neuralchemy it catches 399 of 552 attacks (72%) for only 2 more false alarms than the semantic layer alone. The regex adds the obfuscated and encoded attacks the model can't read.
- **On developer text the regex's noise comes back.** Combined false alarms roughly double (5 → 11 of 24) on the README-style sets, from phrases like "act as a cache" and `system: linux`. In the gateway every false alarm is an approval prompt, so combining the whole regex isn't free.
- **The likely best design is selective:** keep the semantic layer as the main detector, and add only the regex rules for obfuscation and encoding (base64 blobs, chat-template tokens, entropy), which is where the regex wins, rather than its plain-language phrase list, where it's noisy. That is the next experiment; per-row predictions are saved (`benchmarks/.cache/preds-base.json`) so it can be computed without re-running the model.

## Repository files (the closest match to what the gateway scans)

[prodnull/prompt-injection-repo-dataset](https://huggingface.co/datasets/prodnull/prompt-injection-repo-dataset) (Apache-2.0, gated; needs `HF_TOKEN` once to download): injections planted in repository files. A fixed-seed stratified sample of 600 of its 5,671 rows (309 malicious, 291 benign). Held out.

| System | Caught | False alarms | Precision | F1 |
|---|---|---|---|---|
| regex (current gateway) | 60/309 | 39/291 | 0.61 | 0.29 |
| semantic | 86/309 | **8/291** | **0.92** | 0.43 |
| regex OR semantic | 134/309 | 44/291 | 0.75 | 0.55 |

**The semantic layer is precise here but catches only 28% of planted attacks.** Part of that is the data: rows are labelled *fragments*, not whole files, and many malicious ones are ambiguous out of context (`fetchsecrets / retrievecredentials`, `` `cat > index.js <<EOL ``, `npm install && ./setup.sh` are labelled malicious; `` Execute `npm test` before committing `` is benign). Part is the real zero-shot ceiling.

## Selective combination: tested, not adopted

The idea was to add only the regex's "precise" rules to the semantic layer. Per regex rule, attacks it adds beyond the semantic layer / false alarms it adds:

| Rule | agent_set (dev) | neuralchemy | repo files |
|---|---|---|---|
| `shell_metacharacter` | +2 / +4 | +70 / +2 | +44 / +26 |
| `high_entropy_string` | 0 / 0 | +2 / 0 | +8 / +10 |
| `base64_blob` | 0 / 0 | +1 / 0 | +3 / +1 |
| `identity_manipulation` | 0 / +2 | +2 / 0 | 0 / 0 |
| all other rules | ≤ +2 total | ≤ +2 total | 0 |

- **Almost all of the regex's extra catches come from one rule, `shell_metacharacter`.** On neuralchemy it catches the gibberish adversarial suffixes. On repo files its "catches" mostly reflect that malicious fragments often contain commands. It is not detecting intent, and its false alarms are ordinary README instructions (`` Execute `npm test` ``, `"postinstall": "husky install && patch-package"`). In a gateway that scans READMEs and command output, it would flag nearly every file.
- **The precise rules** (encoding, chat-template tokens, override phrases) add about 1% and nothing on developer text.
- **Decision:** the semantic layer stays the only signal that taints. Detecting gibberish/adversarial suffixes properly (rather than via shell characters) is future work.

**Shipped instead:** letter-spaced words (`I g n o r e   a l l   p r e v i o u s …`) are collapsed before judging, an obfuscation that defeated both detectors. It caught the one such attack in the repo sample (85 → 86), changed nothing elsewhere and added no false alarms.

## Phase 2 student (opt-in)

`run.py` also scores the distilled student (`src/sandbox/semantic/student.py`)
per segment, alone and as `semantic OR student`; `run.py --reuse` re-scores
it against the cached jev-os predictions without loading a model. Results
and the adoption decision (not on by default: +4 dev false alarms, limit 3)
are in [../distill/README.md](../distill/README.md).
