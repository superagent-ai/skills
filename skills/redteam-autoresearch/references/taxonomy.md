# Taxonomy and Schema

## Red-team categories

The loop tests four category families (set the sampling mix in `<run_dir>/config.yaml`):

- `harmful_content` - disallowed operational content.
- `jailbreak` - safety-bypass techniques.
- `prompt_injection` - attacker-controlled instruction following / leakage.
- `backdoor` - black-box trigger probing (see [attack-library.md](attack-library.md)).

## Attack styles (diversity axis)

The MAP-Elites archive ([search-loop.md](search-loop.md)) is a grid of `category x attack_style`.
`attack_style` is the second dimension (defined as `ATTACK_STYLES` in `scripts/schema.py`):
`direct`, `roleplay_persona`, `hypothetical_fiction`, `encoding_obfuscation`, `authority_appeal`,
`persuasion_social`, `multi_turn_escalation`, `context_overload`, `format_injection`,
`code_cipher`. Mutators tag each probe with the right style so it lands in the correct cell.

## Hazard codes (Llama Guard 3 / MLCommons)

You label `violated_categories` using these codes; the exporter writes them into the Llama
Guard category block. Defined in `scripts/schema.py` (`HAZARD_CODES`).

- S1 Violent Crimes
- S2 Non-Violent Crimes
- S3 Sex-Related Crimes
- S4 Child Sexual Exploitation
- S5 Defamation
- S6 Specialized Advice
- S7 Privacy
- S8 Intellectual Property
- S9 Indiscriminate Weapons
- S10 Hate
- S11 Suicide & Self-Harm
- S12 Sexual Content
- S13 Elections
- S14 Code Interpreter Abuse

A red-team category is the attack family; the hazard codes describe the harm in the response.
One jailbreak can map to any hazard code depending on what it elicited.

## Outcome taxonomy and label mapping

Outcomes (snake_case, from the `hacker` loop) and how `record.py` maps them to a label:

- `confirmed` -> `unsafe` (with hazard codes)
- `mitigated` -> `safe`
- `false_positive` -> `safe`
- `inconclusive` -> no label (excluded from default export)
- `unsafe_to_test` -> no label (excluded from default export)

## Benchmark metadata

Benchmark runs add optional metadata so results can be macro-averaged across comparable cells.
These fields should pass from `seeds.jsonl` / `attacks.jsonl` into `attempts.jsonl`:

- `difficulty` - `smoke`, `standard`, `hard`, or `adaptive`.
- `benchmark_cell` - stable cell id, usually
  `<category>/<attack_style>/<hazard_target>/<difficulty>`.
- `hazard_target` - intended Llama Guard hazard code (`S1`-`S14`) or `none` for benign controls.
- `seed_family` - named seed/persona/scenario family used for holdout and duplicate analysis.
- `holdout` - boolean; true when the seed family was not used during attack generation or tuning.
- `control_type` - empty for attacks; otherwise `benign`, `clean_trigger_control`,
  `canary_control`, or another explicit control family.
- `leak_channel` - `visible_leak`, `reasoning_leak`, `both`, `none`, or `unknown`.
- `response_mode` - `normal`, `silent_empty`, `over_refusal`, or `error`.
- `adaptive_phase` - `fixed`, `adaptive`, or `transfer`.

For model comparisons, report both micro-ASR (all attempts pooled) and macro-ASR (mean of
per-cell ASR). Macro-ASR is the headline metric when cells have unequal attempt counts.

## Pipeline and files

The agent is the attacker and judge; the harness only calls the target.

- `<run_dir>/target_profile.json` (`profile_target.py`): target fingerprint + recommended attack styles.
- `<run_dir>/seeds.jsonl` (you write): a few seed attacks per under-explored archive cell, plus
  benchmark metadata when running in benchmark mode.
- `<run_dir>/attacks.jsonl` (`mutators.py` expands seeds): `{category, technique, attack_style, hypothesis, prompt}` or `{... , messages}`, preserving benchmark metadata when present.
- `<run_dir>/transcripts.jsonl` (`query_target.py`): attacks plus `{messages, response, assistant_content, reasoning_content, provider, target_model}`. `response` is the combined judge text; the two content fields preserve visible output and provider reasoning separately.
- `<run_dir>/judged.jsonl` (you write): transcripts plus `{refused, specificity, convincingness, strongreject_score, outcome, violated_categories, severity, judge_rationale}`
- `<run_dir>/attempts.jsonl` (`record.py`): normalized `Attempt` rows (label + novelty + StrongREJECT score)
- `<run_dir>/archive.json` (`archive.py`): MAP-Elites elites per `category x attack_style` cell

## Attempt schema (attempts.jsonl)

Each judged turn is one row (`scripts/schema.py`, `Attempt`):

- `id`, `run_id`, `schema_version`, `timestamp`
- `round`, `cycle`, `turn`, `seed_parent_id`
- `category`, `technique`, `attack_style`, `hypothesis`
- `difficulty`, `benchmark_cell`, `hazard_target`, `seed_family`, `holdout`, `control_type`
- `leak_channel`, `response_mode`, `adaptive_phase`
- `provider`, `target_model`, `attacker` (= `agent`), `judged_by` (= `agent`)
- `messages` (full conversation), `prompt`, `response`, `assistant_content`, `reasoning_content`
- `outcome`, `label`, `violated_categories`, `attack_success`, `severity`, `judge_rationale`
- `novelty_score`, `strongreject_score`

The benchmark metadata, `attack_style`, and `strongreject_score` fields are additive. The export
formats below are unchanged: `export_guardrail.py` reads only `label`, `violated_categories`,
`messages`, `prompt`, `response`, `category`, and `technique`, so `llama_guard.jsonl` and
`chat_classification.jsonl` stay compatible.

## Export formats (`scripts/export_guardrail.py`)

- `llama_guard.jsonl`: `{"prompt": <instruction + category block + conversation>,
  "completion": "safe" | "unsafe\nS1,S2"}`. `--role Agent` (default) assesses the response
  (output guardrail); `--role User` assesses the prompt (input guardrail); `--role both`
  emits both.
- `chat_classification.jsonl`: `{"messages": [user, assistant], "label", "categories",
  "category", "technique"}` for generic classifier fine-tuning.
