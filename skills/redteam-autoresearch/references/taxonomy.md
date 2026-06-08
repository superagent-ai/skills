# Taxonomy and Schema

## Red-team categories

The loop tests four category families (set sampling weights in `config.yaml`):

- `harmful_content` - disallowed operational content.
- `jailbreak` - safety-bypass techniques.
- `prompt_injection` - attacker-controlled instruction following / leakage.
- `backdoor` - black-box trigger probing (see [attack-library.md](attack-library.md)).

## Hazard codes (Llama Guard 3 / MLCommons)

The judge labels `violated_categories` using these codes; the exporter writes them into
the Llama Guard category block. Defined in `scripts/schema.py` (`HAZARD_CODES`).

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

A red-team category is the attack family; the hazard codes describe the harm in the
response. One jailbreak can map to any hazard code depending on what it elicited.

## Outcome taxonomy and label mapping

Outcomes (snake_case, from the `hacker` loop) and how they map to a guardrail label:

- `confirmed` -> `unsafe` (with hazard codes)
- `mitigated` -> `safe`
- `false_positive` -> `safe`
- `inconclusive` -> no label (excluded from default export)
- `unsafe_to_test` -> no label (excluded from default export)

## JSONL schema (attempts.jsonl)

Every judged turn is one row (`scripts/schema.py`, `Attempt`):

- `id`, `run_id`, `schema_version`, `timestamp`
- `round`, `cycle`, `turn`
- `category`, `technique`, `hypothesis`, `hypothesis_id`, `seed_parent_id`
- `provider`, `target_model`, `attacker_model`, `judge_model`
- `messages` (full conversation up to this turn), `prompt`, `response`
- `outcome`, `label`, `violated_categories`, `attack_success`, `severity`
- `judge_rationale`, `novelty_score`

## Export formats (`scripts/export_guardrail.py`)

- `llama_guard.jsonl`: `{"prompt": <instruction + category block + conversation>,
  "completion": "safe" | "unsafe\nS1,S2"}`. `--role Agent` (default) assesses the response
  (output guardrail); `--role User` assesses the prompt (input guardrail); `--role both`
  emits both.
- `chat_classification.jsonl`: `{"messages": [user, assistant], "label", "categories",
  "category", "technique"}` for generic classifier fine-tuning.
