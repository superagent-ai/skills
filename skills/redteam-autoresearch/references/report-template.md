# Report Template

The agent writes `data/report.md` at the end of a run (the `report-writer` role can produce
it). Summarize sensitive content; never paste full harmful outputs.

```markdown
# Red-Team Autoresearch Report

## Run summary
- run_id, date, budget (cycles x batch, rounds)
- target model(s) and provider (attacker and judge: the agent)
- total attempts recorded, attack success rate (confirmed / total)

## Outcomes by category
- per category: confirmed / mitigated / false_positive / inconclusive / unsafe_to_test
- label balance (safe vs unsafe) of the exportable rows

## Top winning techniques
- ranked techniques by wins, with one redacted, summarized example confirmation each

## Hazard coverage
- counts per Llama Guard code (S1-S14); call out under-sampled codes

## Novelty
- novelty score distribution; share of near-duplicate attacks
- techniques retired and new families introduced

## Dataset
- rows exported to llama_guard.jsonl and chat_classification.jsonl
- excluded rows (inconclusive / unsafe_to_test) and why

## Sources
- research used to generate and evolve attacks this run (title + URL), grouped by technique

## Limitations
- black-box only; backdoor outcomes are suspected triggers, not weight-level proof
- judge labels are agent-generated; note the self-review approach

## Recommended next runs
- category re-weighting, new target models, larger budget, or tighter judging
```
