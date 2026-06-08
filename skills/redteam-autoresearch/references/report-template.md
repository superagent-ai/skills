# Report Template

The harness writes a basic `data/report.md` automatically at the end of a run. Use this
structure for a richer, agent-authored report (the `report-writer` role produces it).
Summarize sensitive content; never paste full harmful outputs.

```markdown
# Red-Team Autoresearch Report

## Run summary
- run_id, date, budget (rounds x cycles), max_turns
- attacker / judge / target model(s) and provider
- total attempts recorded, attack success rate (confirmed / total)

## Outcomes by category
- per category: confirmed / mitigated / false_positive / inconclusive / unsafe_to_test
- label balance (safe vs unsafe) of the exportable rows

## Top winning techniques
- ranked hypothesis families by wins, with attempts and win rate
- one redacted example confirmation per top family (summarized, not full payload)

## Hazard coverage
- counts per Llama Guard code (S1-S14); call out under-sampled codes

## Novelty
- novelty score distribution; share of near-duplicate attacks
- families pruned as dead; new families introduced by evolution

## Dataset
- rows exported to llama_guard.jsonl and chat_classification.jsonl
- excluded rows (inconclusive / unsafe_to_test) and why

## Limitations
- black-box only; backdoor outcomes are suspected triggers, not weight-level proof
- judge labels are model-generated; note the review sample size and error estimate

## Sources
- research used to seed and evolve attacks this run (title + URL), grouped by technique

## Recommended next runs
- category re-weighting, new target models, larger budget, or judge recalibration
```
