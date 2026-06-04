# Autoresearch Loop

Offensive Security is an **autoresearch** loop: it keeps generating and testing exploit hypotheses until nothing high-value remains or the user stops it.

## Loop semantics

```text
ingest findings
  → hypothesize (templates + compound)
  → validate (sandbox)
  → evolve (score outcomes)
  → if confirmed: generate chaining / follow-up hypotheses
  → validate again
  → repeat until no new hypotheses OR max rounds
  → report
```

## Outcomes drive the next round

| Outcome | Next action |
|---------|-------------|
| `confirmed` | Save PoC; spawn autoresearch chain/combine hypotheses for same file or related findings |
| `inconclusive` | One reformulation round (alternate method or combined path) when autoresearch enabled |
| `false_positive` | Stop retrying that finding; log for defensive tuning |
| `mitigated` | Record compensating control; optional downgrade in report |
| `unsafe_to_test` | Skip; require scope.yaml or sandbox fixtures |

## Running the loop

```bash
python3 skills/offensive-security/scripts/autoresearch.py deduped-findings.json \
  --scope scope.yaml \
  --max-rounds 5 \
  --output-dir ./offensive-run
```

Flags:

- `--max-rounds` — cap iterations (default 5)
- `--dry-run` — no live probes; documents `unsafe_to_test` outcomes
- `--stop-on-no-confirmed` — exit early if a round confirms nothing new

## Agent-driven autoresearch

Without the script, the agent runs the same loop manually:

1. Complete hacker Phases 1–5 first (offensive-security is **last**).
2. Run ingest → hypothesize → validate → evolve.
3. For each `confirmed`, call `hypothesis_generator` follow-ups or re-run `autoresearch.py` with accumulated outcomes.
4. Stop when no new hypotheses or user interrupts.

## Safety

Autoresearch does not relax guardrails. Each round re-checks forbidden actions, rate limits, and scope. Production targets are never added mid-loop.
