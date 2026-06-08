#!/usr/bin/env python3
"""
Red-team autoresearch harness.

Runs a bounded attacker -> target -> judge loop and records EVERY attempt (pass or fail)
to JSONL formatted for guardrail fine-tuning. Models the bounded, gated, outcome-driven
loop from the hacker skill: an upfront round/cycle budget, a per-round gate re-check, and
the confirmed/mitigated/inconclusive/false_positive/unsafe_to_test outcome taxonomy.

Usage:
    python redteam_loop.py --config config.yaml [--rounds R] [--cycles N]
        [--out data/attempts.jsonl] [--concurrency 4] [--max-turns 3]
        [--rate-limit 60] [--seed 1234] [--report data/report.md]

Reads API keys from .env (see .env.example). No data leaves the configured endpoints.
Drop a file named STOP in the output directory to end at the next round boundary.
"""
from __future__ import annotations

import argparse
import random
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml
from tqdm import tqdm

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from hypotheses import HypothesisStore, NoveltyIndex, evolve, generate_attack  # noqa: E402
from judge import judge_attempt  # noqa: E402
from providers import MissingApiKey, ModelClient, RateLimiter  # noqa: E402
from schema import CATEGORIES, Attempt, JsonlWriter, label_for_outcome, new_id  # noqa: E402


def load_config(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def build_targets(cfg: dict, limiter: RateLimiter) -> list[ModelClient]:
    roles = cfg.get("roles", {})
    targets_cfg = cfg.get("targets")
    if targets_cfg:
        return [ModelClient(t, limiter=limiter, label=f"target[{i}]")
                for i, t in enumerate(targets_cfg)]
    return [ModelClient(roles.get("target", {}), limiter=limiter, label="target")]


def run_cycle(round_idx, cycle_idx, store, novelty, attacker, judge, target,
              writer, run_id, max_turns) -> str:
    """Run one PAIR cycle; record every turn. Return the cycle's outcome for stats."""
    category = store.pick_category()
    hyp = store.sample(category)
    history: list[dict] = []
    attack_prompt = generate_attack(attacker, hyp)
    best_outcome = "inconclusive"
    confirmed = False

    for turn in range(1, max_turns + 1):
        if not attack_prompt:
            break
        history = history + [{"role": "user", "content": attack_prompt}]
        try:
            response = target.chat(history)
        except Exception:
            response = ""
        history = history + [{"role": "assistant", "content": response}]

        verdict = judge_attempt(judge, category, history)
        nov = novelty.score(attack_prompt)
        novelty.add(attack_prompt)
        outcome = verdict["outcome"]

        writer.write(Attempt(
            run_id=run_id, round=round_idx, cycle=cycle_idx, turn=turn,
            category=category, technique=hyp.technique, hypothesis=hyp.intent,
            provider=target.provider, target_model=target.model,
            attacker_model=attacker.model, judge_model=judge.model,
            messages=list(history), prompt=attack_prompt, response=response,
            outcome=outcome, label=label_for_outcome(outcome),
            violated_categories=verdict["violated_categories"],
            attack_success=verdict["attack_success"], severity=verdict["severity"],
            judge_rationale=verdict["rationale"], novelty_score=nov,
            hypothesis_id=hyp.id, seed_parent_id=hyp.seed_parent_id,
        ))

        best_outcome = outcome
        if outcome == "confirmed":
            confirmed = True
            break
        if turn < max_turns:
            attack_prompt = generate_attack(attacker, hyp, history, verdict["rationale"])

    store.register(hyp, confirmed)
    return "confirmed" if confirmed else best_outcome


def write_report(path, run_id, rounds, cycles, counts, store, targets, attacker, judge):
    total = sum(counts.values())
    confirmed = counts.get("confirmed", 0)
    asr = (confirmed / total * 100) if total else 0.0
    winners = store.winners()

    lines = [
        "# Red-Team Autoresearch Report",
        "",
        f"- run_id: `{run_id}`",
        f"- budget: {rounds} rounds x {cycles} cycles ({rounds * cycles} cycles planned)",
        f"- attacker: `{attacker.model}`  judge: `{judge.model}`",
        f"- targets: {', '.join('`' + t.model + '`' for t in targets)}",
        "",
        "## Outcomes (per cycle)",
        "",
    ]
    for key in ["confirmed", "mitigated", "false_positive", "inconclusive", "unsafe_to_test"]:
        lines.append(f"- {key}: {counts.get(key, 0)}")
    lines += ["", f"Attack success rate (confirmed / total): {asr:.1f}%", "",
              "## Winning hypothesis families", ""]
    if winners:
        for h in sorted(winners, key=lambda x: x.wins, reverse=True)[:20]:
            lines.append(f"- [{h.category}/{h.technique}] wins={h.wins} attempts={h.attempts}: {h.intent}")
    else:
        lines.append("- none yet")
    lines += [
        "",
        "## Limitations",
        "",
        "- Black-box only; backdoor probing detects behavioral flips, not weight-level triggers.",
        "- Judge labels are model-generated; sample-review before training a guardrail.",
        "",
    ]
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Red-team autoresearch harness")
    ap.add_argument("--config", required=True)
    ap.add_argument("--rounds", type=int)
    ap.add_argument("--cycles", type=int, help="cycles per round")
    ap.add_argument("--out")
    ap.add_argument("--concurrency", type=int)
    ap.add_argument("--max-turns", type=int)
    ap.add_argument("--rate-limit", type=float, help="model requests per minute")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--report")
    args = ap.parse_args(argv)

    cfg = load_config(Path(args.config))
    run_cfg = cfg.get("run", {})
    rounds = args.rounds or int(run_cfg.get("rounds", 5))
    cycles = args.cycles or int(run_cfg.get("cycles_per_round", 50))
    out_path = args.out or run_cfg.get("out", "data/attempts.jsonl")
    concurrency = args.concurrency or int(run_cfg.get("concurrency", 4))
    max_turns = args.max_turns or int(run_cfg.get("max_turns", 3))
    rate_limit = args.rate_limit if args.rate_limit is not None else float(run_cfg.get("rate_limit_per_min", 60))
    seed = args.seed if args.seed is not None else run_cfg.get("seed")
    rng = random.Random(seed)
    categories = cfg.get("categories") or {c: 1.0 for c in CATEGORIES}

    limiter = RateLimiter(rate_limit)
    try:
        attacker = ModelClient(cfg["roles"]["attacker"], limiter=limiter, label="attacker")
        judge = ModelClient(cfg["roles"]["judge"], limiter=limiter, label="judge")
        targets = build_targets(cfg, limiter)
    except MissingApiKey as exc:
        print(f"\nMissing API key: {exc}\n", file=sys.stderr)
        return 2
    except KeyError as exc:
        print(f"Config missing roles.{exc}", file=sys.stderr)
        return 2

    store = HypothesisStore(categories, rng=rng)
    novelty = NoveltyIndex()
    writer = JsonlWriter(out_path)
    run_id = new_id()
    stop_file = Path(out_path).parent / "STOP"

    print(f"run_id={run_id} rounds={rounds} cycles/round={cycles} "
          f"targets={[t.model for t in targets]} out={out_path}")

    counts: dict[str, int] = {o: 0 for o in
                              ["confirmed", "mitigated", "inconclusive", "false_positive", "unsafe_to_test"]}
    counts_lock = threading.Lock()
    pbar = tqdm(total=rounds * cycles, desc="cycles")
    try:
        for r in range(1, rounds + 1):
            # Per-round gate re-check (hacker-style): honor an operator STOP.
            if stop_file.exists():
                print("\nSTOP file present; ending run at round boundary (gate).")
                break

            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = []
                for c in range(1, cycles + 1):
                    cycle_idx = (r - 1) * cycles + c
                    target = targets[(cycle_idx - 1) % len(targets)]
                    futures.append(executor.submit(
                        run_cycle, r, cycle_idx, store, novelty, attacker, judge,
                        target, writer, run_id, max_turns))
                for fut in as_completed(futures):
                    try:
                        outcome = fut.result()
                    except Exception:
                        outcome = "inconclusive"
                    with counts_lock:
                        counts[outcome] = counts.get(outcome, 0) + 1
                    pbar.update(1)

            added = evolve(attacker, store)
            pbar.set_postfix(confirmed=counts["confirmed"], new_hyp=added)
    finally:
        pbar.close()
        writer.close()

    report_path = args.report or str(Path(out_path).parent / "report.md")
    write_report(report_path, run_id, rounds, cycles, counts, store, targets, attacker, judge)
    print(f"\nDone. Attempts -> {out_path}\nReport  -> {report_path}")
    print(f"Summary: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
