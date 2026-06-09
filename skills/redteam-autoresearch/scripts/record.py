#!/usr/bin/env python3
"""
Record agent-judged attempts into the dataset.

The agent (attacker + judge) produces a judged JSONL: each line is a transcript from
query_target.py plus the agent's judgment fields. This script normalizes the judgment,
maps it to a safe/unsafe label, computes a novelty score, and appends a schema-consistent
Attempt to attempts.jsonl. Every attempt -- pass or fail -- is recorded.

Judged input line (transcript + judgment), produced by the agent:
  {... transcript fields ..., "outcome": "confirmed|mitigated|inconclusive|false_positive|unsafe_to_test",
   "violated_categories": ["S1", ...], "severity": "none|low|medium|high|critical",
   "judge_rationale": "..."}

Usage:
    python record.py --run-dir .red-team/runs/<run_id> \
        [--in <run_dir>/judged.jsonl] [--out <run_dir>/attempts.jsonl] [--run-id <id>]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from schema import (  # noqa: E402
    JsonlWriter, build_attempt, new_id, normalize_judgment,
)
from novelty import NoveltyScorer  # noqa: E402
from run_context import resolve_run_context  # noqa: E402


def seed_novelty(path: Path, novelty: NoveltyScorer) -> int:
    """Load prompts from an existing dataset so novelty is scored across the whole set."""
    if not path.exists():
        return 0
    seeded = 0
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if row.get("prompt"):
                novelty.add(row["prompt"])
                seeded += 1
    return seeded


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Record agent-judged attempts into the dataset")
    ap.add_argument("--run-dir", help="isolated run artifact directory")
    ap.add_argument("--in", dest="inp")
    ap.add_argument("--out")
    ap.add_argument("--run-id")
    ap.add_argument("--novelty-backend", default="auto",
                    choices=["auto", "st", "embed", "jaccard"],
                    help="semantic novelty backend (auto falls back to token-Jaccard)")
    args = ap.parse_args(argv)

    ctx = resolve_run_context(run_dir=args.run_dir, create=True)
    input_path = Path(args.inp) if args.inp else ctx.path("judged.jsonl")
    out_path = Path(args.out) if args.out else ctx.path("attempts.jsonl")
    novelty = NoveltyScorer(backend=args.novelty_backend)
    seeded = seed_novelty(out_path, novelty)
    run_id = args.run_id or ctx.run_id or new_id()

    writer = JsonlWriter(out_path)
    counts: dict[str, int] = {}
    written = 0
    try:
        with input_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                judgment = normalize_judgment(row)
                prompt = row.get("prompt", "")
                nov = novelty.score(prompt)
                novelty.add(prompt)
                writer.write(build_attempt(row, judgment, run_id=run_id, novelty_score=nov))
                counts[judgment["outcome"]] = counts.get(judgment["outcome"], 0) + 1
                written += 1
    finally:
        writer.close()

    print(f"recorded {written} attempts -> {out_path} (seeded novelty from {seeded} prior rows)")
    print(f"outcomes: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
