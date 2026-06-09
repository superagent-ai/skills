#!/usr/bin/env python3
"""
Query the target model with agent-authored attacks.

This is the ONLY model the harness calls. The agent running the skill is the attacker and
the judge: it writes attack prompts to an input JSONL, this script sends them to the target
and records the responses, and the agent then judges the transcripts (see record.py).

Input JSONL (one attack per line), produced by the agent:
  {"id"?, "category", "technique"?, "hypothesis"?, "round"?, "cycle"?, "turn"?, "prompt": "..."}
  or, for multi-turn / refinement:
  {... , "messages": [{"role": "user", "content": "..."}, {"role": "assistant", ...}, ...]}

Output JSONL (one transcript per line): the input fields plus
  {"messages": <full conversation incl. assistant>, "response": <content+reasoning for judging>,
   "assistant_content": <visible content>, "reasoning_content": <provider reasoning>, "provider",
   "target_model"}

Usage:
    python query_target.py --run-dir .red-team/runs/<run_id> \
        [--config <run_dir>/config.yaml] [--in <run_dir>/attacks.jsonl] \
        [--out <run_dir>/transcripts.jsonl] [--concurrency 4] [--rate-limit 60]

Reads the target API key from .red-team/.env (see .env.example). No other model is called.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml
from tqdm import tqdm

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from providers import MissingApiKey, ModelClient, RateLimiter  # noqa: E402
from run_context import DEFAULT_CONFIG, RUN_DIR_ENV, resolve_run_context  # noqa: E402
from schema import new_id  # noqa: E402


def load_config(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def build_targets(cfg: dict, limiter: RateLimiter) -> list[ModelClient]:
    targets_cfg = cfg.get("targets")
    if targets_cfg:
        return [ModelClient(t, limiter=limiter, label=f"target[{i}]")
                for i, t in enumerate(targets_cfg)]
    if cfg.get("target"):
        return [ModelClient(cfg["target"], limiter=limiter, label="target")]
    raise KeyError("target")


def messages_for(attack: dict) -> list[dict]:
    msgs = attack.get("messages")
    if msgs:
        return list(msgs)
    return [{"role": "user", "content": attack.get("prompt", "")}]


def query_one(attack: dict, target: ModelClient) -> dict:
    messages = messages_for(attack)
    out = dict(attack)
    try:
        result = target.chat_response(messages)
    except Exception as exc:
        result = {"content": "", "reasoning_content": "", "response": ""}
        out["error"] = str(exc)[:200]
    response = result["response"]
    full = list(messages) + [{"role": "assistant", "content": response}]
    out.setdefault("id", new_id())
    out["messages"] = full
    out["prompt"] = messages[-1]["content"] if messages else ""
    out["response"] = response
    out["assistant_content"] = result["content"]
    out["reasoning_content"] = result["reasoning_content"]
    out["provider"] = target.provider
    out["target_model"] = target.model
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Query the target model with agent-authored attacks")
    ap.add_argument("--config")
    ap.add_argument("--run-dir", help="isolated run artifact directory")
    ap.add_argument("--in", dest="inp")
    ap.add_argument("--out")
    ap.add_argument("--concurrency", type=int)
    ap.add_argument("--rate-limit", type=float, help="target requests per minute")
    args = ap.parse_args(argv)

    run_dir_hint = args.run_dir or os.environ.get(RUN_DIR_ENV)
    cfg_path = Path(args.config) if args.config else Path(run_dir_hint) / "config.yaml" if run_dir_hint else DEFAULT_CONFIG
    cfg = load_config(cfg_path)
    ctx = resolve_run_context(cfg, args.run_dir, create=True)
    run_cfg = cfg.get("run", {})
    concurrency = args.concurrency or int(run_cfg.get("concurrency", 4))
    rate_limit = args.rate_limit if args.rate_limit is not None else float(run_cfg.get("rate_limit_per_min", 60))

    limiter = RateLimiter(rate_limit)
    try:
        targets = build_targets(cfg, limiter)
    except MissingApiKey as exc:
        print(f"\nMissing API key: {exc}\n", file=sys.stderr)
        return 2
    except KeyError:
        print("Config needs a 'target' (or 'targets') section.", file=sys.stderr)
        return 2

    attacks = []
    input_path = Path(args.inp) if args.inp else ctx.path("attacks.jsonl")
    with input_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                attacks.append(json.loads(line))
    if not attacks:
        print("No attacks in input.", file=sys.stderr)
        return 1

    out_path = Path(args.out) if args.out else ctx.path("transcripts.jsonl")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out_path.open("a", encoding="utf-8") as out_f, \
            ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(query_one, a, targets[i % len(targets)]): i
                   for i, a in enumerate(attacks)}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="targets"):
            rec = fut.result()
            out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out_f.flush()
            written += 1
    print(f"wrote {written} transcripts -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
