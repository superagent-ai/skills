#!/usr/bin/env python3
"""
Create an isolated red-team run directory.

Usage:
  python init_run.py --config .red-team/config.yaml
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from run_context import DEFAULT_CONFIG, DEFAULT_RUNS_DIR, RUN_DIR_ENV, init_run  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Create an isolated red-team run directory")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG), help="base config to copy")
    ap.add_argument("--run-id", help="optional explicit run id")
    ap.add_argument("--runs-dir", default=str(DEFAULT_RUNS_DIR), help="parent runs directory")
    args = ap.parse_args(argv)

    try:
        ctx = init_run(args.config, run_id=args.run_id, runs_dir=args.runs_dir)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except FileExistsError:
        print(f"Run directory already exists for run id: {args.run_id}", file=sys.stderr)
        return 2

    print(ctx.run_dir)
    print(f"export {RUN_DIR_ENV}={ctx.run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
