#!/usr/bin/env python3
"""
hacker thin orchestration helper.

This script does deterministic support work only:
1. discover the target surface and dispatch plan;
2. optionally merge JSON outputs already produced by child skills/scanners;
3. optionally render a markdown report.

It does not run model-only specialist skills by itself.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import deduplicator  # noqa: E402
import discover  # noqa: E402
import reporter  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hacker discovery, merge, and report helper")
    parser.add_argument("target", help="Target repository or file")
    parser.add_argument("--domain", help="Authorized live domain/IP scope for recon-security")
    parser.add_argument("--advisory", help="Supplied advisory/report input for vulnerability-triage")
    parser.add_argument(
        "--offensive",
        action="store_true",
        help="Discovery plan includes offensive-security (agent runs validation with --scope)",
    )
    parser.add_argument("--scope", help="Path to scope.yaml for offensive-security (documented for agent; not executed here)")
    parser.add_argument("--findings", nargs="*", default=[], help="Child skill JSON outputs to merge")
    parser.add_argument("--plan-output", help="Write discovery plan JSON to this path")
    parser.add_argument("--deduped-output", help="Write deduplicated JSON to this path")
    parser.add_argument("--output", help="Write markdown report to this path")
    parser.add_argument("--plan-only", action="store_true", help="Only emit discovery plan")
    parser.add_argument("--strict", action="store_true", help="Exit 1 when merged results contain P0 or P1")
    args = parser.parse_args(argv)

    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"Target not found: {target}", file=sys.stderr)
        return 2

    matrix = discover.load_matrix(discover.DEFAULT_MATRIX)
    root = target if target.is_dir() else target.parent
    inventory = discover.build_inventory(target, root)
    plan = discover.build_dispatch_plan(target, root, inventory, matrix, args.domain, args.advisory, args.offensive)
    plan_json = json.dumps(plan, indent=2, sort_keys=True)

    if args.plan_output:
        Path(args.plan_output).write_text(plan_json + "\n", encoding="utf-8")

    if args.plan_only or not args.findings:
        print(plan_json)
        if not args.findings and not args.plan_only:
            print(
                "\nNo --findings files were supplied. The plan above tells the agent which specialist skills still need to run.",
                file=sys.stderr,
            )
        return 0

    raw_docs = deduplicator.load_inputs(args.findings)
    collected, run_log = deduplicator.collect_findings(raw_docs)
    normalized = [deduplicator.normalize_finding(item, source_hint=source) for source, item in collected]
    deduped, merge_log = deduplicator.dedupe_findings(normalized)
    adjusted, adjustment_log = deduplicator.apply_context_scoring(deduped)
    adjusted = sorted(adjusted, key=deduplicator.finding_sort_key)
    result = {
        "tool": "hacker-orchestrator",
        "offensive_requested": args.offensive,
        "offensive_scope": args.scope,
        "post_audit_skills": plan.get("post_audit_skills", []),
        "workflow_order": plan.get("workflow_order", plan.get("skills_to_run", [])),
        "summary": deduplicator.summarize(adjusted),
        "findings": adjusted,
        "merge_log": merge_log,
        "adjustment_log": adjustment_log,
        "run_log": run_log,
        "input_count": len(raw_docs),
    }

    deduped_json = json.dumps(result, indent=2, sort_keys=True)
    if args.deduped_output:
        Path(args.deduped_output).write_text(deduped_json + "\n", encoding="utf-8")

    if args.output:
        report = reporter.render_report(result, plan)
        Path(args.output).write_text(report + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "risk_rating": result["summary"]["risk_rating"],
                    "total_findings": result["summary"]["total"],
                    "report": str(Path(args.output).resolve()),
                    "deduped": str(Path(args.deduped_output).resolve()) if args.deduped_output else None,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(deduped_json)

    if args.strict and any(item.get("severity") in {"P0", "P1"} for item in adjusted):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
