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
        help="Discovery plan includes offensive-security as the final subagent autoresearch phase",
    )
    parser.add_argument("--scope", help="Scope summary/path for offensive-security (documented for agent; not executed here)")
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
        "post_audit_plan": plan.get("post_audit_plan", []),
        "workflow_order": plan.get("workflow_order", plan.get("skills_to_run", [])),
        "summary": deduplicator.summarize(adjusted),
        "findings": adjusted,
        "merge_log": merge_log,
        "adjustment_log": adjustment_log,
        "run_log": run_log,
        "input_count": len(raw_docs),
    }
    offensive_followup = build_offensive_followup(plan, args.scope, args.deduped_output, args.output)
    if offensive_followup:
        result["offensive_followup"] = offensive_followup

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
                    "offensive_followup": offensive_followup.get("status") if offensive_followup else None,
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


def build_offensive_followup(
    plan: dict,
    scope: str | None,
    deduped_output: str | None,
    report_output: str | None,
) -> dict | None:
    if "offensive-security" not in plan.get("post_audit_skills", []):
        return None
    post_audit_plan = plan.get("post_audit_plan") or []
    phase_plan = next((item for item in post_audit_plan if item.get("skill") == "offensive-security"), {})
    triage_plan = next(
        (
            item
            for item in post_audit_plan
            if item.get("skill") == "vulnerability-triage"
            and str(item.get("phase", "")).startswith("Phase 7")
        ),
        {},
    )
    return {
        "status": "ready_for_phase6",
        "skill": "offensive-security",
        "scope": scope,
        "validation_boundary": (
            scope
            if scope
            else "local-only planning and sandbox fixtures inferred from findings; live or external validation is unsafe_to_test"
        ),
        "deduped_findings": (
            str(Path(deduped_output).expanduser().resolve())
            if deduped_output
            else "not written; rerun with --deduped-output or pass this JSON result to offensive-security"
        ),
        "hacker_report": str(Path(report_output).expanduser().resolve()) if report_output else None,
        "load": phase_plan.get(
            "load",
            [
                "skills/offensive-security/SKILL.md",
                "skills/offensive-security/references/autoresearch-loop.md",
            ],
        ),
        "agent_action": phase_plan.get(
            "agent_action",
            "Load offensive-security and run the subagent autoresearch loop last.",
        ),
        "loop": phase_plan.get("loop", {}),
        "post_offensive_triage": {
            "skill": triage_plan.get("skill", "vulnerability-triage"),
            "phase": triage_plan.get("phase", "Phase 7 - Post-Offensive False-Positive Triage"),
            "load": triage_plan.get(
                "load",
                [
                    "skills/vulnerability-triage/SKILL.md",
                    "skills/vulnerability-triage/references/severity-rubric.md",
                    "skills/vulnerability-triage/references/triage-report-template.md",
                ],
            ),
            "agent_action": triage_plan.get(
                "agent_action",
                "Run vulnerability-triage after offensive-security to review false positives and by-design outcomes.",
            ),
        },
        "notes": [
            "The Python helper does not execute instruction-only skills.",
            "A parent agent must load the listed skill files and coordinate Phase 6 subagents.",
            "Do not stop before Phase 6 just because written scope is missing; run the hypothesis loop under a local-only planning boundary.",
            "Without written scope, live or external validation remains unsafe_to_test.",
            "After Phase 6, run vulnerability-triage over offensive outcomes before the final hacker summary.",
        ],
    }


if __name__ == "__main__":
    raise SystemExit(main())
