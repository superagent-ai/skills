#!/usr/bin/env python3
"""
hacker markdown reporter.

Renders the deduplicated JSON produced by deduplicator.py into an executive
report. Pure standard library; no template engine required.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITIES = ("P0", "P1", "P2", "P3", "Informational")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render a hacker markdown report")
    parser.add_argument("deduped", help="Deduplicated JSON result, or '-' for stdin")
    parser.add_argument("--plan", help="Discovery plan JSON from discover.py")
    parser.add_argument("--target", help="Override target path in report")
    parser.add_argument("--output", help="Write markdown report to this path")
    args = parser.parse_args(argv)

    result = load_json_arg(args.deduped)
    plan = load_json_file(args.plan) if args.plan else {}
    report = render_report(result, plan, target_override=args.target)

    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
    else:
        print(report)
    return 0


def load_json_arg(value: str) -> dict[str, Any]:
    if value == "-":
        return json.loads(sys.stdin.read())
    return load_json_file(value)


def load_json_file(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    return json.loads(Path(path).expanduser().resolve().read_text(encoding="utf-8"))


def render_report(result: dict[str, Any], plan: dict[str, Any], target_override: str | None = None) -> str:
    findings = result.get("findings", []) or []
    summary = result.get("summary") or summarize(findings)
    counts = summary.get("counts") or {}
    target = target_override or plan.get("target") or "unknown"
    repo_type = plan.get("repo_type") or "unknown"
    risk = summary.get("risk_rating") or risk_rating(counts)
    skills_to_run = plan.get("skills_to_run") or []
    run_log = result.get("run_log") or []
    completed = [entry.get("source_skill", "unknown") for entry in run_log if entry.get("status") == "completed"]
    failed_or_skipped = [entry for entry in run_log if entry.get("status") not in (None, "completed")]

    lines: list[str] = [
        f"# Security Suite Report: {target}",
        "",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}  ",
        f"**Target:** `{target}`  ",
        f"**Repo type:** {repo_type}  ",
        f"**Overall risk:** {risk}",
        "",
        "## Executive Summary",
        "",
        executive_summary(findings, risk, repo_type, skills_to_run),
        "",
        "## Scope And Methodology",
        "",
        f"- Target: `{target}`",
        "- Mode: read-only static review unless live recon scope is explicitly listed",
        f"- Skills selected: {comma(skills_to_run)}",
        f"- Skills completed: {comma(completed)}",
        f"- Skills failed or skipped: {comma([entry.get('source_skill', 'unknown') for entry in failed_or_skipped])}",
        "- Static limits: no target-code execution, no credential validation, and no cloud/API verification unless separately authorized",
        "",
        "## Risk Dashboard",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for severity in SEVERITIES:
        lines.append(f"| {severity} | {counts.get(severity, 0)} |")
    lines.append(f"| Total | {summary.get('total', len(findings))} |")

    lines.extend(["", "## Top Findings", ""])
    if findings:
        for finding in findings[:10]:
            lines.extend(render_finding(finding))
    else:
        lines.append("No findings against the selected hacker control set.")

    lines.extend(["", "## Per-Skill Detail", ""])
    if run_log:
        by_skill: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            for skill in finding.get("source_skills", []) or ["unknown"]:
                by_skill.setdefault(skill, []).append(finding)
        for entry in run_log:
            skill = entry.get("source_skill", "unknown")
            lines.extend(
                [
                    f"### {skill}",
                    "",
                    f"- Status: {entry.get('status', 'unknown')}",
                    f"- Findings: {len(by_skill.get(skill, []))}",
                    f"- Input: `{entry.get('input_path')}`" if entry.get("input_path") else "- Input: not recorded",
                    "",
                ]
            )
    else:
        lines.append("No per-skill run log was provided.")

    lines.extend(["", "## Deduplication Log", ""])
    merge_log = result.get("merge_log", []) or []
    if merge_log:
        for item in merge_log:
            lines.append(
                f"- `{item.get('result_id')}` merged {comma(item.get('source_ids') or [])}. "
                f"Reason: {item.get('reason')}. Sources: {comma(item.get('source_skills') or [])}."
            )
    else:
        lines.append("No findings were merged.")

    adjustment_log = result.get("adjustment_log", []) or []
    if adjustment_log:
        lines.extend(["", "### Severity Adjustments", ""])
        for item in adjustment_log:
            lines.append(f"- `{item.get('finding_id')}`: {item.get('from')} -> {item.get('to')} ({item.get('reason')})")

    lines.extend(["", "## Remediation Roadmap", ""])
    lines.extend(render_roadmap(findings))
    lines.extend(["", "## Compliance Mapping", ""])
    lines.extend(render_compliance(findings))
    lines.extend(["", "## Appendix", ""])
    lines.extend(render_appendix(plan, result))
    return "\n".join(lines).rstrip()


def executive_summary(findings: list[dict[str, Any]], risk: str, repo_type: str, skills: list[str]) -> str:
    if not findings:
        return (
            f"The suite reviewed a {repo_type} target with {len(skills)} selected specialist skills. "
            "No confirmed findings remained after normalization and deduplication. "
            "This is a clean result against the selected control set, not proof that runtime state or external services are secure."
        )
    top = findings[0]
    return (
        f"The suite reviewed a {repo_type} target with {len(skills)} selected specialist skills and rated overall risk as {risk}. "
        f"The highest-priority finding is {top.get('severity')} `{top.get('title')}` in `{format_location(top)}`. "
        "Address P0/P1 items first, then use the roadmap to schedule medium and hardening work."
    )


def render_finding(finding: dict[str, Any]) -> list[str]:
    lines = [
        f"### [{finding.get('severity')}] {finding.get('title')}",
        "",
        f"- ID: `{finding.get('id')}`",
        f"- Location: `{format_location(finding)}`",
        f"- Category: {finding.get('category')}",
        f"- Source skills: {comma(finding.get('source_skills') or [])}",
        f"- Effort: {finding.get('effort', 'Unknown')}",
        "",
        f"**Issue:** {finding.get('description')}",
        "",
        f"**Recommendation:** {finding.get('recommendation')}",
        "",
    ]
    evidence = finding.get("evidence")
    if evidence:
        lines.extend(["**Evidence:**", "", "```text", str(evidence), "```", ""])
    return lines


def render_roadmap(findings: list[dict[str, Any]]) -> list[str]:
    immediate = [f for f in findings if f.get("severity") in {"P0", "P1"}]
    short = [f for f in findings if f.get("severity") == "P2"]
    long = [f for f in findings if f.get("severity") in {"P3", "Informational", "By-Design"}]
    lines: list[str] = []
    for title, group in (("Immediate", immediate), ("Short Term", short), ("Long Term", long)):
        lines.extend([f"### {title}", ""])
        if not group:
            lines.extend(["No items.", ""])
            continue
        for finding in group:
            lines.append(f"- [{finding.get('severity')}] `{finding.get('id')}` {finding.get('title')} ({finding.get('effort', 'Unknown')})")
        lines.append("")
    return lines


def render_compliance(findings: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Finding | Severity | Controls |",
        "|---|---|---|",
    ]
    if not findings:
        lines.append("| None | - | - |")
        return lines
    for finding in findings:
        lines.append(f"| `{finding.get('id')}` | {finding.get('severity')} | {format_controls(finding.get('compliance_controls'))} |")
    return lines


def render_appendix(plan: dict[str, Any], result: dict[str, Any]) -> list[str]:
    lines = [
        "### Dispatch Plan",
        "",
        f"- Repo type: {plan.get('repo_type', 'unknown')}",
        f"- Confidence: {plan.get('confidence', 'unknown')}",
        f"- Matched signals: {comma(plan.get('matched_signals') or [])}",
        f"- Skills to run: {comma(plan.get('skills_to_run') or [])}",
        "",
        "### File Inventory",
        "",
    ]
    inventory = plan.get("inventory") or {}
    if inventory:
        lines.extend(
            [
                f"- Files: {inventory.get('file_count', 'unknown')}",
                f"- Directories: {inventory.get('dir_count', 'unknown')}",
                f"- Languages: {json.dumps(inventory.get('language_counts', {}), sort_keys=True)}",
            ]
        )
    else:
        lines.append("No discovery inventory was provided.")
    lines.extend(["", "### Limitations", ""])
    lines.extend(
        [
            "- Static review cannot prove deployed configuration, runtime secrets, secret validity, cloud drift, or registry reputation.",
            "- Clean output means no findings against the selected control set, not proof that the system is secure.",
            "- Any unrun, failed, or skipped specialist leaves an explicit coverage gap.",
        ]
    )
    return lines


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = finding.get("severity", "Informational")
        if severity == "By-Design":
            severity = "Informational"
        counts[severity] = counts.get(severity, 0) + 1
    return {"counts": counts, "total": len(findings), "risk_rating": risk_rating(counts)}


def risk_rating(counts: dict[str, int]) -> str:
    if counts.get("P0", 0):
        return "Critical"
    if counts.get("P1", 0):
        return "High"
    if counts.get("P2", 0):
        return "Medium"
    if counts.get("P3", 0):
        return "Low"
    return "Clean"


def format_location(finding: dict[str, Any]) -> str:
    location = str(finding.get("file") or "unknown")
    if finding.get("line"):
        location += f":{finding['line']}"
    return location


def format_controls(value: Any) -> str:
    if not value:
        return "-"
    if isinstance(value, dict):
        parts: list[str] = []
        for key, item in value.items():
            if isinstance(item, list):
                parts.append(f"{key}: {', '.join(map(str, item))}")
            else:
                parts.append(f"{key}: {item}")
        return "; ".join(parts)
    if isinstance(value, list):
        return ", ".join(map(str, value)) or "-"
    return str(value)


def comma(values: list[Any]) -> str:
    cleaned = [str(value) for value in values if value]
    return ", ".join(cleaned) if cleaned else "none"


if __name__ == "__main__":
    raise SystemExit(main())
