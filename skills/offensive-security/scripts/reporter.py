#!/usr/bin/env python3
"""
Render confirmed-vulnerabilities markdown report from validator outcomes.

Usage:
    python3 reporter.py <outcomes.json> [--output report.md] [--target name]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from jinja2 import Template
except ImportError as exc:
    print("Install requirements: pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2) from exc


SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
TEMPLATE_PATH = SKILL_DIR / "references" / "confirmed-report-template.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render offensive-security report")
    parser.add_argument("input", help="Validator outcomes JSON")
    parser.add_argument("--output", help="Markdown output path")
    parser.add_argument("--target", default="repository", help="Target label for report header")
    args = parser.parse_args(argv)

    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    outcomes = data.get("outcomes", [])
    context = build_context(outcomes, data, args.target)
    template = Template(TEMPLATE_PATH.read_text(encoding="utf-8"))
    report = template.render(**context)

    out_path = args.output or f"offensive-security-report-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.md"
    Path(out_path).write_text(report + "\n", encoding="utf-8")
    print(out_path)
    return 0


def build_context(outcomes: list[dict[str, Any]], meta: dict[str, Any], target: str) -> dict[str, Any]:
    confirmed = [o for o in outcomes if o.get("outcome") == "confirmed"]
    inconclusive = [o for o in outcomes if o.get("outcome") == "inconclusive"]
    false_positives = [o for o in outcomes if o.get("outcome") == "false_positive"]
    total = len(outcomes)
    confirmed_count = len(confirmed)
    rate = f"{(confirmed_count / total * 100):.1f}" if total else "0.0"

    roadmap = sorted(
        [
            {
                "priority": o.get("remediation_priority", 99),
                "title": o.get("title", ""),
                "severity": o.get("severity", ""),
                "blast_radius": o.get("blast_radius", ""),
                "effort": "Moderate",
            }
            for o in confirmed
        ],
        key=lambda r: r["priority"],
    )

    for item in confirmed:
        item["finding_id"] = item.get("parent_finding_id", "")
        item["poc_steps"] = item.get("poc_steps") or [item.get("rationale", "")]

    chaining_text, chaining_mermaid = build_chaining(confirmed)

    return {
        "timestamp": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "target": target,
        "total_hypotheses": total,
        "confirmed_count": confirmed_count,
        "confirmation_rate": rate,
        "risk_rating": risk_rating(confirmed),
        "executive_summary": executive_summary(confirmed, false_positives, total),
        "confirmed": confirmed,
        "inconclusive": inconclusive,
        "false_positives": false_positives,
        "remediation_roadmap": roadmap,
        "all_hypotheses": outcomes,
        "chaining_text": chaining_text,
        "chaining_mermaid": chaining_mermaid,
        "scope_file": meta.get("scope_file") or "none",
        "docker_available": meta.get("docker_available", False),
        "dry_run": meta.get("dry_run", True),
        "runtime_seconds": meta.get("runtime_seconds", 0),
        "sandboxes_torn_down": meta.get("sandboxes_torn_down", 0),
    }


def risk_rating(confirmed: list[dict[str, Any]]) -> str:
    if not confirmed:
        return "None"
    severities = [c.get("severity", "P3") for c in confirmed]
    if "P0" in severities:
        return "Critical"
    if severities.count("P1") >= 3:
        return "High"
    if "P1" in severities or "P2" in severities:
        return "Medium"
    return "Low"


def executive_summary(confirmed: list[dict[str, Any]], fps: list[dict[str, Any]], total: int) -> str:
    top = confirmed[0].get("title", "none") if confirmed else "none"
    return (
        f"Validated {total} hypotheses; {len(confirmed)} confirmed exploitable in sandbox scope. "
        f"{len(fps)} false positives for defensive tuning. Highest-impact confirmed: {top}."
    )


def build_chaining(confirmed: list[dict[str, Any]]) -> tuple[str, str]:
    if len(confirmed) < 2:
        return "No multi-step chains identified.", ""
    by_file: dict[str, list[str]] = {}
    for c in confirmed:
        by_file.setdefault(c.get("file", "unknown"), []).append(c.get("rule_id", ""))
    lines = ["Chaining opportunities:"]
    nodes = []
    for file_path, rules in by_file.items():
        if len(rules) > 1:
            lines.append(f"- `{file_path}`: {' → '.join(rules)}")
            nodes.append(f'  {file_path.replace("/", "_")}["{file_path}"]')
    mermaid = ""
    if len(nodes) >= 2:
        mermaid = "flowchart LR\n" + "\n".join(nodes[:5])
    return "\n".join(lines), mermaid


if __name__ == "__main__":
    sys.exit(main())
