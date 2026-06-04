#!/usr/bin/env python3
"""
hacker finding normalizer and deduplicator.

Accepts JSON outputs from child skills or normalized finding lists, adapts common
scanner schemas, merges overlapping findings, and emits a suite-level result.
Pure standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_RANK = {"P0": 4, "P1": 3, "P2": 2, "P3": 1, "Informational": 0, "By-Design": 0}
RANK_SEVERITY = {value: key for key, value in SEVERITY_RANK.items() if key != "By-Design"}
EFFORT_RANK = {"Quick Fix": 0, "Moderate": 1, "Complex": 2, "Unknown": 3}

BOOSTER_PATHS = (
    "auth/",
    "login/",
    "session/",
    "token/",
    "payment/",
    "billing/",
    "checkout/",
    "admin/",
    "api/",
    "routes/",
    "controllers/",
    "release",
    "deploy",
)

REDUCER_PATHS = (
    "test/",
    "tests/",
    "spec/",
    "fixtures/",
    "fixture/",
    "example/",
    "examples/",
    "demo/",
    "docs/",
    "samples/",
    "sample/",
)

APP_SKILLS = {"authz-security", "crypto-secrets"}
PIPELINE_SKILLS = {"ci-cd-security", "supply-chain-security"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize and deduplicate hacker findings")
    parser.add_argument("inputs", nargs="*", help="JSON result files. Reads stdin when omitted.")
    parser.add_argument("--output", help="Write JSON result to this file")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args(argv)

    raw_docs = load_inputs(args.inputs)
    findings, run_log = collect_findings(raw_docs)
    normalized = [normalize_finding(item, source_hint=source) for source, item in findings]
    deduped, merge_log = dedupe_findings(normalized)
    adjusted, adjustment_log = apply_context_scoring(deduped)
    adjusted = sorted(adjusted, key=finding_sort_key)
    result = {
        "tool": "hacker-deduplicator",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summarize(adjusted),
        "findings": adjusted,
        "merge_log": merge_log,
        "adjustment_log": adjustment_log,
        "run_log": run_log,
        "input_count": len(raw_docs),
    }

    rendered = json.dumps(result, indent=2, sort_keys=True) if args.format == "json" else render_markdown(result)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


def load_inputs(paths: list[str]) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    if not paths:
        data = sys.stdin.read().strip()
        if data:
            loaded = json.loads(data)
            docs.append(loaded if isinstance(loaded, dict) else {"findings": loaded})
        return docs

    for raw_path in paths:
        path = Path(raw_path).expanduser().resolve()
        loaded = json.loads(path.read_text(encoding="utf-8"))
        doc = loaded if isinstance(loaded, dict) else {"findings": loaded}
        doc.setdefault("_input_path", str(path))
        docs.append(doc)
    return docs


def collect_findings(docs: list[dict[str, Any]]) -> tuple[list[tuple[str, dict[str, Any]]], list[dict[str, Any]]]:
    findings: list[tuple[str, dict[str, Any]]] = []
    run_log: list[dict[str, Any]] = []
    for doc in docs:
        source = source_from_doc(doc)
        status = doc.get("status") or ("completed" if "findings" in doc else "unknown")
        run_log.append(
            {
                "source_skill": source,
                "status": status,
                "input_path": doc.get("_input_path"),
                "finding_count": len(doc.get("findings", []) or []),
                "summary": doc.get("summary"),
            }
        )
        for finding in doc.get("findings", []) or []:
            if isinstance(finding, dict):
                findings.append((source, finding))
    return findings, run_log


def source_from_doc(doc: dict[str, Any]) -> str:
    for key in ("source_skill", "scanner", "skill", "name"):
        value = doc.get(key)
        if isinstance(value, str):
            return normalize_skill_name(value)
    path = doc.get("_input_path")
    if path:
        name = Path(path).stem
        for known in (
            "crypto-secrets",
            "infra-security",
            "skill-security",
            "authz-security",
            "ci-cd-security",
            "supply-chain-security",
            "recon-security",
            "vulnerability-triage",
            "hacker",
            "security-suite",
        ):
            if known in name:
                return "hacker" if known == "security-suite" else known
    return "unknown"


def normalize_skill_name(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def normalize_finding(raw: dict[str, Any], source_hint: str) -> dict[str, Any]:
    source_values = raw.get("source_skills") or raw.get("source_skill") or raw.get("sources") or source_hint
    source_skills = normalize_sources(source_values)
    rule_id = str(raw.get("rule_id") or raw.get("control_id") or raw.get("id") or raw.get("check_id") or "manual-finding")
    file_value = str(raw.get("file") or raw.get("file_path") or raw.get("path") or raw.get("target") or "unknown")
    line = to_int(raw.get("line") or raw.get("line_number") or raw.get("start_line"))
    line_range = normalize_line_range(raw.get("line_range"), raw.get("start_line"), raw.get("end_line"), line)
    severity = normalize_severity(raw.get("severity") or raw.get("risk") or raw.get("level"))
    title = str(raw.get("title") or raw.get("message") or raw.get("summary") or rule_id)
    category = str(raw.get("category") or raw.get("type") or infer_category(rule_id, source_skills))
    description = str(raw.get("description") or raw.get("rationale") or raw.get("details") or raw.get("message") or title)
    recommendation = str(raw.get("recommendation") or raw.get("recommended_action") or raw.get("fix") or raw.get("remediation") or "Review and remediate according to the source skill guidance.")
    effort = normalize_effort(raw.get("effort"))
    evidence = raw.get("evidence") or raw.get("snippet") or raw.get("current") or raw.get("code") or ""
    controls = raw.get("compliance_controls") or raw.get("compliance") or raw.get("controls") or []
    confidence = raw.get("confidence")
    normalized = {
        "id": "",
        "source_skills": source_skills,
        "severity": severity,
        "category": category,
        "rule_id": rule_id,
        "file": normalize_path(file_value),
        "line": line,
        "line_range": line_range,
        "title": title,
        "description": description,
        "evidence": redact_string(evidence),
        "recommendation": recommendation,
        "effort": effort,
        "compliance_controls": controls,
        "confidence": confidence,
        "source_status": raw.get("source_status") or "candidate",
        "original": raw,
    }
    normalized["id"] = stable_id(normalized)
    return normalized


def normalize_sources(value: Any) -> list[str]:
    if isinstance(value, list):
        return sorted({normalize_skill_name(str(item)) for item in value})
    if isinstance(value, str):
        return [normalize_skill_name(value)]
    return ["unknown"]


def normalize_line_range(value: Any, start: Any, end: Any, line: int | None) -> list[int] | None:
    if isinstance(value, list) and len(value) >= 2:
        left, right = to_int(value[0]), to_int(value[1])
        return [left, right] if left is not None and right is not None else None
    left, right = to_int(start), to_int(end)
    if left is not None and right is not None:
        return [left, right]
    if line is not None:
        return [line, line]
    return None


def normalize_severity(value: Any) -> str:
    text = str(value or "Informational").strip()
    upper = text.upper()
    if upper in {"P0", "CRITICAL", "CRIT"}:
        return "P0"
    if upper in {"P1", "HIGH"}:
        return "P1"
    if upper in {"P2", "MEDIUM", "MODERATE"}:
        return "P2"
    if upper in {"P3", "LOW"}:
        return "P3"
    if upper in {"INFO", "INFORMATIONAL"}:
        return "Informational"
    if upper in {"BY-DESIGN", "BY_DESIGN", "BY DESIGN"}:
        return "By-Design"
    return text if text in SEVERITY_RANK else "Informational"


def normalize_effort(value: Any) -> str:
    text = str(value or "Unknown").strip()
    for allowed in EFFORT_RANK:
        if text.lower() == allowed.lower():
            return allowed
    return "Unknown"


def infer_category(rule_id: str, sources: list[str]) -> str:
    joined = " ".join(sources + [rule_id]).lower()
    if "authz" in joined or "bola" in joined or "idor" in joined:
        return "Authorization"
    if "crypto" in joined or "jwt" in joined or "tls" in joined:
        return "Cryptography"
    if "secret" in joined:
        return "Secrets"
    if "ci" in joined or "workflow" in joined:
        return "CI/CD"
    if "infra" in joined or "iam" in joined or "container" in joined or "network" in joined:
        return "Infrastructure"
    if "supply" in joined or "dependency" in joined:
        return "Supply Chain"
    if "skill" in joined or "plugin" in joined:
        return "Skill Safety"
    if "recon" in joined:
        return "Recon"
    if "triage" in joined or "vulnerability" in joined:
        return "Triage"
    return "Security"


def to_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def dedupe_findings(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_primary: dict[tuple[str, int | None, str], dict[str, Any]] = {}
    merge_log: list[dict[str, Any]] = []

    for finding in findings:
        key = (finding["file"], finding["line"], finding["rule_id"])
        if finding["file"] != "unknown" and finding["line"] is not None and finding["rule_id"] != "manual-finding":
            if key in by_primary:
                before = by_primary[key]
                by_primary[key] = merge_two(before, finding)
                merge_log.append(log_merge(by_primary[key], [before, finding], "primary key: file, line, rule_id"))
            else:
                by_primary[key] = finding
        else:
            synthetic_key = (finding["id"], None, finding["rule_id"])
            by_primary[synthetic_key] = finding

    merged: list[dict[str, Any]] = []
    for finding in by_primary.values():
        target_index = find_secondary_match(merged, finding)
        if target_index is None:
            merged.append(finding)
            continue
        before = merged[target_index]
        merged[target_index] = merge_two(before, finding)
        merge_log.append(log_merge(merged[target_index], [before, finding], "secondary key: overlapping file/category range"))

    for finding in merged:
        finding["id"] = stable_id(finding)
        finding.pop("original", None)
    return merged, merge_log


def find_secondary_match(existing: list[dict[str, Any]], finding: dict[str, Any]) -> int | None:
    if finding["file"] == "unknown":
        return None
    for index, other in enumerate(existing):
        if other["file"] != finding["file"] or other["category"] != finding["category"]:
            continue
        if ranges_overlap(other.get("line_range"), finding.get("line_range")):
            return index
    return None


def ranges_overlap(left: list[int] | None, right: list[int] | None) -> bool:
    if not left or not right:
        return False
    left_start, left_end = left
    right_start, right_end = right
    return max(left_start, right_start) <= min(left_end, right_end) + 3


def merge_two(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(left)
    merged["severity"] = higher_severity(left["severity"], right["severity"])
    merged["source_skills"] = sorted(set(left["source_skills"]) | set(right["source_skills"]))
    merged["rule_id"] = combine_unique(left["rule_id"], right["rule_id"])
    merged["title"] = left["title"] if SEVERITY_RANK[left["severity"]] >= SEVERITY_RANK[right["severity"]] else right["title"]
    merged["description"] = combine_unique(left["description"], right["description"])
    merged["recommendation"] = combine_unique(left["recommendation"], right["recommendation"])
    merged["evidence"] = combine_unique(str(left.get("evidence", "")), str(right.get("evidence", "")))
    merged["effort"] = higher_effort(left.get("effort", "Unknown"), right.get("effort", "Unknown"))
    merged["compliance_controls"] = merge_controls(left.get("compliance_controls"), right.get("compliance_controls"))
    merged["line_range"] = union_ranges(left.get("line_range"), right.get("line_range"))
    merged["line"] = merged["line_range"][0] if merged.get("line_range") else left.get("line")
    merged["id"] = stable_id(merged)
    return merged


def higher_severity(left: str, right: str) -> str:
    return left if SEVERITY_RANK.get(left, 0) >= SEVERITY_RANK.get(right, 0) else right


def higher_effort(left: str, right: str) -> str:
    return left if EFFORT_RANK.get(left, 3) >= EFFORT_RANK.get(right, 3) else right


def combine_unique(left: str, right: str) -> str:
    values = [v for v in (left, right) if v]
    result: list[str] = []
    for value in values:
        for part in str(value).split("\n---\n"):
            if part and part not in result:
                result.append(part)
    return "\n---\n".join(result)


def merge_controls(left: Any, right: Any) -> Any:
    if isinstance(left, dict) or isinstance(right, dict):
        merged: dict[str, Any] = {}
        for item in (left, right):
            if isinstance(item, dict):
                for key, value in item.items():
                    merged.setdefault(key, [])
                    if isinstance(value, list):
                        merged[key].extend(v for v in value if v not in merged[key])
                    elif value not in merged[key]:
                        merged[key].append(value)
        return merged
    values: list[Any] = []
    for item in (left, right):
        if isinstance(item, list):
            values.extend(v for v in item if v not in values)
        elif item and item not in values:
            values.append(item)
    return values


def union_ranges(left: list[int] | None, right: list[int] | None) -> list[int] | None:
    if not left:
        return right
    if not right:
        return left
    return [min(left[0], right[0]), max(left[1], right[1])]


def apply_context_scoring(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    adjusted: list[dict[str, Any]] = []
    log: list[dict[str, Any]] = []
    for finding in findings:
        item = deepcopy(finding)
        original = item["severity"]
        reason = None
        path = item["file"].lower()
        sources = set(item["source_skills"])

        if any(token in path for token in REDUCER_PATHS):
            item["severity"] = downgrade(item["severity"])
            reason = "downgraded for test, fixture, example, demo, docs, or sample path"
        elif APP_SKILLS & sources and PIPELINE_SKILLS & sources and item["severity"] == "P2":
            item["severity"] = "P1"
            reason = "upgraded because the issue crosses application code and CI/release surface"
        elif any(token in path for token in BOOSTER_PATHS):
            item["severity"] = upgrade(item["severity"])
            reason = "upgraded for sensitive path or public/release surface"

        if item["severity"] != original:
            log.append({"finding_id": item["id"], "from": original, "to": item["severity"], "reason": reason})
            item["id"] = stable_id(item)
        adjusted.append(item)
    return adjusted, log


def upgrade(severity: str) -> str:
    if severity in {"Informational", "By-Design"}:
        return severity
    rank = min(SEVERITY_RANK.get(severity, 0) + 1, SEVERITY_RANK["P0"])
    return RANK_SEVERITY[rank]


def downgrade(severity: str) -> str:
    if severity in {"Informational", "By-Design"}:
        return severity
    rank = max(SEVERITY_RANK.get(severity, 0) - 1, SEVERITY_RANK["P3"])
    return RANK_SEVERITY[rank]


def log_merge(result: dict[str, Any], sources: list[dict[str, Any]], reason: str) -> dict[str, Any]:
    return {
        "result_id": result["id"],
        "reason": reason,
        "source_ids": [source.get("id") for source in sources],
        "source_skills": sorted({skill for source in sources for skill in source.get("source_skills", [])}),
        "file": result.get("file"),
        "line_range": result.get("line_range"),
    }


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {severity: 0 for severity in ("P0", "P1", "P2", "P3", "Informational")}
    for finding in findings:
        severity = finding.get("severity", "Informational")
        if severity == "By-Design":
            severity = "Informational"
        counts[severity] = counts.get(severity, 0) + 1
    return {
        "counts": counts,
        "total": len(findings),
        "risk_rating": risk_rating(counts),
    }


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


def finding_sort_key(finding: dict[str, Any]) -> tuple[int, int, int, str, int]:
    controls = finding.get("compliance_controls") or []
    compliance_count = len(controls) if isinstance(controls, list) else len(controls.keys()) if isinstance(controls, dict) else 0
    return (
        -SEVERITY_RANK.get(finding.get("severity", "Informational"), 0),
        EFFORT_RANK.get(finding.get("effort", "Unknown"), 3),
        -compliance_count,
        finding.get("file", ""),
        finding.get("line") or 0,
    )


def stable_id(finding: dict[str, Any]) -> str:
    raw = "|".join(
        [
            ",".join(finding.get("source_skills", [])),
            str(finding.get("rule_id", "")),
            str(finding.get("file", "")),
            str(finding.get("line", "")),
            str(finding.get("title", "")),
            str(finding.get("severity", "")),
        ]
    )
    return "SSF-" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]


def redact_string(value: Any) -> str:
    text = str(value)
    if len(text) <= 120:
        return text
    return text[:80] + "...[truncated/redacted]..." + text[-20:]


def normalize_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./")


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Deduplicated Security Suite Findings",
        "",
        f"Risk rating: **{result['summary']['risk_rating']}**",
        f"Total findings: {result['summary']['total']}",
        "",
    ]
    for finding in result["findings"]:
        location = finding["file"]
        if finding.get("line"):
            location += f":{finding['line']}"
        lines.extend(
            [
                f"## [{finding['severity']}] {finding['title']}",
                "",
                f"- ID: `{finding['id']}`",
                f"- Location: `{location}`",
                f"- Category: {finding['category']}",
                f"- Source skills: {', '.join(finding['source_skills'])}",
                f"- Effort: {finding['effort']}",
                "",
                finding["description"],
                "",
                f"Recommendation: {finding['recommendation']}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


if __name__ == "__main__":
    raise SystemExit(main())
