#!/usr/bin/env python3
"""
Generate exploit hypotheses from normalized findings using hypothesis-templates.yaml.

Usage:
    python3 hypothesis_generator.py <normalized.json> [--output hypotheses.json]
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    import yaml
    from jinja2 import Environment, BaseLoader
except ImportError as exc:  # pragma: no cover
    print("Install requirements: pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2) from exc


SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
TEMPLATES_PATH = SKILL_DIR / "references" / "hypothesis-templates.yaml"

CONFIDENCE_RANK = {"High": 3, "Medium": 2, "Low": 1}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate offensive-security hypotheses")
    parser.add_argument("input", help="Normalized findings JSON from ingest_findings.py")
    parser.add_argument("--output", help="Write hypotheses JSON")
    args = parser.parse_args(argv)

    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    findings = data.get("findings", data if isinstance(data, list) else [])
    hypotheses = generate_hypotheses_from_findings(findings)
    payload = {"hypotheses": hypotheses, "count": len(hypotheses)}
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


def generate_hypotheses_from_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    templates = load_templates()
    env = Environment(loader=BaseLoader(), autoescape=False)
    hypotheses: list[dict[str, Any]] = []
    for finding in findings:
        matched = match_templates(finding, templates)
        for template in matched:
            hypotheses.append(build_hypothesis(finding, template, env))
    hypotheses.extend(build_compound_hypotheses(findings, hypotheses))
    hypotheses = dedupe_hypotheses(hypotheses)
    hypotheses.sort(key=lambda h: (-CONFIDENCE_RANK.get(h["confidence"], 0), h["title"]))
    return hypotheses


def generate_followup_hypotheses(
    confirmed_outcomes: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    tested_keys: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Autoresearch: new chain hypotheses after confirmed validations."""
    followups: list[dict[str, Any]] = []
    confirmed_by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for outcome in confirmed_outcomes:
        file_path = outcome.get("file") or "unknown"
        confirmed_by_file[file_path].append(outcome)

    for file_path, group in confirmed_by_file.items():
        if len(group) < 1:
            continue
        rule_ids = sorted({o.get("rule_id", "") for o in group if o.get("rule_id")})
        parent_ids = sorted({o.get("parent_finding_id", "") for o in group if o.get("parent_finding_id")})
        chain_key = (file_path, "autoresearch-chain")
        if chain_key in tested_keys:
            continue
        titles = [o.get("title", "") for o in group]
        followups.append(
            {
                "hypothesis_id": str(uuid.uuid4()),
                "parent_finding_id": parent_ids[0] if parent_ids else str(uuid.uuid4()),
                "parent_finding_ids": parent_ids,
                "type": "privilege_escalation",
                "title": f"Autoresearch: chain confirmed issues on {file_path} ({', '.join(rule_ids)})?",
                "prerequisites": ["Prior confirmations reproducible in sandbox", "Combined misconfig available"],
                "validation_method": "config_exploit",
                "safe_scope": {
                    "max_requests": 5,
                    "rate_limit_rps": 1,
                    "allowed_targets": ["sandbox-container"],
                    "forbidden_actions": ["modify_production_data", "delete", "bruteforce"],
                },
                "success_criteria": "Chained confirmations yield broader access than any single issue alone",
                "example_poc": {"confirmed_steps": titles, "rule_ids": rule_ids},
                "template_id": "autoresearch-chain",
                "category": "compound",
                "file": file_path,
                "confidence": "Medium",
                "autoresearch_round": True,
            }
        )
        tested_keys.add(chain_key)

    for outcome in confirmed_outcomes:
        for finding in findings:
            if finding.get("file") != outcome.get("file"):
                continue
            if finding.get("finding_id") == outcome.get("parent_finding_id"):
                continue
            retry_key = (finding.get("finding_id", ""), "autoresearch-retry-inconclusive")
            if retry_key in tested_keys:
                continue
            followups.append(
                {
                    "hypothesis_id": str(uuid.uuid4()),
                    "parent_finding_id": finding["finding_id"],
                    "type": outcome.get("type", "unknown"),
                    "title": f"Autoresearch: combine confirmed '{outcome.get('title', '')[:60]}' with {finding.get('rule_id')}",
                    "prerequisites": ["Confirmed PoC from prior round"],
                    "validation_method": outcome.get("validation_method", "config_exploit"),
                    "safe_scope": {
                        "max_requests": 5,
                        "rate_limit_rps": 1,
                        "allowed_targets": ["sandbox-container", "self-hosted-test-api"],
                        "forbidden_actions": ["modify_production_data", "delete", "bruteforce"],
                    },
                    "success_criteria": "Combined attack path succeeds in sandbox",
                    "template_id": "autoresearch-combine",
                    "category": "compound",
                    "file": finding.get("file"),
                    "confidence": "Medium",
                    "autoresearch_round": True,
                }
            )
            tested_keys.add(retry_key)
            break

    return dedupe_hypotheses(followups)


def hypothesis_key(h: dict[str, Any]) -> tuple[str, str]:
    return (h.get("parent_finding_id", ""), h.get("template_id", h.get("title", "")))


def load_templates() -> list[dict[str, Any]]:
    raw = yaml.safe_load(TEMPLATES_PATH.read_text(encoding="utf-8"))
    return list(raw.get("templates", []))


def match_templates(finding: dict[str, Any], templates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rule_id = finding.get("rule_id", "")
    matched = []
    for template in templates:
        triggers = template.get("trigger_control_ids", [])
        if rule_id in triggers:
            matched.append(template)
    return matched


def build_hypothesis(finding: dict[str, Any], template: dict[str, Any], env: Environment) -> dict[str, Any]:
    ctx = {
        "resource_type": "database" if "db" in finding.get("rule_id", "") else "service",
        "port": "5432" if "db" in finding.get("rule_id", "") else "22",
        "resource_name": "resource",
        "user_b_id": "user-b-id",
        "target_ip": "10.0.0.5",
    }
    title_tpl = template.get("title_template", "Validate {{ rule_id }}")
    title = env.from_string(title_tpl).render(**ctx, **finding)

    return {
        "hypothesis_id": str(uuid.uuid4()),
        "parent_finding_id": finding["finding_id"],
        "type": template.get("type", "unknown"),
        "title": title,
        "prerequisites": template.get("prerequisites", []),
        "validation_method": template.get("validation_method", "sandbox_execution"),
        "safe_scope": template.get("safe_scope", {}),
        "success_criteria": template.get("success_criteria", ""),
        "example_poc": template.get("example_poc"),
        "template_id": template.get("id"),
        "category": template.get("category"),
        "rule_id": finding.get("rule_id"),
        "file": finding.get("file"),
        "line": finding.get("line"),
        "source_skill": finding.get("source_skill"),
        "severity": finding.get("severity"),
        "confidence": score_confidence(finding, template),
    }


def score_confidence(finding: dict[str, Any], template: dict[str, Any]) -> str:
    base = finding.get("confidence", "Medium")
    sev = finding.get("severity", "P3")
    boost = sev in {"P0", "P1"}
    rank = CONFIDENCE_RANK.get(base, 2) + (1 if boost else 0)
    if rank >= 3:
        return "High"
    if rank >= 2:
        return "Medium"
    return "Low"


def build_compound_hypotheses(
    findings: list[dict[str, Any]],
    existing: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        by_file[f.get("file", "unknown")].append(f)

    compounds: list[dict[str, Any]] = []
    for file_path, group in by_file.items():
        if len(group) < 2:
            continue
        ids = [g["finding_id"] for g in group]
        compounds.append(
            {
                "hypothesis_id": str(uuid.uuid4()),
                "parent_finding_id": ids[0],
                "parent_finding_ids": ids,
                "type": "privilege_escalation",
                "title": f"Can findings on {file_path} be chained for realistic breach?",
                "prerequisites": ["Sandbox reproduces combined misconfigurations"],
                "validation_method": "config_exploit",
                "safe_scope": {
                    "max_requests": 5,
                    "rate_limit_rps": 1,
                    "allowed_targets": ["sandbox-container"],
                    "forbidden_actions": ["modify_production_data", "delete", "bruteforce"],
                },
                "success_criteria": "Chained steps achieve elevated access in sandbox only",
                "example_poc": {"steps": [g.get("rule_id") for g in group]},
                "template_id": "compound-chain",
                "category": "compound",
                "file": file_path,
                "confidence": "Medium",
                "compound": True,
            }
        )
    return compounds


def dedupe_hypotheses(hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for h in hypotheses:
        key = (h.get("parent_finding_id", ""), h.get("template_id", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


if __name__ == "__main__":
    sys.exit(main())
