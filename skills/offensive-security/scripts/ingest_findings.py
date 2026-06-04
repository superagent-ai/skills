#!/usr/bin/env python3
"""
Ingest defensive security JSON and normalize for offensive-security hypothesis generation.

Usage:
    python3 ingest_findings.py <findings.json|findings_dir> [--output file.json]
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"P0": 4, "P1": 3, "P2": 2, "P3": 1, "Informational": 0}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize defensive findings for offensive-security")
    parser.add_argument("input", help="JSON file or directory of JSON outputs")
    parser.add_argument("--output", help="Write normalized JSON (default: stdout)")
    args = parser.parse_args(argv)

    path = Path(args.input).expanduser().resolve()
    raw_docs = load_documents(path)
    normalized = []
    for doc in raw_docs:
        source = detect_source_skill(doc)
        for raw in extract_findings(doc):
            normalized.append(normalize_finding(raw, source))

    normalized.sort(key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0), f["file"], f["line"] or 0))
    payload = {"findings": normalized, "count": len(normalized)}
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


def load_documents(path: Path) -> list[dict[str, Any]]:
    if path.is_file():
        return [load_json(path)]
    docs: list[dict[str, Any]] = []
    for child in sorted(path.glob("*.json")):
        docs.append(load_json(child))
    return docs


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {"findings": data, "_input_path": str(path)}
    if isinstance(data, dict):
        data.setdefault("_input_path", str(path))
        return data
    raise ValueError(f"Unsupported JSON root in {path}")


def extract_findings(doc: dict[str, Any]) -> list[dict[str, Any]]:
    findings = doc.get("findings")
    if isinstance(findings, list):
        return [f for f in findings if isinstance(f, dict)]
    return []


def detect_source_skill(doc: dict[str, Any]) -> str:
    for key in ("source_skill", "scanner", "skill", "tool", "name"):
        val = doc.get(key)
        if isinstance(val, str):
            name = val.lower().replace("_", "-")
            if "hacker" in name or "security-suite" in name:
                return "hacker"
            if "infra" in name:
                return "infra-security"
            if "crypto" in name:
                return "crypto-secrets"
            if "skill-security" in name:
                return "skill-security"
            return name
    path = doc.get("_input_path", "")
    for known in (
        "infra-security",
        "crypto-secrets",
        "skill-security",
        "authz-security",
        "ci-cd-security",
        "supply-chain-security",
        "vulnerability-triage",
        "hacker",
        "security-suite",
    ):
        if known in path:
            return "hacker" if known == "security-suite" else known
    if doc.get("deployment_risk") is not None or any(
        isinstance(f, dict) and "control_id" in f for f in doc.get("findings", []) or []
    ):
        return "infra-security"
    return "unknown"


def normalize_finding(raw: dict[str, Any], source_hint: str) -> dict[str, Any]:
    rule_id = str(raw.get("rule_id") or raw.get("control_id") or raw.get("id") or "unknown")
    sources = raw.get("source_skills") or raw.get("source_skill") or source_hint
    if isinstance(sources, list):
        source_skill = sources[0] if sources else source_hint
    else:
        source_skill = str(sources)

    category = infer_category(rule_id, str(source_skill))
    confidence = normalize_confidence(raw.get("confidence"))

    return {
        "finding_id": str(raw.get("finding_id") or raw.get("id") or uuid.uuid4()),
        "source_skill": str(source_skill),
        "category": str(raw.get("category") or category),
        "file": str(raw.get("file") or raw.get("path") or "unknown"),
        "line": to_int(raw.get("line") or raw.get("line_number")),
        "snippet": redact(str(raw.get("snippet") or raw.get("evidence") or "")),
        "severity": normalize_severity(raw.get("severity")),
        "description": str(raw.get("description") or raw.get("title") or rule_id),
        "confidence": confidence,
        "rule_id": rule_id,
    }


def infer_category(rule_id: str, source: str) -> str:
    joined = f"{rule_id} {source}".lower()
    if "authz" in joined or "bola" in joined:
        return "authz"
    if "crypto" in joined or "jwt" in joined or "secret" in joined:
        return "crypto"
    if "network" in joined or "iam" in joined or "storage" in joined or "container" in joined:
        return "infra"
    if "cicd" in joined or "ci-cd" in joined or "workflow" in joined:
        return "ci-cd"
    if "supply" in joined:
        return "supply-chain"
    return "other"


def normalize_severity(value: Any) -> str:
    text = str(value or "Informational").upper()
    mapping = {"CRITICAL": "P0", "CRIT": "P0", "HIGH": "P1", "MEDIUM": "P2", "LOW": "P3", "INFO": "Informational"}
    if text in SEVERITY_ORDER:
        return text if text != "INFO" else "Informational"
    return mapping.get(text, "Informational")


def normalize_confidence(value: Any) -> str:
    if isinstance(value, str):
        upper = value.strip().capitalize()
        if upper in {"High", "Medium", "Low"}:
            return upper
    if isinstance(value, (int, float)):
        if value >= 0.8:
            return "High"
        if value >= 0.5:
            return "Medium"
        return "Low"
    return "Medium"


def to_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def redact(text: str) -> str:
    import re

    text = re.sub(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[^'\"\s]{8,}", r"\1=[REDACTED]", text)
    return text[:500]


if __name__ == "__main__":
    sys.exit(main())
