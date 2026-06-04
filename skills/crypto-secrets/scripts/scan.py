#!/usr/bin/env python3
"""
crypto-secrets scanner -- Stage 1 deterministic engine.

Walks a target tree, skips dependency/build artifacts, and runs offline detectors
for hardcoded secrets, weak crypto, unsafe TLS/JWT settings, weak randomness, and
dangerous serialization. Emits redacted findings with file:line anchors.

Pure standard library -- no pip install, no network, no target-code execution.

Usage:
    python3 scan.py <target-dir-or-file> [--format markdown|json]
        [--severity P0,P1] [--include-secrets] [--include-crypto]
        [--no-secrets] [--no-crypto]

Exit code: 1 if any P0/P1 finding is present after filtering, else 0.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import detect_crypto  # noqa: E402
import detect_secrets  # noqa: E402


VERSION = "1.0.0"
SEVERITY_ORDER = {"P0": 5, "P1": 4, "P2": 3, "P3": 2, "INFO": 1, "Informational": 1}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "site-packages",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".terraform",
    ".terragrunt-cache",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    "target",
    "bin",
    "obj",
}

TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".go",
    ".java",
    ".kt",
    ".kts",
    ".rb",
    ".php",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".hpp",
    ".rs",
    ".swift",
    ".m",
    ".mm",
    ".scala",
    ".cs",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".env",
    ".pem",
    ".key",
    ".crt",
    ".cer",
    ".p12",
    ".jks",
    ".txt",
    ".md",
    ".dockerfile",
}

TEXT_NAMES = {
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "requirements.txt",
    "Gemfile",
    "Procfile",
}

MAX_FILE_BYTES = 2_000_000


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline crypto and secrets scanner")
    parser.add_argument("target", help="Directory or file to scan")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--severity", help="Comma-separated severities to include, e.g. P0,P1")
    parser.add_argument("--include-secrets", action="store_true", help="Include secrets checks (default)")
    parser.add_argument("--include-crypto", action="store_true", help="Include crypto/JWT/TLS checks (default)")
    parser.add_argument("--no-secrets", action="store_true", help="Disable secrets checks")
    parser.add_argument("--no-crypto", action="store_true", help="Disable crypto/JWT/TLS checks")
    args = parser.parse_args(argv)

    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"Target not found: {target}", file=sys.stderr)
        return 2

    include_secrets = not args.no_secrets
    include_crypto = not args.no_crypto
    if args.include_secrets:
        include_secrets = True
    if args.include_crypto:
        include_crypto = True
    if not include_secrets and not include_crypto:
        print("Nothing to scan: both secrets and crypto checks are disabled.", file=sys.stderr)
        return 2

    root = target if target.is_dir() else target.parent
    ignore = GitIgnore(root)
    scanned: list[dict] = []
    skipped: dict[str, int] = {"binary": 0, "oversized": 0, "ignored": 0, "unsupported": 0, "read_error": 0}
    inventory: dict[str, int] = {}
    findings: list[dict] = []

    for file_path in iter_files(target, root, ignore, skipped):
        rel = relpath(file_path, root)
        kind = file_kind(file_path)
        inventory[kind] = inventory.get(kind, 0) + 1
        read = read_text(file_path)
        if read is None:
            skipped["read_error"] += 1
            continue
        text, reason = read
        if reason:
            skipped[reason] += 1
            continue
        scanned.append({"file": rel, "kind": kind})
        if include_crypto:
            findings.extend(detect_crypto.scan_file(file_path, rel, text))
        if include_secrets:
            findings.extend(detect_secrets.scan_file(file_path, rel, text, root))

    findings = sorted(dedupe_findings(findings), key=finding_sort_key)
    findings = [redact_finding(f) for f in findings]
    severities = parse_severities(args.severity)
    if severities:
        findings = [f for f in findings if normalize_severity(f.get("severity")) in severities]

    result = {
        "scanner": "crypto-secrets",
        "version": VERSION,
        "target": str(target),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summarize(findings),
        "inventory": inventory,
        "scanned_files": len(scanned),
        "skipped": skipped,
        "findings": findings,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_markdown(result))

    return 1 if any(normalize_severity(f.get("severity")) in {"P0", "P1"} for f in findings) else 0


class GitIgnore:
    """Small .gitignore matcher for common project patterns.

    It intentionally handles the subset most useful for scanner traversal:
    comments, blank lines, directory patterns, basename globs, and root-relative
    globs. The scanner still skips dependency/build directories even when no
    .gitignore is present.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.patterns: list[str] = []
        ignore_file = root / ".gitignore"
        if ignore_file.exists():
            try:
                for raw in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#") or line.startswith("!"):
                        continue
                    self.patterns.append(line)
            except OSError:
                pass

    def matches(self, path: Path) -> bool:
        rel = relpath(path, self.root)
        name = path.name
        for pattern in self.patterns:
            pat = pattern.rstrip("/")
            if pattern.endswith("/") and not path.is_dir():
                continue
            if pattern.startswith("/"):
                if fnmatch.fnmatch(rel, pat.lstrip("/")):
                    return True
            elif "/" in pat:
                if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, f"{pat}/*"):
                    return True
            else:
                if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, f"*/{pat}"):
                    return True
        return False


def iter_files(target: Path, root: Path, ignore: GitIgnore, skipped: dict[str, int]):
    if target.is_file():
        if should_scan_file(target, root, ignore, skipped):
            yield target
        return

    for current, dirs, files in os.walk(target):
        current_path = Path(current)
        dirs[:] = sorted(
            d for d in dirs
            if d not in SKIP_DIRS and not ignore.matches(current_path / d)
        )
        for name in sorted(files):
            path = current_path / name
            if should_scan_file(path, root, ignore, skipped):
                yield path


def should_scan_file(path: Path, root: Path, ignore: GitIgnore, skipped: dict[str, int]) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        skipped["ignored"] += 1
        return False
    if ignore.matches(path):
        skipped["ignored"] += 1
        return False
    if not is_supported_text_name(path):
        skipped["unsupported"] += 1
        return False
    return True


def is_supported_text_name(path: Path) -> bool:
    if path.name in TEXT_NAMES:
        return True
    if path.name.startswith(".env"):
        return True
    if path.name.startswith("Dockerfile"):
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def read_text(path: Path) -> tuple[str | None, str | None] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > MAX_FILE_BYTES:
        return None, "oversized"
    if b"\x00" in data[:4096]:
        return None, "binary"
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), None


def dedupe_findings(findings: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, str, int]] = set()
    for finding in findings:
        key = (finding.get("rule_id", ""), finding.get("file", ""), int(finding.get("line", 0)))
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def finding_sort_key(finding: dict):
    severity = SEVERITY_ORDER.get(normalize_severity(finding.get("severity")), 0)
    return (-severity, finding.get("file", ""), int(finding.get("line", 0)), finding.get("rule_id", ""))


def summarize(findings: list[dict]) -> dict:
    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "INFO": 0}
    secret_rotation = 0
    for finding in findings:
        sev = normalize_severity(finding.get("severity"))
        counts[sev if sev in counts else "INFO"] += 1
        if finding.get("rotation_required"):
            secret_rotation += 1
    risk = "Low"
    if counts["P0"] or counts["P1"] > 1:
        risk = "High"
    elif counts["P1"] or counts["P2"]:
        risk = "Medium"
    return {"counts": counts, "rotation_required": secret_rotation, "deployment_risk": risk, "total": len(findings)}


def render_markdown(result: dict) -> str:
    summary = result["summary"]
    counts = summary["counts"]
    lines = [
        f"# Crypto Secrets Scan: `{result['target']}`",
        "",
        f"**Scanner:** crypto-secrets {result['version']}",
        f"**Timestamp:** {result['timestamp']}",
        f"**Deployment risk:** {summary['deployment_risk']}",
        f"**Files scanned:** {result['scanned_files']}",
        "",
        "## Summary",
        "",
        f"- Findings: {counts['P0']} P0, {counts['P1']} P1, {counts['P2']} P2, {counts['P3']} P3, {counts['INFO']} Informational",
        f"- Secrets requiring rotation: {summary['rotation_required']}",
        "",
    ]

    if not result["findings"]:
        lines.extend(
            [
                "## Findings",
                "",
                "No findings against the crypto-secrets Stage 1 rule set.",
                "",
                "Static limits: this does not prove runtime secrets, deployed TLS, external vault policy, or secret history are clean.",
            ]
        )
        return "\n".join(lines)

    lines.extend(["## Findings", ""])
    for finding in result["findings"]:
        sev = normalize_severity(finding.get("severity"))
        rule = finding.get("rule_id", "unknown")
        title = finding.get("title", rule)
        location = f"{finding.get('file')}:{finding.get('line')}"
        lines.extend(
            [
                f"### [{sev}] {rule}: {title}",
                "",
                f"**Category:** {finding.get('category', 'Other')}  ",
                f"**Location:** `{location}`  ",
                f"**Confidence:** {finding.get('confidence', 'n/a')}  ",
                f"**Rotation required:** {'Yes' if finding.get('rotation_required') else 'No'}",
                "",
                "Current:",
                "",
                "```text",
                str(finding.get("snippet", "")),
                "```",
                "",
                f"Rationale: {finding.get('rationale', 'Review the surrounding code to confirm impact.')}",
                "",
                f"Fix: {finding.get('remediation') or finding.get('rotation_hint') or 'Replace with a secure, framework-appropriate pattern.'}",
                "",
            ]
        )
        if finding.get("redacted_value"):
            lines.extend([f"Redacted value: `{finding['redacted_value']}`", ""])
    return "\n".join(lines)


def redact_finding(finding: dict) -> dict:
    """Mask obvious secret literals in any snippet, including crypto-rule hits."""
    copied = dict(finding)
    snippet = str(copied.get("snippet", ""))
    if copied.get("redacted_value"):
        return copied
    if (
        copied.get("rotation_required")
        or "secret" in str(copied.get("rule_id", "")).lower()
        or re.search(r"\b(jwt\.(?:encode|sign)|jsonwebtoken\.sign)\s*\(", snippet, re.IGNORECASE)
    ):
        copied["snippet"] = redact_literal_values(snippet)
    return copied


def redact_literal_values(snippet: str) -> str:
    def repl(match: re.Match) -> str:
        quote = match.group(1)
        value = match.group(2)
        if len(value) < 8:
            return match.group(0)
        return f"{quote}{detect_secrets.redact_secret(value)}{quote}"

    return re.sub(r"(['\"])([A-Za-z0-9._~+/=-]{8,})\1", repl, snippet)


def parse_severities(value: str | None) -> set[str]:
    if not value:
        return set()
    return {normalize_severity(part.strip()) for part in value.split(",") if part.strip()}


def normalize_severity(value) -> str:
    sev = str(value or "INFO").strip()
    if sev.upper() in {"INFO", "INFORMATIONAL"}:
        return "INFO"
    return sev.upper()


def relpath(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def file_kind(path: Path) -> str:
    if path.name.startswith(".env"):
        return "env"
    if path.name.startswith("Dockerfile"):
        return "dockerfile"
    suffix = path.suffix.lower()
    return suffix[1:] if suffix else "text"


if __name__ == "__main__":
    raise SystemExit(main())
