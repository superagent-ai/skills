#!/usr/bin/env python3
"""
hacker discovery helper.

Classifies a target tree from file and directory signals, then emits a
deterministic dispatch plan for the meta-skill. Pure standard library: no YAML
parser, no network, no target-code execution.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
DEFAULT_MATRIX = SKILL_DIR / "references" / "coverage-matrix.yaml"

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

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".swift": "swift",
    ".m": "objective-c",
    ".mm": "objective-c",
    ".tf": "terraform",
    ".hcl": "hcl",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
}

FRAMEWORK_SIGNALS = {
    "fastapi": ["fastapi", "from fastapi", "FastAPI("],
    "django": ["django", "manage.py"],
    "flask": ["flask", "Flask("],
    "express": ["express", "app.get(", "app.post("],
    "nextjs": ["next.config.js", "next.config.ts"],
    "react": ["react", "src/App.tsx", "src/App.jsx"],
    "vue": ["vue", "nuxt.config.js", "nuxt.config.ts"],
    "angular": ["angular.json"],
    "spring": ["pom.xml", "build.gradle", "@SpringBootApplication"],
    "rails": ["Gemfile", "config/routes.rb"],
    "terraform": [".tf", ".tfvars"],
    "kubernetes": ["apiVersion:", "kind:"],
    "docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
}

CONTENT_HINT_PATTERNS = {
    "fastapi": ("from fastapi", "import fastapi", "fastapi("),
    "flask": ("from flask", "import flask", "flask("),
    "express": ("require('express')", 'require("express")', "from 'express'", 'from "express"', "express()"),
    "cli:argparse": ("import argparse", "from argparse"),
    "cli:click": ("import click", "from click"),
    "cli:commander": ("require('commander')", 'require("commander")', "from 'commander'", 'from "commander"'),
    "cli:cobra": ("github.com/spf13/cobra", "cobra.command"),
    "cli:clap": ("use clap", "clap::"),
    "kubernetes": ("apiversion:", "kind:"),
    "spring": ("@springbootapplication",),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Discover hacker audit surface")
    parser.add_argument("target", help="Directory or file to classify")
    parser.add_argument("--matrix", default=str(DEFAULT_MATRIX), help="Coverage matrix path")
    parser.add_argument("--domain", help="Authorized live domain or IP scope")
    parser.add_argument("--advisory", help="Path/id for supplied advisory, CVE/GHSA, or report")
    parser.add_argument(
        "--offensive",
        action="store_true",
        help="Include offensive-security in plan (requires scope.yaml at validation time)",
    )
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", help="Write result to this file instead of stdout")
    args = parser.parse_args(argv)

    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"Target not found: {target}", file=sys.stderr)
        return 2

    matrix_path = Path(args.matrix).expanduser().resolve()
    matrix = load_matrix(matrix_path)
    root = target if target.is_dir() else target.parent
    inventory = build_inventory(target, root)
    plan = build_dispatch_plan(target, root, inventory, matrix, args.domain, args.advisory, args.offensive)

    rendered = json.dumps(plan, indent=2, sort_keys=True) if args.format == "json" else render_markdown(plan)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


def load_matrix(path: Path) -> dict:
    """Load JSON-compatible YAML from the coverage matrix."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{path} must remain JSON-compatible YAML for stdlib parsing: {exc}"
        ) from exc


def build_inventory(target: Path, root: Path) -> dict:
    files: list[str] = []
    dirs: set[str] = set()
    content_hints: set[str] = set()
    skipped = {"directories": 0, "oversized": 0, "read_errors": 0}

    paths = [target] if target.is_file() else iter_files(target)
    for path in paths:
        rel = relpath(path, root)
        files.append(rel)
        for parent in Path(rel).parents:
            parent_s = "." if str(parent) == "." else normalize_path(str(parent)) + "/"
            dirs.add(parent_s)
        if path.stat().st_size > 512_000:
            skipped["oversized"] += 1
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:64_000]
        except OSError:
            skipped["read_errors"] += 1
            continue
        lower = text.lower()
        for hint, patterns in CONTENT_HINT_PATTERNS.items():
            if any(pattern in lower for pattern in patterns):
                content_hints.add(hint)

    language_counts: dict[str, int] = {}
    for rel in files:
        suffix = Path(rel).suffix
        language = LANGUAGE_BY_SUFFIX.get(suffix)
        if language:
            language_counts[language] = language_counts.get(language, 0) + 1

    frameworks = detect_frameworks(files, content_hints)
    return {
        "files": sorted(files),
        "dirs": sorted(dirs),
        "content_hints": sorted(content_hints),
        "file_count": len(files),
        "dir_count": len(dirs),
        "languages": sorted(language_counts, key=lambda k: (-language_counts[k], k)),
        "language_counts": language_counts,
        "frameworks": frameworks,
        "skipped": skipped,
    }


def iter_files(root: Path):
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def detect_frameworks(files: list[str], content_hints: set[str]) -> list[str]:
    frameworks: list[str] = []
    lower_files = {f.lower() for f in files}
    basenames = {Path(f).name.lower() for f in files}
    for framework, signals in FRAMEWORK_SIGNALS.items():
        for signal in signals:
            s = signal.lower()
            if s in content_hints or s in basenames or any(fnmatch.fnmatch(f, f"*{s}*") for f in lower_files):
                frameworks.append(framework)
                break
    return sorted(set(frameworks))


def build_dispatch_plan(
    target: Path,
    root: Path,
    inventory: dict,
    matrix: dict,
    domain: str | None,
    advisory: str | None,
    offensive: bool = False,
) -> dict:
    repo_scores: list[dict] = []
    for repo_type, config in matrix.get("repo_types", {}).items():
        matched = [s for s in config.get("signals", []) if signal_matches(s, inventory, domain, advisory)]
        confidence = 0.0 if not config.get("signals") else round(len(matched) / len(config["signals"]), 3)
        repo_scores.append(
            {
                "repo_type": repo_type,
                "description": config.get("description", ""),
                "matched_signals": matched,
                "matched_count": len(matched),
                "confidence": confidence,
            }
        )

    repo_scores.sort(key=lambda s: (-s["matched_count"], -s["confidence"], s["repo_type"]))
    best = repo_scores[0] if repo_scores and repo_scores[0]["matched_count"] else {
        "repo_type": "unknown",
        "description": "No strong repo-type signal matched.",
        "matched_signals": [],
        "matched_count": 0,
        "confidence": 0.0,
    }

    repo_config = matrix.get("repo_types", {}).get(best["repo_type"], {})
    selected = list(repo_config.get("skills") or matrix.get("default_skills", []))
    skipped_optional: dict[str, str] = {}

    for skill, triggers in matrix.get("skill_triggers", {}).items():
        if skill in repo_config.get("excluded_skills", []):
            skipped_optional[skill] = "excluded for repo type"
            continue
        if skill == "recon-security":
            if domain:
                selected.append(skill)
            else:
                skipped_optional[skill] = "requires explicit live domain/IP scope and authorization"
            continue
        if skill == "vulnerability-triage":
            if advisory:
                selected.append(skill)
            else:
                skipped_optional[skill] = "requires supplied advisory/report input"
            continue
        if skill == "offensive-security":
            continue
        if any(signal_matches(t, inventory, domain, advisory) for t in triggers):
            selected.append(skill)

    excluded = set(repo_config.get("excluded_skills", []))
    selected = [skill for skill in unique(selected) if skill not in excluded]

    post_audit_skills: list[str] = []
    offensive_condition = matrix.get("optional_skill_conditions", {}).get(
        "offensive-security",
        "requires explicit user request and sandbox scope.yaml",
    )
    if offensive and "offensive-security" not in excluded:
        post_audit_skills.append("offensive-security")
    else:
        skipped_optional["offensive-security"] = (
            f"{offensive_condition} Runs last (Phase 6), after all defensive skills and deduplicated findings."
        )
    detected_surfaces = {
        surface: [signal for signal in signals if signal_matches(signal, inventory, domain, advisory)]
        for surface, signals in matrix.get("surfaces", {}).items()
    }
    detected_surfaces = {k: v for k, v in detected_surfaces.items() if v}

    return {
        "tool": "hacker-discover",
        "version": matrix.get("version", 1),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "root": str(root),
        "repo_type": best["repo_type"],
        "repo_description": best["description"],
        "confidence": best["confidence"],
        "matched_signals": best["matched_signals"],
        "detected_surfaces": detected_surfaces,
        "detected_languages": inventory["languages"],
        "detected_frameworks": inventory["frameworks"],
        "skills_to_run": selected,
        "post_audit_skills": post_audit_skills,
        "workflow_order": selected + post_audit_skills,
        "skipped_optional_skills": skipped_optional,
        "repo_type_scores": repo_scores,
        "inventory": {
            "file_count": inventory["file_count"],
            "dir_count": inventory["dir_count"],
            "language_counts": inventory["language_counts"],
            "skipped": inventory["skipped"],
        },
        "inputs": {
            "domain": domain,
            "advisory": advisory,
            "offensive": offensive,
        },
    }


def signal_matches(signal: str, inventory: dict, domain: str | None, advisory: str | None) -> bool:
    if signal == "__domain_required__":
        return bool(domain)
    if signal == "__advisory_required__":
        return bool(advisory)
    if signal.startswith("content:"):
        return signal.split(":", 1)[1].lower() in set(inventory["content_hints"])

    normalized = normalize_path(signal)
    files = inventory["files"]
    dirs = inventory["dirs"]
    hints = set(inventory["content_hints"])

    if normalized.endswith("/"):
        prefix = normalized
        return any(d == prefix or d.startswith(prefix) for d in dirs) or any(f.startswith(prefix) for f in files)

    if any(ch in normalized for ch in "*?[]"):
        return any(fnmatch.fnmatch(f, normalized) or fnmatch.fnmatch(Path(f).name, normalized) for f in files)

    lower = normalized.lower()
    if lower in hints:
        return True
    return any(f == normalized or f.endswith("/" + normalized) or Path(f).name == normalized for f in files)


def unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def relpath(path: Path, root: Path) -> str:
    try:
        return normalize_path(str(path.relative_to(root)))
    except ValueError:
        return normalize_path(str(path))


def normalize_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./")


def render_markdown(plan: dict) -> str:
    lines = [
        f"# Hacker Discovery: {plan['repo_type']}",
        "",
        f"- Target: `{plan['target']}`",
        f"- Confidence: {plan['confidence']}",
        f"- Skills to run (Phases 2–5): {', '.join(plan['skills_to_run']) or 'none'}",
        f"- Post-audit / last (Phase 6): {', '.join(plan.get('post_audit_skills', [])) or 'none'}",
        f"- Languages: {', '.join(plan['detected_languages']) or 'none detected'}",
        f"- Frameworks: {', '.join(plan['detected_frameworks']) or 'none detected'}",
        "",
        "## Matched Signals",
    ]
    lines.extend(f"- `{signal}`" for signal in plan["matched_signals"] or ["none"])
    if plan["skipped_optional_skills"]:
        lines.append("")
        lines.append("## Skipped Optional Skills")
        for skill, reason in plan["skipped_optional_skills"].items():
            lines.append(f"- `{skill}`: {reason}")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
