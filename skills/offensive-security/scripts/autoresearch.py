#!/usr/bin/env python3
"""
Autoresearch loop: ingest → hypothesize → validate → evolve → chain → repeat → report.

Usage:
    python3 autoresearch.py <deduped-findings.json> [--scope scope.yaml] [--max-rounds 5]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import hypothesis_generator as hypogen  # noqa: E402
import ingest_findings as ingest  # noqa: E402
import reporter  # noqa: E402
import validator  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offensive-security autoresearch loop")
    parser.add_argument("findings", help="Deduped findings JSON from hacker deduplicator")
    parser.add_argument("--scope", help="scope.yaml for sandbox validation")
    parser.add_argument("--max-rounds", type=int, default=5, help="Max autoresearch iterations")
    parser.add_argument("--output-dir", default=".", help="Directory for intermediate JSON and report")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--target", default="repository", help="Report target label")
    parser.add_argument(
        "--stop-on-no-confirmed",
        action="store_true",
        help="Stop after a round with zero new confirmed outcomes",
    )
    args = parser.parse_args(argv)

    out_dir = Path(args.output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_docs = ingest.load_documents(Path(args.findings).expanduser().resolve())
    findings = [ingest.normalize_finding(raw, ingest.detect_source_skill(doc)) for doc in raw_docs for raw in ingest.extract_findings(doc)]

    scope = validator.load_scope(args.scope) if args.scope else None
    dry_run = args.dry_run or scope is None
    docker_available = validator.check_docker()

    all_outcomes: list[dict[str, Any]] = []
    tested_keys: set[tuple[str, str]] = set()
    pending_hypotheses = hypogen.generate_hypotheses_from_findings(findings)
    for h in pending_hypotheses:
        tested_keys.add(hypogen.hypothesis_key(h))

    round_num = 0
    while pending_hypotheses and round_num < args.max_rounds:
        round_num += 1
        request_log: dict[str, list[float]] = {}
        round_outcomes = []
        for hypothesis in pending_hypotheses:
            round_outcomes.append(
                validator.validate_one(hypothesis, scope, dry_run, docker_available, request_log)
            )

        prior_confirmed_ids = {o["hypothesis_id"] for o in all_outcomes if o.get("outcome") == "confirmed"}
        new_confirmed = [
            o for o in round_outcomes if o.get("outcome") == "confirmed" and o["hypothesis_id"] not in prior_confirmed_ids
        ]
        all_outcomes.extend(round_outcomes)

        round_path = out_dir / f"round-{round_num}-outcomes.json"
        round_path.write_text(
            json.dumps({"round": round_num, "outcomes": round_outcomes}, indent=2) + "\n",
            encoding="utf-8",
        )

        if args.stop_on_no_confirmed and not new_confirmed:
            break

        confirmed_all = [o for o in all_outcomes if o.get("outcome") == "confirmed"]
        pending_hypotheses = hypogen.generate_followup_hypotheses(confirmed_all, findings, tested_keys)
        for h in pending_hypotheses:
            tested_keys.add(hypogen.hypothesis_key(h))

        if not pending_hypotheses:
            break

    final_payload = {
        "tool": "offensive-security-autoresearch",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rounds_completed": round_num,
        "dry_run": dry_run,
        "docker_available": docker_available,
        "scope_file": args.scope,
        "outcomes": all_outcomes,
        "sandboxes_torn_down": sum(1 for o in all_outcomes if o.get("sandbox_used")),
    }
    outcomes_path = out_dir / "autoresearch-outcomes.json"
    outcomes_path.write_text(json.dumps(final_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_path = out_dir / f"offensive-security-report-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.md"
    context = reporter.build_context(all_outcomes, final_payload, args.target)
    from jinja2 import Template

    template = Template((SCRIPT_DIR.parent / "references" / "confirmed-report-template.md").read_text(encoding="utf-8"))
    report_path.write_text(template.render(**context) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "rounds": round_num,
                "outcomes": str(outcomes_path),
                "report": str(report_path),
                "confirmed": sum(1 for o in all_outcomes if o.get("outcome") == "confirmed"),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
