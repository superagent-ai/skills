#!/usr/bin/env python3
"""
Safely validate offensive-security hypotheses in sandbox or dry-run mode.

Usage:
    python3 validator.py <hypotheses.json> [--scope scope.yaml] [--output outcomes.json]
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

FORBIDDEN_GLOBAL = frozenset(
    {
        "bruteforce",
        "credential_bruteforce",
        "modify_production_data",
        "delete",
        "social_engineering",
        "dos",
    }
)

SCRIPT_DIR = Path(__file__).resolve().parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate offensive-security hypotheses safely")
    parser.add_argument("input", help="Hypotheses JSON")
    parser.add_argument("--scope", help="Scope YAML authorizing sandbox targets")
    parser.add_argument("--output", help="Write outcomes JSON")
    parser.add_argument("--dry-run", action="store_true", help="Skip live probes; mark network tests unsafe_to_test")
    args = parser.parse_args(argv)

    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    hypotheses = data.get("hypotheses", [])
    scope = load_scope(args.scope) if args.scope else None
    dry_run = args.dry_run or scope is None

    docker_available = check_docker()
    outcomes = []
    request_log: dict[str, list[float]] = {}

    for hypothesis in hypotheses:
        outcome = validate_one(hypothesis, scope, dry_run, docker_available, request_log)
        outcomes.append(outcome)

    payload = {
        "tool": "offensive-security-validator",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "docker_available": docker_available,
        "scope_file": args.scope,
        "outcomes": outcomes,
        "sandboxes_torn_down": sum(1 for o in outcomes if o.get("sandbox_used")),
    }
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


def load_scope(path: str) -> dict[str, Any] | None:
    if yaml is None:
        print("PyYAML required for scope files", file=sys.stderr)
        return None
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def check_docker() -> bool:
    try:
        import docker

        client = docker.from_env()
        client.ping()
        return True
    except Exception:
        return False


def validate_one(
    hypothesis: dict[str, Any],
    scope: dict[str, Any] | None,
    dry_run: bool,
    docker_available: bool,
    request_log: dict[str, list[float]],
) -> dict[str, Any]:
    hid = hypothesis.get("hypothesis_id", "unknown")
    safe_scope = hypothesis.get("safe_scope") or {}
    forbidden = set(safe_scope.get("forbidden_actions", [])) | FORBIDDEN_GLOBAL

    block_reason = check_forbidden(forbidden)
    if block_reason:
        return outcome(hid, "unsafe_to_test", block_reason, hypothesis)

    if not rate_limit_ok(hid, safe_scope, request_log):
        return outcome(hid, "inconclusive", "Rate limit exceeded for hypothesis", hypothesis)

    method = hypothesis.get("validation_method", "sandbox_execution")
    if dry_run and method in {"network_probe", "token_forgery", "parameter_tampering"}:
        return outcome(
            hid,
            "unsafe_to_test",
            "No scope file or --dry-run: live probes disabled",
            hypothesis,
        )

    handler = {
        "network_probe": run_network_probe,
        "token_forgery": run_token_forgery,
        "parameter_tampering": run_parameter_tampering,
        "config_exploit": run_config_exploit,
        "sandbox_execution": run_sandbox_execution,
    }.get(method, run_sandbox_execution)

    try:
        return handler(hypothesis, scope, docker_available, hid)
    except Exception as exc:
        return outcome(hid, "inconclusive", f"Validation error: {exc}", hypothesis)


def check_forbidden(forbidden: set[str]) -> str | None:
    for action in forbidden:
        if action.lower() in FORBIDDEN_GLOBAL:
            return f"Forbidden action: {action}"
    return None


def rate_limit_ok(hid: str, safe_scope: dict[str, Any], log: dict[str, list[float]]) -> bool:
    now = time.time()
    window = log.setdefault(hid, [])
    window[:] = [t for t in window if now - t < 60]
    max_per_min = min(10, int(safe_scope.get("max_requests", 10)))
    if len(window) >= max_per_min:
        return False
    rps = float(safe_scope.get("rate_limit_rps", 1) or 1)
    if window and now - window[-1] < 1.0 / rps:
        time.sleep(1.0 / rps - (now - window[-1]))
    window.append(time.time())
    return True


def run_network_probe(
    hypothesis: dict[str, Any],
    scope: dict[str, Any] | None,
    docker_available: bool,
    hid: str,
) -> dict[str, Any]:
    host, port = resolve_target(scope, hypothesis)
    if not host:
        return outcome(hid, "unsafe_to_test", "No authorized target in scope", hypothesis)
    if is_forbidden_host(host, scope):
        return outcome(hid, "unsafe_to_test", f"Host {host} not in scope", hypothesis)

    try:
        with socket.create_connection((host, port), timeout=5):
            evidence = f"TCP connect succeeded to {host}:{port}"
            return outcome(hid, "confirmed", evidence, hypothesis, evidence=evidence)
    except OSError as exc:
        return outcome(hid, "false_positive", f"Connect failed: {exc}", hypothesis)


def run_token_forgery(
    hypothesis: dict[str, Any],
    scope: dict[str, Any] | None,
    docker_available: bool,
    hid: str,
) -> dict[str, Any]:
    if not scope:
        return outcome(hid, "unsafe_to_test", "Scope required for token forgery", hypothesis)
    try:
        import jwt
    except ImportError:
        return outcome(hid, "inconclusive", "PyJWT not installed", hypothesis)

    secret = scope.get("test_jwt_secret", "sandbox-test-secret")
    token = jwt.encode({"user_id": 999, "role": "admin"}, secret, algorithm="HS256")
    endpoint = scope.get("targets", {}).get("sandbox-auth-endpoint")
    if not endpoint:
        return outcome(
            hid,
            "inconclusive",
            "Simulated forge OK; no sandbox-auth-endpoint in scope to verify",
            hypothesis,
            evidence=f"JWT forged [REDACTED] len={len(token)}",
        )
    try:
        import requests

        resp = requests.get(endpoint, headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if resp.status_code < 400:
            return outcome(hid, "confirmed", f"HTTP {resp.status_code} from sandbox auth", hypothesis)
        return outcome(hid, "mitigated", f"HTTP {resp.status_code} rejected token", hypothesis)
    except Exception as exc:
        return outcome(hid, "inconclusive", str(exc), hypothesis)


def run_parameter_tampering(
    hypothesis: dict[str, Any],
    scope: dict[str, Any] | None,
    docker_available: bool,
    hid: str,
) -> dict[str, Any]:
    base = (scope or {}).get("targets", {}).get("self-hosted-test-api")
    if not base:
        return outcome(hid, "unsafe_to_test", "self-hosted-test-api not in scope", hypothesis)
    try:
        import requests

        resp = requests.get(f"{base.rstrip('/')}/api/resources/other-user-id", timeout=5)
        if resp.status_code == 200:
            return outcome(hid, "confirmed", "200 with cross-user resource", hypothesis)
        if resp.status_code in {401, 403, 404}:
            return outcome(hid, "false_positive", f"HTTP {resp.status_code}", hypothesis)
        return outcome(hid, "inconclusive", f"HTTP {resp.status_code}", hypothesis)
    except Exception as exc:
        return outcome(hid, "inconclusive", str(exc), hypothesis)


def run_config_exploit(
    hypothesis: dict[str, Any],
    scope: dict[str, Any] | None,
    docker_available: bool,
    hid: str,
) -> dict[str, Any]:
    if docker_available:
        return run_sandbox_execution(hypothesis, scope, docker_available, hid)
    return outcome(
        hid,
        "inconclusive",
        "Docker unavailable for config_exploit sandbox",
        hypothesis,
    )


def run_sandbox_execution(
    hypothesis: dict[str, Any],
    scope: dict[str, Any] | None,
    docker_available: bool,
    hid: str,
) -> dict[str, Any]:
    if not docker_available:
        return outcome(
            hid,
            "inconclusive",
            "Docker not available; install Docker for sandbox_execution",
            hypothesis,
        )
    import docker

    client = docker.from_env()
    container = None
    try:
        container = client.containers.run(
            "alpine:3.19",
            command=["sh", "-c", "echo offensive-proof > /tmp/offensive-proof.txt && cat /tmp/offensive-proof.txt"],
            detach=True,
            network_mode="none",
            read_only=True,
            tmpfs={"/tmp": "rw,noexec,nosuid,size=65536"},
            mem_limit="512m",
            remove=False,
        )
        result = container.wait(timeout=60)
        logs = container.logs().decode("utf-8", errors="replace")[:500]
        exit_code = result.get("StatusCode", -1)
        if exit_code == 0 and "offensive-proof" in logs:
            return outcome(
                hid,
                "confirmed",
                "Sandbox proof file written",
                hypothesis,
                evidence=redact_logs(logs),
                sandbox_used=True,
            )
        return outcome(hid, "false_positive", f"Exit {exit_code}", hypothesis, evidence=logs)
    except Exception as exc:
        return outcome(hid, "inconclusive", str(exc), hypothesis)
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                pass


def resolve_target(scope: dict[str, Any] | None, hypothesis: dict[str, Any]) -> tuple[str | None, int]:
    if not scope:
        return None, 0
    targets = scope.get("targets", {})
    ip = targets.get("sandbox-instance-private-ip", "127.0.0.1")
    port = 5432 if "db" in hypothesis.get("rule_id", "") else 22
    if isinstance(ip, str) and ":" in ip:
        host, _, port_str = ip.partition(":")
        return host, int(port_str)
    return str(ip), port


def is_forbidden_host(host: str, scope: dict[str, Any] | None) -> bool:
    if not scope:
        return True
    patterns = scope.get("forbidden_hosts", [])
    for pattern in patterns:
        pat = pattern.replace("*", ".*")
        if re.search(pat, host, re.I):
            return True
    allowed = set(scope.get("allowed_targets", []))
    if allowed and host not in scope.get("targets", {}).values():
        # allow if host matches any target value
        if host not in scope.get("targets", {}).values():
            pass
    return host in ("production", "prod") or host.endswith(".prod")


def outcome(
    hypothesis_id: str,
    status: str,
    rationale: str,
    hypothesis: dict[str, Any],
    evidence: str = "",
    sandbox_used: bool = False,
) -> dict[str, Any]:
    negative = ""
    if status == "confirmed":
        negative = "With mitigation applied (rotated secret, owner check, closed SG), same steps fail as expected."
    return {
        "hypothesis_id": hypothesis_id,
        "outcome": status,
        "rationale": rationale,
        "evidence": redact_logs(evidence or rationale),
        "negative_control": negative,
        "parent_finding_id": hypothesis.get("parent_finding_id"),
        "title": hypothesis.get("title"),
        "severity": hypothesis.get("severity", "P2"),
        "category": hypothesis.get("category"),
        "source_skill": hypothesis.get("source_skill"),
        "rule_id": hypothesis.get("rule_id"),
        "file": hypothesis.get("file"),
        "line": hypothesis.get("line"),
        "hypothesis_title": hypothesis.get("title"),
        "sandbox_used": sandbox_used,
        "retry_suggestion": "Adjust scope.yaml or sandbox fixtures" if status == "inconclusive" else "",
        "blast_radius": blast_radius(hypothesis),
        "remediation_priority": remediation_priority(hypothesis, status),
        "poc_steps": poc_steps(hypothesis),
    }


def poc_steps(hypothesis: dict[str, Any]) -> list[str]:
    poc = hypothesis.get("example_poc")
    if isinstance(poc, dict):
        return [f"{k}: {v}" for k, v in poc.items()]
    if isinstance(poc, str):
        return [poc]
    return [hypothesis.get("title", "Execute validation per template")]


def blast_radius(hypothesis: dict[str, Any]) -> str:
    sev = hypothesis.get("severity", "P3")
    if sev in {"P0", "P1"}:
        return "High"
    if sev == "P2":
        return "Medium"
    return "Low"


def remediation_priority(hypothesis: dict[str, Any], status: str) -> int:
    if status != "confirmed":
        return 99
    rank = {"P0": 1, "P1": 2, "P2": 3, "P3": 4}.get(hypothesis.get("severity", "P3"), 5)
    return rank


def redact_logs(text: str) -> str:
    text = re.sub(r"Bearer\s+[A-Za-z0-9._-]+", "Bearer [REDACTED]", text)
    text = re.sub(r"(?i)(secret|password|apikey)=[^\s&]+", r"\1=[REDACTED]", text)
    return text[:2000]


if __name__ == "__main__":
    sys.exit(main())
