#!/usr/bin/env python3
"""
crypto-secrets secret detector.

Finds high-signal credential patterns in text files. It redacts every candidate
before returning it and never validates credentials against live services.
"""

from __future__ import annotations

import math
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


CONTEXT_WORDS = re.compile(
    r"(?i)\b(secret|token|password|passwd|pwd|api[_-]?key|access[_-]?key|"
    r"client[_-]?secret|auth|credential|bearer|private[_-]?key|connection|string)\b"
)

LOW_VALUE_PATH = re.compile(r"(?i)(^|/)(test|tests|spec|fixtures?|examples?|docs?)(/|$)|(\.example|\.sample|\.template)$")
ENV_NAME_RE = re.compile(r"(?i)^\.env(?:\.|$)|(^|/)\.env(?:\.|$)")


@dataclass(frozen=True)
class SecretPattern:
    pattern_id: str
    name: str
    severity: str
    regex: str
    confidence: str
    exclude_patterns: tuple[str, ...]
    rotation_hint: str


PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("secret-aws-access-key", "AWS access key id", "P0", r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}", "High", ("EXAMPLE", "FAKE", "TEST", "PLACEHOLDER"), "Disable and rotate the IAM access key; review CloudTrail for use."),
    SecretPattern("secret-gcp-api-key", "Google API key", "P1", r"AIza[0-9A-Za-z_-]{35}", "High", ("000000", "EXAMPLE", "FAKE", "TEST"), "Rotate the API key and restrict it by API, referrer, IP, or service account."),
    SecretPattern("secret-azure-storage-key", "Azure storage account key", "P0", r"(?i)(?:AccountKey=)[A-Za-z0-9+/=]{40,}", "High", ("example", "placeholder", "changeme"), "Regenerate the affected storage account key and move it to Key Vault."),
    SecretPattern("secret-digitalocean-token", "DigitalOcean access token", "P0", r"dop_v1_[0-9a-f]{64}", "High", ("0000000000000000", "example", "test"), "Revoke the token in DigitalOcean and issue a scoped replacement."),
    SecretPattern("secret-postgres-url", "PostgreSQL URL with credentials", "P0", r"postgres(?:ql)?://[^\s:@/]+:[^\s@/]+@[^\s\"']+", "High", ("user:pass", "username:password", "example.com", "localhost"), "Rotate the database password and remove credentials from source/history."),
    SecretPattern("secret-mysql-url", "MySQL URL with credentials", "P0", r"mysql://[^\s:@/]+:[^\s@/]+@[^\s\"']+", "High", ("user:pass", "username:password", "example.com", "localhost"), "Rotate the database password and move the URL into secret storage."),
    SecretPattern("secret-mongodb-url", "MongoDB URL with credentials", "P0", r"mongodb(?:\+srv)?://[^\s:@/]+:[^\s@/]+@[^\s\"']+", "High", ("user:pass", "username:password", "example", "localhost"), "Rotate the database user password and verify network/IP restrictions."),
    SecretPattern("secret-rsa-private-key", "RSA private key", "P0", r"-----BEGIN RSA PRIVATE KEY-----", "High", ("test", "fixture", "example"), "Replace the private key, revoke dependent certificates/tokens, and remove history."),
    SecretPattern("secret-openssh-private-key", "OpenSSH private key", "P0", r"-----BEGIN OPENSSH PRIVATE KEY-----", "High", ("test", "fixture", "example"), "Remove the key from authorized use, generate a new keypair, and audit access."),
    SecretPattern("secret-ec-private-key", "EC private key", "P0", r"-----BEGIN EC PRIVATE KEY-----", "High", ("test", "fixture", "example"), "Replace the keypair and revoke certificates or tokens signed with it if needed."),
    SecretPattern("secret-bearer-token", "Bearer token", "P1", r"(?i)Authorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]{20,}", "Medium", ("example", "dummy", "placeholder", "synthetic"), "Revoke the token or invalidate the session/provider credential."),
    SecretPattern("secret-oauth-client-secret", "OAuth client secret", "P1", r"(?i)(?:client_secret|oauth_secret)[\"'\s:=]+[\"']?[A-Za-z0-9._~+/=-]{16,}", "Medium", ("example", "dummy", "placeholder", "changeme", "synthetic"), "Rotate the OAuth client secret with the identity provider."),
    SecretPattern("secret-slack-webhook", "Slack webhook URL", "P1", r"https://hooks\.slack\.com/services/[A-Z0-9]{8,}/[A-Z0-9]{8,}/[A-Za-z0-9]{20,}", "High", ("XXXXXXXX", "example", "test"), "Revoke the Slack webhook and create a replacement with least privilege."),
    SecretPattern("secret-generic-webhook", "Webhook URL with embedded secret", "P1", r"https://[^\s\"']*(?:webhook|hooks)[^\s\"']*(?:token|secret|key)[^\s\"']{12,}", "Medium", ("example.test", "localhost", "synthetic", "placeholder"), "Rotate the webhook token and scope inbound permissions."),
    SecretPattern("secret-generic-password", "Generic password assignment", "P1", r"(?i)\b(?:password|passwd|pwd)\b[\"'\s:=]+[\"'][^\"'\s]{8,}[\"']", "Medium", ("password", "example", "changeme", "placeholder", "dummy", "synthetic"), "Rotate the password and replace source literals with secret loading."),
    SecretPattern("secret-generic-secret", "Generic secret assignment", "P1", r"(?i)\b(?:secret|api_key|apikey|access_token|auth_token)\b[\"'\s:=]+[\"'][A-Za-z0-9._~+/=-]{16,}[\"']", "Medium", ("example", "changeme", "placeholder", "dummy", "synthetic"), "Rotate the value if real and move it to environment or a secret manager."),
    SecretPattern("secret-jwt-hmac-secret", "JWT HMAC signing secret", "P0", r"(?i)\b(?:jwt_secret|jwtSecret|JWT_SECRET)\b[\"'\s:=]+[\"'][A-Za-z0-9._~+/=-]{12,}[\"']", "High", ("example", "changeme", "placeholder", "dummy", "synthetic"), "Rotate the JWT signing secret and invalidate tokens signed with the exposed key."),
    SecretPattern("secret-github-token", "GitHub token", "P0", r"gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,}_[A-Za-z0-9_]{59,}", "High", ("000000000000", "example", "test"), "Revoke the token in GitHub, inspect audit logs, and issue a least-privilege token."),
    SecretPattern("secret-gitlab-token", "GitLab token", "P0", r"glpat-[A-Za-z0-9_-]{20,}", "High", ("000000", "example", "test"), "Revoke the token in GitLab and review recent token activity."),
    SecretPattern("secret-slack-token", "Slack token", "P0", r"xox[baprs]-[A-Za-z0-9-]{20,}", "High", ("000000", "XXXXXXXX", "example", "test"), "Revoke the Slack token and review app scopes and audit logs."),
    SecretPattern("secret-stripe-key", "Stripe secret key", "P0", r"sk_(?:live|test)_[A-Za-z0-9]{16,}", "High", ("000000", "example", "test_fixture"), "Roll the Stripe key and inspect API logs for unauthorized use."),
    SecretPattern("secret-sendgrid-key", "SendGrid API key", "P0", r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}", "High", ("000000", "XXXXXXXX", "example", "test"), "Revoke the SendGrid key and create a scoped replacement."),
    SecretPattern("secret-twilio-token", "Twilio auth token", "P0", r"(?i)(?:twilio_auth_token|TWILIO_AUTH_TOKEN)[\"'\s:=]+[\"']?[A-Fa-f0-9]{32}[\"']?", "High", ("000000", "example", "test"), "Rotate the Twilio auth token and review account usage."),
    SecretPattern("secret-env-file", "Sensitive value in env file", "P1", r"(?i)^\s*[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY)[A-Z0-9_]*\s*=\s*[^#\s]{8,}", "Medium", ("example", "sample", "template", "dummy", "placeholder", "changeme"), "Move values to runtime secret injection; rotate anything real."),
)


def scan_file(path: Path, rel: str, text: str, root: Path | None = None) -> list[dict]:
    """Return redacted secret findings for a decoded text file."""
    findings: list[dict] = []
    tracked = _git_tracked(path, root) if root else None
    lines = text.splitlines()

    for pattern in PATTERNS:
        if pattern.pattern_id == "secret-env-file" and not _is_env_like(path, rel):
            continue
        compiled = re.compile(pattern.regex, re.MULTILINE)
        for match in compiled.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
            matched = match.group(0)
            context = _context(lines, line_no)
            if _excluded(pattern, matched, context, rel):
                continue
            candidate = _candidate_value(matched)
            entropy = shannon_entropy(candidate)
            confidence = _confidence(pattern, entropy, context, rel)
            severity = _severity(pattern, confidence, rel)
            redacted = redact_secret(candidate)
            findings.append(
                {
                    "rule_id": pattern.pattern_id,
                    "pattern_id": pattern.pattern_id,
                    "severity": severity,
                    "category": "SecretExposure",
                    "title": pattern.name,
                    "file": rel,
                    "line": line_no,
                    "snippet": _redact_in_line(line.strip()[:260], candidate, redacted),
                    "redacted_value": redacted,
                    "confidence": confidence,
                    "entropy": round(entropy, 2),
                    "rotation_required": severity in {"P0", "P1"},
                    "rotation_hint": pattern.rotation_hint,
                    "remediation": _remediation(pattern),
                    "rationale": _rationale(pattern, tracked),
                    "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
                    "kind": "secret",
                    "git_tracked": tracked,
                }
            )
    return _dedupe(findings)


def redact_secret(value: str) -> str:
    value = value.strip().strip("\"'")
    if len(value) <= 8:
        return "****"
    prefix = value[:4]
    suffix = value[-3:]
    return f"{prefix}****{suffix}"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _candidate_value(match: str) -> str:
    if "-----BEGIN " in match:
        return match
    if "://" in match:
        return match
    if "Bearer " in match:
        return match.split("Bearer ", 1)[1]
    if "AccountKey=" in match:
        return match.split("AccountKey=", 1)[1]
    if "=" in match:
        return match.rsplit("=", 1)[1].strip().strip("\"'")
    if ":" in match and not match.startswith("http"):
        return match.rsplit(":", 1)[1].strip().strip("\"'")
    return match.strip().strip("\"'")


def _context(lines: list[str], line_no: int, radius: int = 2) -> str:
    start = max(0, line_no - radius - 1)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def _excluded(pattern: SecretPattern, matched: str, context: str, rel: str) -> bool:
    haystack = f"{matched}\n{context}\n{rel}"
    for excluded in pattern.exclude_patterns:
        if re.search(excluded, haystack, re.IGNORECASE):
            return True
    if LOW_VALUE_PATH.search(rel) and pattern.severity != "P0":
        return True
    return False


def _confidence(pattern: SecretPattern, entropy: float, context: str, rel: str) -> str:
    score = {"Low": 1, "Medium": 2, "High": 3}[pattern.confidence]
    if entropy >= 4.5:
        score += 1
    if CONTEXT_WORDS.search(context):
        score += 1
    if _is_env_like(Path(rel), rel) or re.search(r"(?i)(^|/)(config|secrets?|credentials?)(/|$)", rel):
        score += 1
    if LOW_VALUE_PATH.search(rel):
        score -= 1
    if score >= 4:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"


def _severity(pattern: SecretPattern, confidence: str, rel: str) -> str:
    if confidence == "Low":
        return "P3" if pattern.severity in {"P0", "P1"} else pattern.severity
    if LOW_VALUE_PATH.search(rel) and pattern.severity != "P0":
        return "P3"
    return pattern.severity


def _is_env_like(path: Path, rel: str) -> bool:
    name = path.name
    return bool(ENV_NAME_RE.search(name) or ENV_NAME_RE.search(rel))


def _redact_in_line(line: str, candidate: str, redacted: str) -> str:
    if candidate and candidate in line:
        return line.replace(candidate, redacted)
    return line


def _remediation(pattern: SecretPattern) -> str:
    if pattern.pattern_id.endswith("private-key"):
        return "Remove the private key from source, replace the keypair, and store private material in a secret manager or protected keystore."
    if "url" in pattern.pattern_id:
        return "Move the connection string to runtime secret injection and rotate the embedded password."
    return "Move the value to a secret manager or environment variable, rotate the exposed credential if real, and remove it from git history where practical."


def _rationale(pattern: SecretPattern, tracked: bool | None) -> str:
    tracked_note = " It appears tracked by git." if tracked is True else ""
    if tracked is False:
        tracked_note = " It was found on disk but does not appear tracked by git."
    return f"{pattern.name} material in source can be reused by anyone who can read the repository or artifact.{tracked_note}"


def _git_tracked(path: Path, root: Path | None) -> bool | None:
    if not root:
        return None
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--error-unmatch", str(rel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.returncode == 0


def _dedupe(findings: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, str, int, str]] = set()
    for finding in findings:
        key = (finding["rule_id"], finding["file"], finding["line"], finding.get("redacted_value", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out
