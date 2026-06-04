#!/usr/bin/env python3
"""
infra-security scanner -- Stage 1 (deterministic) engine.

Walks a target tree, classifies each file (Terraform, CloudFormation/SAM,
Kubernetes/Helm, Docker, Docker Compose), and runs line-oriented detectors for
the misconfigurations that are unambiguous in text: world-open security groups,
wildcard IAM, public S3, disabled encryption, privileged/root containers,
plaintext secrets, and more. Emits findings with file:line and a CI exit code.

This is the *mechanical* half. The agent that invoked the skill reads the output
and performs Stage 2: blast-radius judgment, false-positive suppression, and the
controls a regex cannot see (a *missing* resource, an over-broad role for its
workload, a cross-resource chain). See ../SKILL.md and ../references/controls.md.

Pure standard library -- no pip install, no hcl2, no pyyaml.

Usage:
    python3 scan.py <target-dir-or-file> [--format markdown|json] \\
        [--severity P0,P1] [--min-confidence 0.0]

Exit code: 1 if any P0/P1 finding is present (CI gate), else 0.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"

SEVERITY_ORDER = {"P0": 4, "P1": 3, "P2": 2, "P3": 1, "INFO": 0}

# Database / cache / search ports that must never face the internet.
DB_PORTS = {3306, 5432, 1433, 1521, 6379, 27017, 9200, 9300, 11211, 5984, 9042}

SKIP_DIRS = {".git", ".terraform", ".terragrunt-cache", "node_modules", "vendor",
             ".venv", "venv", "__pycache__", ".idea", ".vscode", "dist", "build"}

CATEGORY_BY_PREFIX = {
    "network": "Network",
    "iam": "IAM",
    "storage": "Storage",
    "container": "Compute",
    "secrets": "Secrets",
    "logging": "Logging",
    "supply": "Supply Chain",
}

# Default human title per control id (a detector may pass its own).
TITLES = {
    "network-ssh-world-open": "SSH (22) open to 0.0.0.0/0",
    "network-rdp-world-open": "RDP (3389) open to 0.0.0.0/0",
    "network-db-world-open": "Database port open to 0.0.0.0/0",
    "network-all-ports-world-open": "All ports open to 0.0.0.0/0 (ingress)",
    "network-egress-world-open": "Unrestricted egress to 0.0.0.0/0",
    "iam-wildcard-action": "IAM policy allows Action *",
    "iam-wildcard-resource": "IAM policy allows Resource *",
    "iam-wildcard-principal": "Resource policy allows Principal *",
    "iam-passrole-wildcard": "iam:PassRole / AssumeRole on *",
    "storage-s3-public-acl": "S3 bucket with public ACL",
    "storage-encryption-disabled": "Encryption at rest disabled",
    "secrets-plaintext": "Plaintext secret in IaC",
    "secrets-missing-tls": "Plaintext / non-redirected HTTP",
    "secrets-kms-wildcard-policy": "KMS key policy allows wildcard principal",
    "logging-no-retention": "Log group without retention",
    "container-privileged": "Privileged / escalation-capable container",
    "container-run-as-root": "Container runs as root",
    "container-host-namespace": "Container shares a host namespace",
    "container-docker-socket-mount": "Docker socket / host root mounted in",
    "supply-image-untrusted": "Mutable / untrusted image or module",
}


@dataclass
class Finding:
    control_id: str
    severity: str
    file: str
    line: int
    snippet: str
    confidence: float = 0.8
    title: str = ""
    category: str = ""

    def __post_init__(self) -> None:
        if not self.title:
            self.title = TITLES.get(self.control_id, self.control_id)
        if not self.category:
            self.category = CATEGORY_BY_PREFIX.get(self.control_id.split("-")[0], "Other")

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------------- #
def _snip(line: str, limit: int = 160) -> str:
    return line.strip()[:limit]


def _is_star(value: str) -> bool:
    """True if value is a bare wildcard ("*", '*', ["*"]) -- not a partial like s3:*."""
    return re.sub(r"[\[\]\{\}\"'\s,]", "", value) == "*"


def _nearest_direction(lines: list[str], i: int, radius: int = 30) -> str:
    """Walk backward from line i to decide if a rule is ingress or egress."""
    for d in range(radius + 1):
        j = i - d
        if j < 0:
            break
        s = lines[j].lower()
        if "egress" in s:
            return "egress"
        if "ingress" in s:
            return "ingress"
    return "ingress"


def _nearest_ports(lines: list[str], i: int, radius: int = 18):
    """Find the closest from/to port and protocol around a CIDR line."""
    frm = to = proto = None
    for d in range(radius + 1):
        for j in (i - d, i + d):
            if not (0 <= j < len(lines)):
                continue
            s = lines[j]
            if frm is None:
                m = re.search(r"(?i)(?:from_?port)\s*[:=]\s*\"?(\d+)", s)
                if m:
                    frm = int(m.group(1))
            if to is None:
                m = re.search(r"(?i)(?:to_?port)\s*[:=]\s*\"?(\d+)", s)
                if m:
                    to = int(m.group(1))
            if proto is None:
                m = re.search(r"(?i)(?:ip_?protocol|protocol)\s*[:=]\s*\"?(-1|all|tcp|udp|\d+)", s)
                if m:
                    proto = m.group(1).lower()
        if frm is not None and to is not None and proto is not None:
            break
    return frm, to, proto


def _iter_blocks(lines: list[str], header_re: re.Pattern):
    """Yield (start_index, block_text) for brace-delimited HCL blocks whose
    opening line matches header_re. Used for whole-resource checks."""
    i = 0
    n = len(lines)
    while i < n:
        if header_re.search(lines[i]):
            depth = lines[i].count("{") - lines[i].count("}")
            start = i
            j = i
            while depth > 0 and j + 1 < n:
                j += 1
                depth += lines[j].count("{") - lines[j].count("}")
            yield start, "\n".join(lines[start:j + 1])
            i = j + 1
        else:
            i += 1


SECRET_KEY_RE = re.compile(
    r"(?i)\b\w*(?:password|passwd|secret|secret[_-]?key|api[_-]?key|access[_-]?key|"
    r"auth[_-]?token|token|private[_-]?key|client[_-]?secret)\w*\b"
)


def _looks_secretish(name: str) -> bool:
    return bool(SECRET_KEY_RE.search(name))


# --------------------------------------------------------------------------- #
# network: world-open security groups (Terraform + CloudFormation)
# --------------------------------------------------------------------------- #
def d_security_groups(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(lines):
        if "0.0.0.0/0" not in line and "::/0" not in line:
            continue
        direction = _nearest_direction(lines, i)
        frm, to, proto = _nearest_ports(lines, i)
        all_ports = (
            proto in ("-1", "all")
            or (frm == 0 and to is not None and to >= 65535)
            or (frm == 0 and to == 0 and proto in (None, "-1", "all"))
        )
        if direction == "egress":
            out.append(Finding("network-egress-world-open", "P3", rel, i + 1, _snip(line), 0.7))
            continue
        if all_ports:
            out.append(Finding("network-all-ports-world-open", "P0", rel, i + 1, _snip(line), 0.85))
            continue
        if frm is None or to is None:
            continue  # unknown port range -- let the model judge, avoid web-port FPs
        lo, hi = min(frm, to), max(frm, to)
        if lo <= 22 <= hi:
            out.append(Finding("network-ssh-world-open", "P0", rel, i + 1, _snip(line), 0.9))
        elif lo <= 3389 <= hi:
            out.append(Finding("network-rdp-world-open", "P0", rel, i + 1, _snip(line), 0.9))
        elif any(lo <= p <= hi for p in DB_PORTS):
            out.append(Finding("network-db-world-open", "P0", rel, i + 1, _snip(line), 0.9))
    return out


# --------------------------------------------------------------------------- #
# IAM: wildcard action / resource / principal, PassRole (TF + CFN + JSON)
# --------------------------------------------------------------------------- #
def _principal_control(lines: list[str], i: int) -> str:
    """A wildcard principal on a KMS key policy maps to its own control."""
    for d in range(1, 22):
        j = i - d
        if j < 0:
            break
        s = lines[j].lower()
        if "aws_kms_key" in s or "aws::kms::key" in s or re.search(r"\bkms[_ ]?key\b", s):
            return "secrets-kms-wildcard-policy"
    return "iam-wildcard-principal"


def d_iam(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    ctx = None  # "action" | "resource" | "principal" when inside a multi-line list
    key_re = re.compile(r"(?i)^\"?(action|resource|principal)\"?s?\s*[:=]\s*(.*)$")
    open_re = re.compile(r"(?i)^\"?(action|resource|principal)\"?s?\s*[:=]\s*(\[|)\s*$")
    aws_star_re = re.compile(r"(?i)^\"?aws\"?\s*[:=]\s*\"?\*\"?\s*,?$")
    inline_principal_re = re.compile(
        r"(?i)\"?principal\"?\s*[:=]\s*(?:\"?\*\"?|\{[^}]*\"?aws\"?\s*[:=]\s*\"?\*\"?[^}]*\})"
    )

    def emit(kind: str, idx: int) -> None:
        if kind == "action":
            out.append(Finding("iam-wildcard-action", "P1", rel, idx + 1, _snip(lines[idx]), 0.8))
        elif kind == "resource":
            out.append(Finding("iam-wildcard-resource", "P2", rel, idx + 1, _snip(lines[idx]), 0.7))
        else:
            cid = _principal_control(lines, idx)
            sev = "P1" if cid == "secrets-kms-wildcard-policy" else "P0"
            out.append(Finding(cid, sev, rel, idx + 1, _snip(lines[idx]), 0.8))

    for i, raw in enumerate(lines):
        line = raw.strip()
        if not line:
            ctx = None
            continue
        if aws_star_re.match(line):
            emit("principal", i)
            continue
        if inline_principal_re.search(line):
            emit("principal", i)
            ctx = None
            continue
        m = key_re.match(line)
        if m:
            kind, val = m.group(1).lower(), m.group(2).strip().rstrip(",")
            if val and val not in ("[", "{") and _is_star(val):
                emit(kind, i)
                ctx = None
                continue
            if open_re.match(line):  # opens a list / yaml block
                ctx = kind
                continue
            ctx = None
            continue
        if ctx:
            item = re.sub(r"^-\s*", "", line).rstrip(",")
            if _is_star(item):
                emit(ctx, i)
            if line.endswith("]") or line.endswith("}") or key_re.match(line):
                ctx = None
    return out


def d_iam_passrole(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(lines):
        if not re.search(r"(?i)(iam:passrole|sts:assumerole)", line):
            continue
        for d in range(-15, 16):
            j = i + d
            if 0 <= j < len(lines) and re.search(r"(?i)\"?resource\"?s?\s*[:=]", lines[j]):
                val = lines[j].split("=", 1)[-1].split(":", 1)[-1]
                if _is_star(val) or (j + 1 < len(lines) and _is_star(lines[j + 1])):
                    out.append(Finding("iam-passrole-wildcard", "P1", rel, i + 1, _snip(line), 0.6))
                    break
    return out


# --------------------------------------------------------------------------- #
# storage: public S3 ACL, disabled encryption (TF + CFN)
# --------------------------------------------------------------------------- #
def d_storage(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(lines):
        if re.search(r"(?i)\bacl\s*[:=]\s*\"?public-read(-write)?\"?", line) or \
           re.search(r"(?i)AccessControl\s*[:=]\s*\"?PublicRead(Write)?\"?", line):
            out.append(Finding("storage-s3-public-acl", "P0", rel, i + 1, _snip(line), 0.85))
        if re.search(r"(?i)(storage_encrypted|encrypted)\s*=\s*false", line) or \
           re.search(r"(?i)(StorageEncrypted|Encrypted)\s*:\s*false", line):
            out.append(Finding("storage-encryption-disabled", "P2", rel, i + 1, _snip(line), 0.8))
    return out


def d_tf_log_retention(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    header = re.compile(r"(?i)resource\s+\"aws_cloudwatch_log_group\"")
    for start, block in _iter_blocks(lines, header):
        if not re.search(r"(?i)retention_in_days", block):
            out.append(Finding("logging-no-retention", "P3", rel, start + 1,
                               _snip(lines[start]), 0.7))
    return out


def d_tf_module(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(lines):
        m = re.search(r"(?i)source\s*=\s*\"((?:git::)?https?://[^\"]+)\"", line)
        if m and "ref=" not in m.group(1):
            out.append(Finding("supply-image-untrusted", "P3", rel, i + 1, _snip(line), 0.6,
                               title="Terraform module from unpinned/unverified source"))
    return out


def d_tls(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(lines):
        if re.search(r"(?i)viewer_protocol_policy\s*[:=]\s*\"?allow-all\"?", line):
            out.append(Finding("secrets-missing-tls", "P2", rel, i + 1, _snip(line), 0.8))
    return out


# --------------------------------------------------------------------------- #
# secrets: plaintext values (Terraform)
# --------------------------------------------------------------------------- #
def d_secrets_tf(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    var_name = None
    var_depth = 0
    assign_re = re.compile(r"(?i)^\s*([\w-]+)\s*=\s*\"([^\"${}]{4,})\"\s*$")
    for i, raw in enumerate(lines):
        line = raw.strip()
        mvar = re.match(r"(?i)variable\s+\"([^\"]+)\"", line)
        if mvar:
            var_name = mvar.group(1)
            var_depth = 0
        if var_name:
            var_depth += line.count("{") - line.count("}")
            md = re.match(r"(?i)^default\s*=\s*\"([^\"${}]{4,})\"", line)
            if md and _looks_secretish(var_name):
                out.append(Finding("secrets-plaintext", "P1", rel, i + 1, _snip(raw), 0.6))
            if var_depth <= 0 and "{" in "".join(lines[max(0, i - 3):i + 1]):
                var_name = None
        m = assign_re.match(raw)
        if m and _looks_secretish(m.group(1)):
            out.append(Finding("secrets-plaintext", "P1", rel, i + 1, _snip(raw), 0.6))
    return out


# --------------------------------------------------------------------------- #
# kubernetes / compose container security
# --------------------------------------------------------------------------- #
def d_container_yaml(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    last_name = None
    for i, raw in enumerate(lines):
        line = raw.strip()
        if re.search(r"(?i)^privileged\s*:\s*true", line) or re.search(r"(?i)privileged\s*=\s*true", line):
            out.append(Finding("container-privileged", "P1", rel, i + 1, _snip(raw), 0.85))
        if re.search(r"(?i)^allowPrivilegeEscalation\s*:\s*true", line):
            out.append(Finding("container-privileged", "P2", rel, i + 1, _snip(raw), 0.8,
                               title="allowPrivilegeEscalation: true"))
        if re.search(r"(?i)^runAsNonRoot\s*:\s*false", line):
            out.append(Finding("container-run-as-root", "P1", rel, i + 1, _snip(raw), 0.85))
        if re.search(r"(?i)^runAsUser\s*:\s*0\b", line):
            out.append(Finding("container-run-as-root", "P1", rel, i + 1, _snip(raw), 0.85))
        if re.search(r"(?i)^host(Network|PID|IPC)\s*:\s*true", line):
            out.append(Finding("container-host-namespace", "P1", rel, i + 1, _snip(raw), 0.85))
        if re.search(r"(?i)add\s*:\s*\[?[^]]*\b(SYS_ADMIN|NET_ADMIN|ALL)\b", line):
            out.append(Finding("container-privileged", "P1", rel, i + 1, _snip(raw), 0.7,
                               title="Dangerous Linux capability added"))
        if re.search(r"/var/run/docker\.sock", line):
            out.append(Finding("container-docker-socket-mount", "P0", rel, i + 1, _snip(raw), 0.9))
        elif re.search(r"(?i)path\s*:\s*\"?/\"?\s*$", line):
            out.append(Finding("container-docker-socket-mount", "P0", rel, i + 1, _snip(raw), 0.7,
                               title="Host root filesystem mounted via hostPath"))
        if re.search(r"(?i)image\s*[:=]\s*\"?\S+:latest\"?", line):
            out.append(Finding("supply-image-untrusted", "P3", rel, i + 1, _snip(raw), 0.8,
                               title="Container image pinned to :latest"))
        mname = re.match(r"(?i)-?\s*name\s*:\s*\"?([\w.-]+)\"?", line)
        if mname:
            last_name = mname.group(1)
        mval = re.match(r"(?i)value\s*:\s*\"?([^\"$#{}\s][^\"#]{3,})\"?", line)
        if mval and last_name and _looks_secretish(last_name):
            out.append(Finding("secrets-plaintext", "P1", rel, i + 1, _snip(raw), 0.6,
                               title="Plaintext secret in env value"))
    return out


# --------------------------------------------------------------------------- #
# dockerfile
# --------------------------------------------------------------------------- #
def d_dockerfile(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    saw_nonroot_user = False
    user_root_lines: list[int] = []
    for i, raw in enumerate(lines):
        line = raw.strip()
        mu = re.match(r"(?i)^USER\s+(\S+)", line)
        if mu:
            if mu.group(1).lower() in ("root", "0"):
                user_root_lines.append(i + 1)
            else:
                saw_nonroot_user = True
        if re.match(r"(?i)^FROM\s+\S+:latest(\s|$)", line):
            out.append(Finding("supply-image-untrusted", "P3", rel, i + 1, _snip(raw), 0.8,
                               title="Base image pinned to :latest"))
        if re.match(r"(?i)^ENV\s+\w*", line):
            menv = re.match(r"(?i)^ENV\s+([\w.-]+)\s*[= ]\s*(\S.*)$", line)
            if menv and _looks_secretish(menv.group(1)) and "${" not in menv.group(2):
                out.append(Finding("secrets-plaintext", "P1", rel, i + 1, _snip(raw), 0.6,
                                   title="Plaintext secret in Dockerfile ENV"))
    for ln in user_root_lines:
        out.append(Finding("container-run-as-root", "P2", rel, ln, "USER root", 0.7,
                           title="Dockerfile sets USER root"))
    if not saw_nonroot_user and not user_root_lines and any(
            re.match(r"(?i)^FROM\s", ln) and "scratch" not in ln.lower() for ln in lines):
        out.append(Finding("container-run-as-root", "P2", rel, 1,
                           "no USER directive -- defaults to root", 0.6,
                           title="Dockerfile never sets a non-root USER"))
    return out


# --------------------------------------------------------------------------- #
# classification + dispatch
# --------------------------------------------------------------------------- #
def classify(path: Path, text: str):
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix in (".tf", ".tfvars", ".hcl"):
        return "terraform"
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return "docker"
    if re.match(r"(docker-)?compose.*\.ya?ml$", name):
        return "compose"
    if suffix in (".yaml", ".yml"):
        if "AWSTemplateFormatVersion" in text or ("AWS::" in text and re.search(r"(?m)^Resources\s*:", text)):
            return "cloudformation"
        if re.search(r"(?m)^\s*apiVersion\s*:", text) and re.search(r"(?m)^\s*kind\s*:", text):
            return "kubernetes"
        if re.search(r"(?m)^services\s*:", text):
            return "compose"
        return None
    if suffix == ".json":
        if "AWSTemplateFormatVersion" in text or "AWS::" in text:
            return "cloudformation"
        if '"Statement"' in text and ('"Action"' in text or '"Effect"' in text):
            return "iam_json"
        return None
    return None


DISPATCH = {
    "terraform": [d_security_groups, d_iam, d_iam_passrole, d_storage, d_secrets_tf,
                  d_tf_log_retention, d_tf_module, d_tls],
    "cloudformation": [d_security_groups, d_iam, d_iam_passrole, d_storage, d_tls],
    "iam_json": [d_iam, d_iam_passrole],
    "kubernetes": [d_container_yaml],
    "compose": [d_container_yaml],
    "docker": [d_dockerfile],
}


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > 2_000_000:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return ""


def _iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        yield p


def run_scan(target: str) -> dict:
    root = Path(target)
    findings: list[Finding] = []
    inventory: dict[str, int] = {}
    files_scanned = 0

    for fp in _iter_files(root):
        text = _read_text(fp)
        if not text:
            continue
        kind = classify(fp, text)
        if kind is None:
            continue
        files_scanned += 1
        inventory[kind] = inventory.get(kind, 0) + 1
        rel = str(fp.relative_to(root)) if root.is_dir() else fp.name
        lines = text.splitlines()
        for detector in DISPATCH.get(kind, []):
            try:
                findings += detector(rel, lines)
            except Exception as exc:  # a malformed file must never crash the scan
                print(f"warn: {detector.__name__} failed on {rel}: {exc}", file=sys.stderr)

    findings = _dedupe(findings)
    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.file, f.line))
    return {
        "tool": "infra-security",
        "version": VERSION,
        "target": str(target),
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files_scanned": files_scanned,
        "inventory": inventory,
        "summary": _summary(findings),
        "deployment_risk": _deployment_risk(findings),
        "findings": [f.to_dict() for f in findings],
    }


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.file, f.line, f.control_id)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _summary(findings: list[Finding]) -> dict:
    by_sev: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    return {"total": len(findings), "by_severity": by_sev, "by_category": by_cat}


def _deployment_risk(findings: list[Finding]) -> str:
    p0 = sum(1 for f in findings if f.severity == "P0")
    p1 = sum(1 for f in findings if f.severity == "P1")
    p2 = sum(1 for f in findings if f.severity == "P2")
    if p0 or p1 >= 3:
        return "High"
    if p1 or p2:
        return "Medium"
    return "Low"


def _has_blocking(findings: list[dict]) -> bool:
    return any(f["severity"] in ("P0", "P1") for f in findings)


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #
def fmt_json(result: dict) -> str:
    return json.dumps(result, indent=2)


def fmt_markdown(result: dict) -> str:
    s = result["summary"]
    sev = s["by_severity"]
    lines = [
        f"# infra-security report: {result['target']}",
        "",
        f"- **Deployment risk:** {result['deployment_risk']}",
        f"- **Files scanned:** {result['files_scanned']}  ({', '.join(f'{k}: {v}' for k, v in sorted(result['inventory'].items())) or 'none'})",
        f"- **Findings:** {s['total']}  "
        f"(P0: {sev.get('P0', 0)}, P1: {sev.get('P1', 0)}, P2: {sev.get('P2', 0)}, P3: {sev.get('P3', 0)})",
        f"- **Scanned at:** {result['scanned_at']}  ·  scanner v{result['version']}",
        "",
        "## Findings",
        "",
    ]
    if not result["findings"]:
        lines.append("_No deterministic findings. Still review the IaC for missing-control "
                     "and blast-radius issues the scanner cannot see (see references/controls.md)._")
        return "\n".join(lines)
    current = None
    for f in result["findings"]:
        if f["severity"] != current:
            current = f["severity"]
            lines.append(f"### {current}")
            lines.append("")
        lines.append(f"- **[{f['severity']}] {f['control_id']}** — {f['title']}")
        lines.append(f"  - `{f['file']}:{f['line']}`  (confidence {f['confidence']:.2f})")
        lines.append(f"  - `{f['snippet']}`")
    lines += [
        "",
        "---",
        "_Stage 1 (deterministic) output. Confirm blast radius, suppress false positives, "
        "and add the missing-control findings per `references/controls.md`, then write the "
        "report with `references/report-template.md`._",
    ]
    return "\n".join(lines)


FORMATTERS = {"markdown": fmt_markdown, "json": fmt_json}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Deterministic IaC security scanner (Terraform, CloudFormation, K8s, Docker).")
    ap.add_argument("target", help="path to an IaC directory or a single file")
    ap.add_argument("-f", "--format", choices=list(FORMATTERS), default="markdown")
    ap.add_argument("--severity", help="comma-separated levels to show, e.g. P0,P1")
    ap.add_argument("--min-confidence", type=float, default=0.0,
                    help="hide findings below this confidence (0.0-1.0)")
    ap.add_argument("-o", "--output", help="write to a file instead of stdout")
    args = ap.parse_args()

    if not Path(args.target).exists():
        print(f"error: target not found: {args.target}", file=sys.stderr)
        return 2

    result = run_scan(args.target)
    blocking = _has_blocking(result["findings"])  # gate on the full result set

    if args.min_confidence > 0:
        result["findings"] = [f for f in result["findings"] if f["confidence"] >= args.min_confidence]
    if args.severity:
        wanted = {s.strip().upper() for s in args.severity.split(",")}
        result["findings"] = [f for f in result["findings"] if f["severity"] in wanted]
    result["summary"] = _summary([Finding(**{k: f[k] for k in
                                  ("control_id", "severity", "file", "line", "snippet", "confidence", "title", "category")})
                                  for f in result["findings"]])

    text = FORMATTERS[args.format](result)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(text)
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
