#!/usr/bin/env python3
"""
Collect a GitHub repository's security-relevant configuration and files into a
single JSON inventory for the repo-security-posture skill to reason over.

Usage:
    python3 collect.py owner/name [--output PATH]
    python3 collect.py https://github.com/owner/name

Auth:
    Set GITHUB_TOKEN (or GH_TOKEN) to read settings that require admin/push
    (branch protection, actions permissions, security features, collaborators,
    hooks, deploy keys, environments). Without a token, public file content is
    still collected and protected settings are recorded under `not_verified`.

Design: stdlib only, no pip installs. Every protected read is wrapped so a 403/404
is recorded as inaccessible rather than crashing the run or guessing a value.
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = "https://api.github.com"
TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

# Files worth pulling. Each entry is (inventory_key, [candidate paths]).
SINGLE_FILES = {
    "codeowners": [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"],
    "dependabot": [".github/dependabot.yml", ".github/dependabot.yaml"],
    "package_json": ["package.json"],
    "pyproject": ["pyproject.toml"],
    "renovate": ["renovate.json", ".github/renovate.json", ".renovaterc.json", ".renovaterc"],
    "pnpm_workspace": ["pnpm-workspace.yaml"],
}
EXISTENCE_ONLY = {
    "security_md": ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"],
    "lock_npm": ["package-lock.json"],
    "lock_pnpm": ["pnpm-lock.yaml"],
    "lock_yarn": ["yarn.lock"],
    "lock_shrinkwrap": ["npm-shrinkwrap.json"],
    "npmrc": [".npmrc"],
}


def parse_repo(arg):
    arg = arg.strip()
    m = re.search(r"github\.com[/:]([^/]+)/([^/.\s]+)", arg)
    if m:
        return m.group(1), m.group(2)
    if "/" in arg:
        owner, name = arg.split("/")[:2]
        return owner, re.sub(r"\.git$", "", name)
    raise ValueError(f"Could not parse repo from: {arg!r}. Use owner/name or a URL.")


# Set when the API returns a hard rate-limit, so callers can give a clear message.
RATE_LIMITED = {"hit": False}

# Keep inventories useful without copying literal tokens into model context,
# reports, shell logs, or issue bodies.
SECRET_PATTERNS = [
    re.compile(r"(?i)((?:_authToken|authToken)\s*=\s*)([^\s#]+)"),
    re.compile(r"(?i)((?:token|secret|password|api[_-]?key)\s*[:=]\s*[\"']?)([^\"'\s#]+)"),
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\b(npm_[A-Za-z0-9]{20,})\b"),
    re.compile(r"\b(pypi-[A-Za-z0-9_\-]{20,})\b"),
]


def redact_content(content):
    """Redact common literal token formats from fetched repository files."""
    redacted = content
    changed = False
    for pattern in SECRET_PATTERNS:
        if pattern.groups >= 2:
            redacted, count = pattern.subn(r"\1[REDACTED]", redacted)
        else:
            redacted, count = pattern.subn("[REDACTED]", redacted)
        changed = changed or count > 0
    return redacted, changed


def request(path, accept="application/vnd.github+json", raw=False):
    """Return (status, parsed_or_text). status is an int; -1 on network error."""
    url = path if path.startswith("http") else API + path
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github.raw" if raw else accept)
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "repo-security-posture")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            status = resp.status
            if raw:
                return status, body.decode("utf-8", "replace")
            text = body.decode("utf-8", "replace")
            return status, (json.loads(text) if text.strip() else None)
    except urllib.error.HTTPError as e:
        # Distinguish a quota wall from a permissions wall.
        if e.code in (403, 429) and e.headers.get("X-RateLimit-Remaining") == "0":
            RATE_LIMITED["hit"] = True
        return e.code, None
    except Exception as e:  # network, timeout, DNS
        return -1, str(e)


def raw_get(owner, name, branch, path):
    """Fetch a file's text from raw.githubusercontent.com (separate quota). None if absent."""
    url = f"https://raw.githubusercontent.com/{owner}/{name}/{branch}/{path}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "repo-security-posture")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError:
        return None
    except Exception:
        return None


def accessible(status):
    return 200 <= status < 300


def reason(status):
    if RATE_LIMITED["hit"]:
        return "GitHub API rate limit exhausted — set GITHUB_TOKEN (anonymous is 60/hr, token is 5000/hr)"
    return {
        401: "auth required / token invalid",
        403: "forbidden — needs admin or push access (set GITHUB_TOKEN)",
        404: "not found or not visible without sufficient access",
        -1: "network error reaching api.github.com",
    }.get(status, f"http {status}")


def get_file(owner, name, branches, path):
    """Return text content of a file via raw CDN, trying each branch. None if absent."""
    for branch in branches:
        content = raw_get(owner, name, branch, path)
        if content is not None:
            return content
    return None


def file_exists(owner, name, branches, path):
    return get_file(owner, name, branches, path) is not None


def list_workflows(owner, name, branches):
    """List + fetch workflow files. Uses one contents-API call to enumerate, then
    pulls each file's body from the raw CDN (download_url) to spare API quota."""
    status, listing = request(f"/repos/{owner}/{name}/contents/.github/workflows")
    if not accessible(status) or not isinstance(listing, list):
        return []
    out = []
    for entry in listing:
        if entry.get("type") == "file" and entry.get("name", "").endswith((".yml", ".yaml")):
            content = None
            dl = entry.get("download_url")
            if dl:
                _, content = request(dl, raw=True)
                if not isinstance(content, str):
                    content = None
            if content is None:
                content = get_file(owner, name, branches, entry["path"])
            content, redacted = redact_content(content or "")
            item = {"path": entry["path"], "content": content}
            if redacted:
                item["redacted"] = True
            out.append(item)
    return out


def protected_read(inv_key, path, not_verified, transform=None):
    """Read an admin-gated endpoint; record under not_verified if inaccessible."""
    status, data = request(path)
    if accessible(status):
        return transform(data) if transform else (data if data is not None else True)
    not_verified.append({"check": inv_key, "reason": reason(status)})
    return {"accessible": False, "reason": reason(status)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", help="owner/name or GitHub URL")
    ap.add_argument("--output", help="write JSON here instead of stdout")
    args = ap.parse_args()

    owner, name = parse_repo(args.repo)
    not_verified = []

    inv = {
        "repo": f"{owner}/{name}",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "auth": "token" if TOKEN else "anonymous",
    }

    # --- Basic metadata (public) ---
    status, meta = request(f"/repos/{owner}/{name}")
    if status == -1:
        inv["error"] = f"network error: {meta}. Check access to api.github.com."
        emit(inv, args.output)
        return

    meta = meta or {}
    api_blocked = not accessible(status)
    if api_blocked:
        # Don't give up: file content still comes from the raw CDN on a separate
        # quota. Record the API gap and continue with branch guesses.
        inv["api_warning"] = f"GitHub API metadata unreadable: {reason(status)}. " \
            "Settings could not be checked; file-based checks still ran via raw CDN."
        default_branch = "main"
    else:
        default_branch = meta.get("default_branch", "main")

    # Branch order for raw file fetches: default first, then common fallbacks.
    branches = list(dict.fromkeys([default_branch, "main", "master"]))

    inv["metadata"] = {
        "default_branch": default_branch if not api_blocked else "unknown (assumed main/master)",
        "visibility": meta.get("visibility"),
        "is_fork": meta.get("fork"),
        "archived": meta.get("archived"),
        "pushed_at": meta.get("pushed_at"),
        "open_issues": meta.get("open_issues_count"),
        "forks": meta.get("forks_count"),
        "stars": meta.get("stargazers_count"),
        "language": meta.get("language"),
    }
    # security_and_analysis only present with admin
    sec = meta.get("security_and_analysis")
    inv["metadata"]["security_and_analysis"] = sec if sec else None

    # --- Settings (mostly admin-gated) ---
    settings = {}
    settings["branch_protection"] = protected_read(
        "branch_protection",
        f"/repos/{owner}/{name}/branches/{default_branch}/protection",
        not_verified,
    )
    settings["rules_for_default_branch"] = protected_read(
        "branch_rules",
        f"/repos/{owner}/{name}/rules/branches/{default_branch}",
        not_verified,
    )
    settings["actions_permissions"] = protected_read(
        "actions_permissions",
        f"/repos/{owner}/{name}/actions/permissions",
        not_verified,
    )
    settings["default_workflow_token"] = protected_read(
        "default_workflow_token",
        f"/repos/{owner}/{name}/actions/permissions/workflow",
        not_verified,
    )
    # vulnerability alerts: 204 enabled, 404 disabled/no-access
    va_status, _ = request(f"/repos/{owner}/{name}/vulnerability-alerts")
    if va_status == 204:
        settings["vulnerability_alerts"] = {"enabled": True}
    elif va_status == 404:
        settings["vulnerability_alerts"] = {"enabled": False}
    else:
        settings["vulnerability_alerts"] = {"accessible": False, "reason": reason(va_status)}
        not_verified.append({"check": "vulnerability_alerts", "reason": reason(va_status)})

    settings["environments"] = protected_read(
        "environments",
        f"/repos/{owner}/{name}/environments",
        not_verified,
    )
    inv["settings"] = settings

    # --- Access surface (push/admin-gated) ---
    access = {}
    access["collaborators"] = protected_read(
        "collaborators",
        f"/repos/{owner}/{name}/collaborators?affiliation=all&per_page=100",
        not_verified,
        transform=lambda d: [
            {"login": c.get("login"), "permissions": c.get("permissions")} for c in d
        ] if isinstance(d, list) else d,
    )
    access["webhooks"] = protected_read(
        "webhooks", f"/repos/{owner}/{name}/hooks", not_verified,
        transform=lambda d: [
            {"url": h.get("config", {}).get("url"), "has_secret": bool(h.get("config", {}).get("secret")),
             "events": h.get("events"), "active": h.get("active")} for h in d
        ] if isinstance(d, list) else d,
    )
    access["deploy_keys"] = protected_read(
        "deploy_keys", f"/repos/{owner}/{name}/keys", not_verified,
        transform=lambda d: [
            {"title": k.get("title"), "read_only": k.get("read_only")} for k in d
        ] if isinstance(d, list) else d,
    )
    inv["access"] = access

    # --- Files (public content via raw CDN) ---
    files = {"workflows": list_workflows(owner, name, branches)}
    for key, candidates in SINGLE_FILES.items():
        content = None
        for path in candidates:
            content = get_file(owner, name, branches, path)
            if content is not None:
                content, redacted = redact_content(content)
                files[key] = {"path": path, "content": content}
                if redacted:
                    files[key]["redacted"] = True
                break
        if content is None:
            files[key] = None
    for key, candidates in EXISTENCE_ONLY.items():
        files[key] = any(file_exists(owner, name, branches, p) for p in candidates)
    # GitHub serves community-health files (SECURITY.md) from the org-level
    # `{owner}/.github` repo when absent in the repo itself. Check that fallback
    # so a present-but-org-level policy isn't flagged as missing.
    if not files.get("security_md"):
        org_health = any(
            get_file(owner, ".github", ["main", "master"], p) is not None
            for p in ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md", "profile/SECURITY.md"]
        )
        if org_health:
            files["security_md"] = "org-level (.github repo)"
    inv["files"] = files

    inv["not_verified"] = not_verified
    inv["notes"] = (
        "Items in not_verified require admin/push access. Re-run with a "
        "sufficiently-scoped GITHUB_TOKEN to resolve them, or have the "
        "maintainer confirm current state manually."
    ) if not_verified else "All targeted settings were readable."

    emit(inv, args.output)


def emit(inv, output):
    text = json.dumps(inv, indent=2)
    if output:
        with open(output, "w") as f:
            f.write(text)
        print(f"Wrote inventory to {output}", file=sys.stderr)
        print(f"  auth={inv.get('auth')}  not_verified={len(inv.get('not_verified', []))}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
