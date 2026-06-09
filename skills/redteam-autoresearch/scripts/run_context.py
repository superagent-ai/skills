#!/usr/bin/env python3
"""Shared run-directory helpers for red-team autoresearch scripts."""
from __future__ import annotations

import json
import os
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_WORKSPACE = Path(".red-team")
DEFAULT_RUNS_DIR = DEFAULT_WORKSPACE / "runs"
DEFAULT_CONFIG = DEFAULT_WORKSPACE / "config.yaml"
RUN_DIR_ENV = "REDTEAM_RUN_DIR"


@dataclass(frozen=True)
class RunContext:
    run_dir: Path
    run_id: str

    def path(self, name: str) -> Path:
        return self.run_dir / name


def new_run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{timestamp}-{uuid.uuid4().hex[:6]}"


def _run_dir_from_config(cfg: dict | None) -> str | None:
    if not cfg:
        return None
    run_cfg = cfg.get("run") or {}
    if not isinstance(run_cfg, dict):
        return None
    value = run_cfg.get("dir") or run_cfg.get("run_dir")
    return str(value) if value else None


def _read_manifest(run_dir: Path) -> dict:
    manifest_path = run_dir / "run.json"
    if not manifest_path.exists():
        return {}
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def run_id_for(run_dir: Path) -> str:
    manifest = _read_manifest(run_dir)
    return str(manifest.get("run_id") or run_dir.name)


def resolve_run_context(
    cfg: dict | None = None,
    run_dir: str | Path | None = None,
    *,
    create: bool = False,
) -> RunContext:
    """Resolve a run dir from CLI, env, config, then legacy .red-team fallback."""
    selected = run_dir or os.environ.get(RUN_DIR_ENV) or _run_dir_from_config(cfg) or DEFAULT_WORKSPACE
    path = Path(selected)
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return RunContext(run_dir=path, run_id=run_id_for(path))


def write_manifest(run_dir: Path, run_id: str, source_config: Path | None = None) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if source_config is not None:
        manifest["source_config"] = str(source_config)
    path = run_dir / "run.json"
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def init_run(
    config_path: str | Path = DEFAULT_CONFIG,
    *,
    run_id: str | None = None,
    runs_dir: str | Path = DEFAULT_RUNS_DIR,
) -> RunContext:
    source = Path(config_path)
    if not source.exists():
        raise FileNotFoundError(f"Config not found: {source}")
    rid = run_id or new_run_id()
    run_dir = Path(runs_dir) / rid
    run_dir.mkdir(parents=True, exist_ok=False)
    shutil.copy2(source, run_dir / "config.yaml")
    write_manifest(run_dir, rid, source)
    return RunContext(run_dir=run_dir, run_id=rid)
