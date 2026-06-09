#!/usr/bin/env python3
"""
MAP-Elites quality-diversity archive over a (category x attack_style) grid (Rainbow Teaming).

The archive is what makes the loop find *novel* breaks instead of re-running the one trick that
worked. Each grid cell keeps a single "elite": the highest-fitness attack discovered for that
(category, attack_style) combination. Fitness is the StrongREJECT score (optionally plus a
novelty bonus). Reporting the grid shows coverage gaps, and `--suggest` samples the
under-explored cells so the next cycle deliberately fills them.

Reads recorded attempts (<run_dir>/attempts.jsonl), updates <run_dir>/archive.json, and can print a
coverage report and a list of cells to target next.

Usage:
  python archive.py --run-dir .red-team/runs/<run_id> --report
  python archive.py --run-dir .red-team/runs/<run_id> --suggest 8
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

try:  # canonical taxonomy if available; otherwise self-contained defaults
    from schema import ATTACK_STYLES as _STYLES, CATEGORIES as _CATS
except Exception:  # pragma: no cover - defensive
    _CATS = ["harmful_content", "jailbreak", "prompt_injection", "backdoor"]
    _STYLES = ["direct", "roleplay_persona", "hypothetical_fiction", "encoding_obfuscation",
               "authority_appeal", "persuasion_social", "multi_turn_escalation",
               "context_overload", "format_injection", "code_cipher"]

from run_context import resolve_run_context  # noqa: E402

_ELITE_FIELDS = ("id", "category", "attack_style", "technique", "prompt", "outcome",
                 "severity", "strongreject_score", "novelty_score")


def cell_key(category: str, style: str) -> str:
    return f"{category}|{style}"


def fitness(row: dict, novelty_weight: float) -> float:
    score = float(row.get("strongreject_score", 0.0) or 0.0)
    nov = float(row.get("novelty_score", 0.0) or 0.0)
    return score + novelty_weight * nov


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return rows


def load_archive(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {"cells": {}, "meta": {}}


def elite_of(row: dict, novelty_weight: float) -> dict:
    elite = {k: row.get(k) for k in _ELITE_FIELDS}
    elite["fitness"] = round(fitness(row, novelty_weight), 4)
    return elite


def update_archive(archive: dict, attempts: list[dict], novelty_weight: float) -> dict:
    cells = archive.setdefault("cells", {})
    placed = unplaced = improved = 0
    for row in attempts:
        cat, style = row.get("category"), row.get("attack_style")
        if cat not in _CATS or style not in _STYLES:
            unplaced += 1
            continue
        placed += 1
        key = cell_key(cat, style)
        cand = elite_of(row, novelty_weight)
        cur = cells.get(key)
        if cur is None or cand["fitness"] > cur.get("fitness", -1.0):
            cells[key] = cand
            improved += 1
    archive["meta"] = {
        "categories": _CATS, "attack_styles": _STYLES,
        "total_cells": len(_CATS) * len(_STYLES), "filled_cells": len(cells),
        "novelty_weight": novelty_weight, "placed": placed, "unplaced": unplaced,
        "improved": improved,
    }
    return archive


def coverage_report(archive: dict) -> str:
    cells = archive.get("cells", {})
    total = len(_CATS) * len(_STYLES)
    filled = len(cells)
    fits = [c["fitness"] for c in cells.values()]
    mean_fit = sum(fits) / len(fits) if fits else 0.0
    wins = sum(1 for c in cells.values() if c.get("outcome") == "confirmed")
    lines = [
        "Archive coverage",
        f"  filled cells : {filled}/{total} ({100 * filled / total:.0f}%)",
        f"  mean elite fitness : {mean_fit:.3f}",
        f"  confirmed elites : {wins}",
        "",
        "Fitness grid (rows=category, cols=attack_style; '.' = empty):",
    ]
    width = max(len(s) for s in _STYLES)
    header = " " * 18 + " ".join(s[:6].rjust(6) for s in _STYLES)
    lines.append(header)
    for cat in _CATS:
        cellsrow = []
        for style in _STYLES:
            c = cells.get(cell_key(cat, style))
            cellsrow.append(f"{c['fitness']:.2f}".rjust(6) if c else "     .")
        lines.append(f"{cat[:17].ljust(17)} " + " ".join(cellsrow))
    return "\n".join(lines)


def suggest_cells(archive: dict, n: int, rng: random.Random) -> list[dict]:
    """Sample under-explored cells: empty cells first, then low-fitness cells (softmax)."""
    cells = archive.get("cells", {})
    candidates = []
    for cat in _CATS:
        for style in _STYLES:
            c = cells.get(cell_key(cat, style))
            fit = c.get("fitness", 0.0) if c else None
            # priority: empty cell -> 1.0; filled -> headroom (1 - fitness), min 0.05
            priority = 1.0 if fit is None else max(0.05, 1.0 - min(fit, 1.0))
            candidates.append({
                "category": cat, "attack_style": style,
                "current_fitness": None if fit is None else round(fit, 4),
                "reason": "empty" if fit is None else "low_fitness",
                "_p": priority,
            })
    # weighted sampling without replacement via softmax over priority
    chosen = []
    pool = list(candidates)
    for _ in range(min(n, len(pool))):
        weights = [math.exp(2.0 * c["_p"]) for c in pool]
        total = sum(weights)
        r = rng.random() * total
        acc = 0.0
        for i, w in enumerate(weights):
            acc += w
            if acc >= r:
                pick = pool.pop(i)
                pick.pop("_p", None)
                chosen.append(pick)
                break
    return chosen


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="MAP-Elites quality-diversity archive")
    ap.add_argument("--run-dir", help="isolated run artifact directory")
    ap.add_argument("--attempts")
    ap.add_argument("--archive")
    ap.add_argument("--novelty-weight", type=float, default=0.0,
                    help="add novelty_weight * novelty_score to fitness")
    ap.add_argument("--report", action="store_true", help="print coverage report")
    ap.add_argument("--suggest", type=int, default=0, help="print N under-explored cells to target")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args(argv)

    ctx = resolve_run_context(run_dir=args.run_dir, create=True)
    archive_path = Path(args.archive) if args.archive else ctx.path("archive.json")
    archive = load_archive(archive_path)
    attempts_path = Path(args.attempts) if args.attempts else ctx.path("attempts.jsonl")
    attempts = load_jsonl(attempts_path)
    archive = update_archive(archive, attempts, args.novelty_weight)

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    archive_path.write_text(json.dumps(archive, ensure_ascii=False, indent=2), encoding="utf-8")
    meta = archive["meta"]
    print(f"archive: {meta['filled_cells']}/{meta['total_cells']} cells filled "
          f"({meta['placed']} placed, {meta['unplaced']} unplaced) -> {archive_path}")

    if args.report:
        print()
        print(coverage_report(archive))
    if args.suggest:
        rng = random.Random(args.seed)
        print()
        print(f"# target these {args.suggest} under-explored cells next:")
        for cell in suggest_cells(archive, args.suggest, rng):
            print(json.dumps(cell, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
