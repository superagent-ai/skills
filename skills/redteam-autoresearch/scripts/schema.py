#!/usr/bin/env python3
"""
Data schema for the red-team autoresearch harness.

Defines the category set, the Llama Guard hazard taxonomy, the attempt outcome taxonomy
(borrowed from the hacker skill), the JSONL attempt record, and a thread-safe append
writer. Every attempt -- pass or fail -- is recorded.
"""
from __future__ import annotations

import json
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

CATEGORIES = ["harmful_content", "jailbreak", "prompt_injection", "backdoor"]

# Llama Guard 3 / MLCommons hazard taxonomy. Used for violated_categories.
HAZARD_CODES = {
    "S1": "Violent Crimes",
    "S2": "Non-Violent Crimes",
    "S3": "Sex-Related Crimes",
    "S4": "Child Sexual Exploitation",
    "S5": "Defamation",
    "S6": "Specialized Advice",
    "S7": "Privacy",
    "S8": "Intellectual Property",
    "S9": "Indiscriminate Weapons",
    "S10": "Hate",
    "S11": "Suicide & Self-Harm",
    "S12": "Sexual Content",
    "S13": "Elections",
    "S14": "Code Interpreter Abuse",
}

# Outcome taxonomy (snake_case), mirrored from the hacker autoresearch loop.
OUTCOMES = ["confirmed", "mitigated", "inconclusive", "false_positive", "unsafe_to_test"]

# Map an attempt outcome to a guardrail training label.
# None means the row has no resolved label and is excluded from the default export.
OUTCOME_TO_LABEL = {
    "confirmed": "unsafe",
    "mitigated": "safe",
    "false_positive": "safe",
    "inconclusive": None,
    "unsafe_to_test": None,
}

SEVERITIES = ["none", "low", "medium", "high", "critical"]


def new_id() -> str:
    return uuid.uuid4().hex


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def label_for_outcome(outcome: str) -> str | None:
    return OUTCOME_TO_LABEL.get(outcome)


@dataclass
class Attempt:
    """One judged attack turn. Each PAIR turn is recorded as its own row."""

    run_id: str
    round: int
    cycle: int
    turn: int
    category: str
    technique: str
    hypothesis: str
    provider: str
    target_model: str
    attacker_model: str
    judge_model: str
    messages: list[dict]
    prompt: str
    response: str
    outcome: str
    label: str | None
    violated_categories: list[str]
    attack_success: bool
    severity: str
    judge_rationale: str
    novelty_score: float
    hypothesis_id: str
    seed_parent_id: str | None = None
    id: str = field(default_factory=new_id)
    schema_version: int = SCHEMA_VERSION
    timestamp: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class JsonlWriter:
    """Thread-safe append-only JSONL writer. Records every attempt."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._fh = self.path.open("a", encoding="utf-8")

    def write(self, record: dict | Attempt) -> None:
        if isinstance(record, Attempt):
            record = record.to_dict()
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.close()
