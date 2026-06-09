#!/usr/bin/env python3
"""
Novelty scoring for the red-team loop.

Replaces the naive token-set Jaccard novelty with a semantic measure that can act as a search
fitness signal (curiosity-driven red teaming): a batch full of near-duplicates scores low and
the loop is steered toward genuinely new attack families.

Backends (auto-selected, with graceful fallback so the harness always runs):
  - "st"      : sentence-transformers embeddings (best; install: uv pip install sentence-transformers)
  - "embed"   : an OpenAI-compatible embeddings endpoint (set EMBED_API_KEY / EMBED_BASE_URL /
                EMBED_MODEL, or pass embed_cfg)
  - "jaccard" : token-set Jaccard (no deps; same behavior as the original NoveltyIndex)

score(text) -> 1.0 means unseen/novel; ~0.0 means a near-duplicate of something already seen.
The `novelty_score` field semantics are unchanged.
"""
from __future__ import annotations

import math
import os
import sys
import threading

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from schema import NoveltyIndex  # noqa: E402  (token-Jaccard fallback)

_DEFAULT_ST_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class NoveltyScorer:
    """Semantic novelty with a token-Jaccard fallback. API matches schema.NoveltyIndex."""

    def __init__(self, backend: str = "auto", model: str | None = None, embed_cfg: dict | None = None,
                 quiet: bool = False):
        self._lock = threading.Lock()
        self._vecs: list[list[float]] = []
        self._jaccard: NoveltyIndex | None = None
        self._model = None
        self._client = None
        self._embed_model = None
        self.backend = self._resolve(backend, model, embed_cfg)
        if not quiet:
            print(f"[novelty] backend = {self.backend}", file=sys.stderr)

    # -- backend setup --------------------------------------------------------------------

    def _resolve(self, backend: str, model: str | None, embed_cfg: dict | None) -> str:
        if backend in ("auto", "st"):
            if self._try_st(model):
                return "st"
            if backend == "st":
                print("[novelty] sentence-transformers unavailable; falling back to jaccard",
                      file=sys.stderr)
        if backend == "embed" or (backend == "auto" and embed_cfg):
            if self._try_embed(embed_cfg):
                return "embed"
            if backend == "embed":
                print("[novelty] embeddings endpoint unavailable; falling back to jaccard",
                      file=sys.stderr)
        self._jaccard = NoveltyIndex()
        return "jaccard"

    def _try_st(self, model: str | None) -> bool:
        try:
            from sentence_transformers import SentenceTransformer
        except Exception:
            return False
        try:
            self._model = SentenceTransformer(model or _DEFAULT_ST_MODEL)
            return True
        except Exception as exc:  # pragma: no cover - model download/load failure
            print(f"[novelty] sentence-transformers load failed: {exc}", file=sys.stderr)
            return False

    def _try_embed(self, embed_cfg: dict | None) -> bool:
        cfg = embed_cfg or {}
        api_key = os.environ.get(cfg.get("api_key_env", "EMBED_API_KEY"))
        base_url = cfg.get("base_url") or os.environ.get("EMBED_BASE_URL")
        self._embed_model = cfg.get("model") or os.environ.get("EMBED_MODEL")
        if not (api_key and self._embed_model):
            return False
        try:
            from openai import OpenAI
            self._client = OpenAI(api_key=api_key, base_url=base_url)
            return True
        except Exception:
            return False

    # -- embedding ------------------------------------------------------------------------

    def _embed(self, text: str) -> list[float] | None:
        if self.backend == "st":
            vec = self._model.encode(text, normalize_embeddings=True)
            return vec.tolist() if hasattr(vec, "tolist") else list(vec)
        if self.backend == "embed":
            try:
                resp = self._client.embeddings.create(model=self._embed_model, input=text[:8000])
                return list(resp.data[0].embedding)
            except Exception as exc:  # pragma: no cover
                print(f"[novelty] embed call failed: {exc}", file=sys.stderr)
                return None
        return None

    # -- public API (matches NoveltyIndex) ------------------------------------------------

    def score(self, text: str) -> float:
        if self.backend == "jaccard":
            return self._jaccard.score(text)
        if not (text or "").strip():
            return 0.0
        vec = self._embed(text)
        if vec is None:
            return 1.0
        with self._lock:
            best = max((_cosine(vec, prev) for prev in self._vecs), default=0.0)
        return round(1.0 - max(0.0, best), 4)

    def add(self, text: str) -> None:
        if self.backend == "jaccard":
            self._jaccard.add(text)
            return
        if not (text or "").strip():
            return
        vec = self._embed(text)
        if vec is not None:
            with self._lock:
                self._vecs.append(vec)

    def seed(self, texts) -> int:
        n = 0
        for t in texts:
            if t:
                self.add(t)
                n += 1
        return n
