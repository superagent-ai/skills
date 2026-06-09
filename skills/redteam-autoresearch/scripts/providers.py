#!/usr/bin/env python3
"""
Provider-agnostic, OpenAI-compatible model client for the red-team autoresearch harness.

Default provider is OpenRouter (one OPENROUTER_API_KEY, models selected by id). Named
OpenAI-compatible providers are available by setting provider/model, and any other
compatible endpoint works by setting provider/base_url/api_key_env in the per-role
config. API keys are read from the run workspace's .red-team/.env, a skill-local
.red-team/.env, or a legacy .env via python-dotenv.

This module only issues chat-completion requests to the configured endpoints; no data
leaves them.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent

def load_env_files() -> None:
    """Load target provider keys without overriding already-exported env vars."""
    load_dotenv(Path.cwd() / ".red-team" / ".env", override=False)
    load_dotenv(SKILL_DIR / ".red-team" / ".env", override=False)
    load_dotenv(override=False)
    load_dotenv(SKILL_DIR / ".env", override=False)


load_env_files()

PROVIDERS = {
    "openrouter": {"base_url": "https://openrouter.ai/api/v1", "api_key_env": "OPENROUTER_API_KEY"},
    "ubicloud": {"base_url": None, "api_key_env": "UBICLOUD_API_KEY"},  # base_url is per-model
    "openai": {"base_url": "https://api.openai.com/v1", "api_key_env": "OPENAI_API_KEY"},
    "moonshot": {"base_url": "https://api.moonshot.ai/v1", "api_key_env": "MOONSHOT_API_KEY"},
    "fireworks": {
        "base_url": "https://api.fireworks.ai/inference/v1",
        "api_key_env": "FIREWORKS_API_KEY",
    },
    "custom": {"base_url": None, "api_key_env": "OPENAI_API_KEY"},
}


class MissingApiKey(RuntimeError):
    """Raised when the env var for a role's API key is not set."""


def _message_field(message, name: str):
    if isinstance(message, dict):
        return message.get(name)
    value = getattr(message, name, None)
    if value is None and hasattr(message, "model_extra"):
        value = message.model_extra.get(name)
    return value


def _content_to_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                parts.append(str(item.get("text") or item.get("content") or ""))
            else:
                parts.append(str(item))
        return "".join(parts)
    return str(value)


def message_content_parts(message) -> tuple[str, str]:
    """Return (assistant content, reasoning content) from an OpenAI-compatible message."""
    content = _content_to_text(_message_field(message, "content")).strip()
    reasoning = _content_to_text(_message_field(message, "reasoning_content")).strip()
    return content, reasoning


def combined_response_text(content: str, reasoning_content: str) -> str:
    """Return the text judges should inspect, including hidden/provider reasoning if present."""
    parts = []
    if reasoning_content:
        parts.append(f"[reasoning]\n{reasoning_content}")
    if content:
        parts.append(f"[content]\n{content}")
    return "\n\n".join(parts).strip()


def resolve_endpoint(role_cfg: dict) -> tuple[str, str]:
    """Return (base_url, api_key_env) for a role config."""
    provider = role_cfg.get("provider", "openrouter")
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider '{provider}'. Known: {list(PROVIDERS)}")
    defaults = PROVIDERS[provider]
    base_url = role_cfg.get("base_url") or defaults["base_url"]
    model = role_cfg.get("model")
    if provider == "ubicloud" and not base_url:
        if not model:
            raise ValueError("ubicloud role needs a 'model' to build its base_url")
        base_url = f"https://{model}.ai.ubicloud.com/v1"
    if not base_url:
        raise ValueError(f"role for provider '{provider}' needs a base_url")
    api_key_env = role_cfg.get("api_key_env") or defaults["api_key_env"]
    return base_url, api_key_env


class RateLimiter:
    """Thread-safe token bucket shared across all model calls (requests per minute)."""

    def __init__(self, rate_per_min: float):
        self.rate = max(float(rate_per_min), 0.0)
        self._lock = threading.Lock()
        self._allowance = self.rate
        self._last = time.monotonic()

    def acquire(self) -> None:
        if self.rate <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                self._allowance = min(
                    self.rate, self._allowance + (now - self._last) * (self.rate / 60.0)
                )
                self._last = now
                if self._allowance >= 1.0:
                    self._allowance -= 1.0
                    return
                deficit = 1.0 - self._allowance
                sleep_for = deficit * (60.0 / self.rate)
            time.sleep(sleep_for)


class ModelClient:
    """Wraps an OpenAI-compatible client for the target model under test."""

    def __init__(self, role_cfg: dict, limiter: RateLimiter | None = None, label: str = ""):
        self.label = label or role_cfg.get("model", "model")
        self.provider = role_cfg.get("provider", "openrouter")
        self.model = role_cfg.get("model")
        if not self.model:
            raise ValueError(f"role '{self.label}' is missing a 'model'")
        self.temperature = float(role_cfg.get("temperature", 0.7))
        self.max_tokens = int(role_cfg.get("max_tokens", 1024))
        self.system = role_cfg.get("system")
        self._limiter = limiter

        base_url, api_key_env = resolve_endpoint(role_cfg)
        api_key = os.environ.get(api_key_env)
        if not api_key:
            raise MissingApiKey(
                f"Env var {api_key_env} is not set. Add it to .red-team/.env "
                f"(see scripts/.env.example) for role '{self.label}'."
            )
        headers = {"X-Title": "redteam-autoresearch"} if self.provider == "openrouter" else None
        self._client = OpenAI(api_key=api_key, base_url=base_url, default_headers=headers)

    @retry(reraise=True, stop=stop_after_attempt(4),
           wait=wait_exponential(multiplier=1, min=2, max=30))
    def _create(self, messages, temperature, max_tokens):
        return self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def chat_response(self, messages, temperature=None, max_tokens=None, system=None) -> dict:
        """Send a chat completion and return content plus any provider reasoning text."""
        if self._limiter:
            self._limiter.acquire()
        sys_prompt = system if system is not None else self.system
        if sys_prompt:
            messages = [{"role": "system", "content": sys_prompt}] + list(messages)
        resp = self._create(
            messages,
            self.temperature if temperature is None else temperature,
            self.max_tokens if max_tokens is None else max_tokens,
        )
        if not resp.choices:
            return {"content": "", "reasoning_content": "", "response": ""}
        content, reasoning_content = message_content_parts(resp.choices[0].message)
        response = combined_response_text(content, reasoning_content) or content or reasoning_content
        return {
            "content": content,
            "reasoning_content": reasoning_content,
            "response": response,
        }

    def chat(self, messages, temperature=None, max_tokens=None, system=None) -> str:
        """Send a chat completion and return judge-visible assistant text."""
        return self.chat_response(messages, temperature, max_tokens, system)["response"]
