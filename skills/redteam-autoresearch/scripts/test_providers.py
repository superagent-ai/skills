#!/usr/bin/env python3
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from providers import combined_response_text, load_env_files, message_content_parts, resolve_endpoint


class ResolveEndpointTests(unittest.TestCase):
    def test_loads_current_workspace_red_team_env(self):
        key = "REDTEAM_WORKSPACE_ENV_TEST_KEY"
        old_cwd = Path.cwd()
        old_value = os.environ.pop(key, None)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                workspace = Path(tmp)
                env_dir = workspace / ".red-team"
                env_dir.mkdir()
                (env_dir / ".env").write_text(f"{key}=loaded\n", encoding="utf-8")

                os.chdir(workspace)
                load_env_files()

                self.assertEqual(os.environ.get(key), "loaded")
        finally:
            os.chdir(old_cwd)
            os.environ.pop(key, None)
            if old_value is not None:
                os.environ[key] = old_value

    def test_moonshot_provider_uses_named_endpoint(self):
        base_url, api_key_env = resolve_endpoint({"provider": "moonshot", "model": "kimi-k2.6"})

        self.assertEqual(base_url, "https://api.moonshot.ai/v1")
        self.assertEqual(api_key_env, "MOONSHOT_API_KEY")

    def test_fireworks_provider_uses_named_endpoint(self):
        base_url, api_key_env = resolve_endpoint(
            {
                "provider": "fireworks",
                "model": "accounts/fireworks/models/nvidia-nemotron-3-super-120b-a12b-nvfp4",
            }
        )

        self.assertEqual(base_url, "https://api.fireworks.ai/inference/v1")
        self.assertEqual(api_key_env, "FIREWORKS_API_KEY")

    def test_custom_provider_requires_base_url(self):
        with self.assertRaisesRegex(ValueError, "needs a base_url"):
            resolve_endpoint({"provider": "custom", "model": "provider-model"})

    def test_custom_provider_honors_api_key_env(self):
        base_url, api_key_env = resolve_endpoint(
            {
                "provider": "custom",
                "base_url": "https://example-provider.test/v1",
                "api_key_env": "EXAMPLE_PROVIDER_API_KEY",
                "model": "provider-model",
            }
        )

        self.assertEqual(base_url, "https://example-provider.test/v1")
        self.assertEqual(api_key_env, "EXAMPLE_PROVIDER_API_KEY")

    def test_unknown_provider_lists_known_providers(self):
        with self.assertRaisesRegex(ValueError, "Unknown provider 'unknown'"):
            resolve_endpoint({"provider": "unknown", "model": "provider-model"})

    def test_extracts_reasoning_content_from_message(self):
        message = {"content": "visible answer", "reasoning_content": "private leak"}

        content, reasoning = message_content_parts(message)

        self.assertEqual(content, "visible answer")
        self.assertEqual(reasoning, "private leak")

    def test_combines_reasoning_and_visible_content_for_judging(self):
        combined = combined_response_text("visible answer", "private leak")

        self.assertIn("[reasoning]\nprivate leak", combined)
        self.assertIn("[content]\nvisible answer", combined)


if __name__ == "__main__":
    unittest.main()
