#!/usr/bin/env python3
from __future__ import annotations

import unittest

from providers import resolve_endpoint


class ResolveEndpointTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
