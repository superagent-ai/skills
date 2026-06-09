#!/usr/bin/env python3
from __future__ import annotations

import unittest

from query_target import query_one


class FakeTarget:
    provider = "moonshot"
    model = "kimi-k2.6"

    def chat_response(self, messages):
        return {
            "content": "visible answer",
            "reasoning_content": "reasoning leak",
            "response": "[reasoning]\nreasoning leak\n\n[content]\nvisible answer",
        }


class QueryOneTests(unittest.TestCase):
    def test_records_reasoning_and_visible_content(self):
        transcript = query_one({"prompt": "probe"}, FakeTarget())

        self.assertEqual(transcript["assistant_content"], "visible answer")
        self.assertEqual(transcript["reasoning_content"], "reasoning leak")
        self.assertIn("reasoning leak", transcript["response"])
        self.assertEqual(transcript["messages"][-1]["content"], transcript["response"])


if __name__ == "__main__":
    unittest.main()
