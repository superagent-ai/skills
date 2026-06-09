#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from query_target import main, query_one


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

    def test_main_defaults_to_run_dir_files(self):
        old_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                root = Path(tmp)
                os.chdir(root)
                run_dir = Path(".red-team/runs/test")
                run_dir.mkdir(parents=True)
                (run_dir / "config.yaml").write_text(
                    "target:\n  provider: moonshot\n  model: kimi-k2.6\nrun:\n  concurrency: 1\n",
                    encoding="utf-8",
                )
                (run_dir / "attacks.jsonl").write_text('{"prompt": "probe"}\n', encoding="utf-8")

                with patch("query_target.build_targets", return_value=[FakeTarget()]):
                    code = main(["--run-dir", str(run_dir), "--rate-limit", "0"])

                self.assertEqual(code, 0)
                rows = [
                    json.loads(line)
                    for line in (run_dir / "transcripts.jsonl").read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["reasoning_content"], "reasoning leak")
            finally:
                os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
