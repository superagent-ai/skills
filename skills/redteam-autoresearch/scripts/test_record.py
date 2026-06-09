#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from record import main
from run_context import write_manifest


class RecordRunDirTests(unittest.TestCase):
    def test_main_defaults_to_run_dir_files_and_manifest_run_id(self):
        old_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                root = Path(tmp)
                os.chdir(root)
                run_dir = Path(".red-team/runs/run-123")
                write_manifest(run_dir, "run-123")
                judged = {
                    "category": "jailbreak",
                    "attack_style": "direct",
                    "prompt": "probe",
                    "response": "safe refusal",
                    "messages": [{"role": "user", "content": "probe"}],
                    "provider": "moonshot",
                    "target_model": "kimi-k2.6",
                    "outcome": "mitigated",
                    "violated_categories": [],
                    "severity": "none",
                    "judge_rationale": "Refused.",
                }
                (run_dir / "judged.jsonl").write_text(json.dumps(judged) + "\n", encoding="utf-8")

                code = main(["--run-dir", str(run_dir), "--novelty-backend", "jaccard"])

                self.assertEqual(code, 0)
                row = json.loads((run_dir / "attempts.jsonl").read_text(encoding="utf-8").strip())
                self.assertEqual(row["run_id"], "run-123")
                self.assertEqual(row["label"], "safe")
            finally:
                os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
