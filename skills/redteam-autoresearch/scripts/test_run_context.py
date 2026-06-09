#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from run_context import RUN_DIR_ENV, init_run, resolve_run_context, write_manifest


class RunContextTests(unittest.TestCase):
    def test_init_run_creates_unique_dirs_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "config.yaml"
            config.write_text("target:\n  provider: openrouter\n  model: test\n", encoding="utf-8")
            runs_dir = root / "runs"

            first = init_run(config, runs_dir=runs_dir)
            second = init_run(config, runs_dir=runs_dir)

            self.assertNotEqual(first.run_dir, second.run_dir)
            self.assertTrue((first.run_dir / "config.yaml").exists())
            manifest = json.loads((first.run_dir / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["run_id"], first.run_id)
            self.assertEqual(manifest["source_config"], str(config))

    def test_resolve_prefers_explicit_run_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "explicit"
            ctx = resolve_run_context({"run": {"dir": "ignored"}}, run_dir, create=True)

            self.assertEqual(ctx.run_dir, run_dir)
            self.assertTrue(run_dir.exists())

    def test_resolve_uses_env_before_config(self):
        old = os.environ.get(RUN_DIR_ENV)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                env_dir = Path(tmp) / "env"
                os.environ[RUN_DIR_ENV] = str(env_dir)

                ctx = resolve_run_context({"run": {"dir": str(Path(tmp) / "config")}}, create=True)

                self.assertEqual(ctx.run_dir, env_dir)
        finally:
            if old is None:
                os.environ.pop(RUN_DIR_ENV, None)
            else:
                os.environ[RUN_DIR_ENV] = old

    def test_run_id_comes_from_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            write_manifest(run_dir, "manifest-id")

            ctx = resolve_run_context(run_dir=run_dir)

            self.assertEqual(ctx.run_id, "manifest-id")


if __name__ == "__main__":
    unittest.main()
