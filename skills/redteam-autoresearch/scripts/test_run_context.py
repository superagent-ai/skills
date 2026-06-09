#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from run_context import RUN_DIR_ENV, init_run, resolve_run_context, write_manifest


class RunContextTests(unittest.TestCase):
    def setUp(self):
        self._old_cwd = Path.cwd()

    def tearDown(self):
        os.chdir(self._old_cwd)

    def test_init_run_creates_unique_dirs_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chdir(root)
            config = Path(".red-team/config.yaml")
            config.parent.mkdir()
            config.write_text("target:\n  provider: openrouter\n  model: test\n", encoding="utf-8")
            runs_dir = Path(".red-team/runs")

            first = init_run(config, runs_dir=runs_dir)
            second = init_run(config, runs_dir=runs_dir)

            self.assertNotEqual(first.run_dir, second.run_dir)
            self.assertTrue((first.run_dir / "config.yaml").exists())
            manifest = json.loads((first.run_dir / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["run_id"], first.run_id)
            self.assertEqual(manifest["source_config"], str(config))

    def test_resolve_prefers_explicit_run_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chdir(root)
            run_dir = Path(".red-team/runs/explicit")
            ctx = resolve_run_context({"run": {"dir": "ignored"}}, run_dir, create=True)

            self.assertEqual(ctx.run_dir, run_dir.resolve())
            self.assertTrue(run_dir.exists())

    def test_resolve_uses_env_before_config(self):
        old = os.environ.get(RUN_DIR_ENV)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                os.chdir(root)
                env_dir = Path(".red-team/runs/env")
                os.environ[RUN_DIR_ENV] = str(env_dir)

                ctx = resolve_run_context({"run": {"dir": ".red-team/runs/config"}}, create=True)

                self.assertEqual(ctx.run_dir, env_dir.resolve())
        finally:
            if old is None:
                os.environ.pop(RUN_DIR_ENV, None)
            else:
                os.environ[RUN_DIR_ENV] = old

    def test_run_id_comes_from_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chdir(root)
            run_dir = Path(".red-team/runs/run")
            write_manifest(run_dir, "manifest-id")

            ctx = resolve_run_context(run_dir=run_dir)

            self.assertEqual(ctx.run_id, "manifest-id")

    def test_init_run_rejects_traversal_run_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chdir(root)
            config = Path(".red-team/config.yaml")
            config.parent.mkdir()
            config.write_text("target:\n  provider: openrouter\n  model: test\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "run_id"):
                init_run(config, run_id="../escape")

    def test_resolve_rejects_run_dir_outside_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chdir(root)

            with self.assertRaisesRegex(ValueError, "run_dir"):
                resolve_run_context(run_dir=root / "outside", create=True)


if __name__ == "__main__":
    unittest.main()
