import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harsieve.cli import main
from harsieve.core import HarError
from harsieve.demo import capture
from harsieve.io import load, write_bundle


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source.har"
        self.source.write_text(json.dumps(capture()), encoding="utf-8")

    def run_cli(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(args)
        return code, out.getvalue(), err.getvalue()

    def test_clean_bundle(self):
        original = self.source.read_bytes()
        output = self.root / "bundle"
        code, out, err = self.run_cli(["clean", str(self.source), "-o", str(output)])
        self.assertEqual(code, 0, err)
        self.assertEqual(original, self.source.read_bytes())
        self.assertEqual(
            {p.name for p in output.iterdir()}, {"capture.har", "audit.json", "report.html"}
        )
        for p in output.iterdir():
            self.assertNotIn("DEMO_SECRET", p.read_text(encoding="utf-8"))
        self.assertNotIn(str(self.source), out + err)

    def test_demo(self):
        code, _, err = self.run_cli(["demo", "-o", str(self.root / "demo")])
        self.assertEqual(code, 0, err)

    def test_summary_json(self):
        code, out, err = self.run_cli(["summary", str(self.source)])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["requests"], 12)

    def test_fail_on_http_errors_writes_bundle(self):
        output = self.root / "bundle"
        code, _, _ = self.run_cli(
            ["clean", str(self.source), "-o", str(output), "--fail-on-http-errors"]
        )
        self.assertEqual(code, 1)
        self.assertTrue((output / "report.html").exists())

    def test_existing_directory_never_overwritten(self):
        output = self.root / "existing"
        output.mkdir()
        sentinel = output / "capture.har"
        sentinel.write_text("KEEP", encoding="utf-8")
        code, _, _ = self.run_cli(["clean", str(self.source), "-o", str(output)])
        self.assertEqual(code, 2)
        self.assertEqual(sentinel.read_text(), "KEEP")

    def test_input_cannot_be_output(self):
        original = self.source.read_bytes()
        code, _, _ = self.run_cli(["clean", str(self.source), "-o", str(self.source)])
        self.assertEqual(code, 2)
        self.assertEqual(self.source.read_bytes(), original)

    def test_invalid_input_creates_no_destination(self):
        self.source.write_text('{"SECRET":', encoding="utf-8")
        output = self.root / "bad"
        code, out, err = self.run_cli(["clean", str(self.source), "-o", str(output)])
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())
        self.assertNotIn("SECRET", out + err)

    def test_missing_file_does_not_echo_path(self):
        code, out, err = self.run_cli(["summary", str(self.root / "SECRET_FILENAME")])
        self.assertEqual(code, 2)
        self.assertNotIn("SECRET_FILENAME", out + err)

    def test_duplicate_keys_rejected(self):
        self.source.write_text('{"log": {}, "log": {"SECRET": 1}}')
        with self.assertRaises(HarError):
            load(self.source)

    def test_nonfinite_and_deep_json_rejected(self):
        for text in ('{"value":NaN}', '{"value":Infinity}', "[" * 2000 + "]" * 2000):
            self.source.write_text(text)
            with self.subTest(text=text[:30]), self.assertRaises(HarError):
                load(self.source)

    def test_utf8_bom_accepted(self):
        self.source.write_bytes(b"\xef\xbb\xbf" + json.dumps(capture()).encode())
        self.assertEqual(len(load(self.source)["log"]["entries"]), 12)

    def test_invalid_utf8_rejected(self):
        self.source.write_bytes(b"\xff")
        with self.assertRaises(HarError):
            load(self.source)

    def test_file_limit_enforced(self):
        with patch("harsieve.io.MAX_BYTES", 10), self.assertRaises(HarError):
            load(self.source)

    def test_write_failure_removes_partial_bundle(self):
        output = self.root / "failure"
        with patch("os.fsync", side_effect=OSError("disk full")), self.assertRaises(HarError):
            write_bundle(output, {"capture.har": "{}"})
        self.assertFalse(output.exists())

    def test_new_directory_permissions_posix(self):
        import os

        if os.name == "nt":
            self.skipTest("POSIX permission bits")
        output = self.root / "mode"
        write_bundle(output, {"capture.har": "{}"})
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)

    def test_bundle_rejects_path_traversal(self):
        output = self.root / "bundle"
        with self.assertRaises(HarError):
            write_bundle(output, {"../escape": "no"})
        self.assertFalse(output.exists())

    def test_parse_error_never_quotes_invalid_values(self):
        raw = capture()
        raw["log"]["entries"][0]["request"]["url"] = "SECRET_INVALID_URL"
        self.source.write_text(json.dumps(raw))
        code, out, err = self.run_cli(["summary", str(self.source)])
        self.assertEqual(code, 2)
        self.assertNotIn("SECRET_INVALID_URL", out + err)
