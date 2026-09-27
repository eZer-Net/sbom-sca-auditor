import subprocess
import sys
import unittest
from pathlib import Path


class EntryPointTests(unittest.TestCase):
    def test_python_entrypoint_help_is_small(self):
        root = Path(__file__).resolve().parents[1]
        cp = subprocess.run(
            [sys.executable, str(root / "sbom_auditor.py"), "--help"],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("--severity", cp.stdout)
        self.assertIn("--trivy-db-update", cp.stdout)
        self.assertIn("--output", cp.stdout)
        self.assertNotIn("--include-private", cp.stdout)
        self.assertNotIn("--detect-only", cp.stdout)
        self.assertNotIn("--no-install", cp.stdout)
        self.assertNotIn("--scan-dir", cp.stdout)

    def test_legacy_python_entrypoint_still_works(self):
        root = Path(__file__).resolve().parents[1]
        cp = subprocess.run(
            [sys.executable, str(root / "sbom_macos.py"), "--help"],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("--severity", cp.stdout)


if __name__ == "__main__":
    unittest.main()
