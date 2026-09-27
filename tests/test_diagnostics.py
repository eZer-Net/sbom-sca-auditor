import tempfile
import unittest
from pathlib import Path

from sbom_builder.diagnostics import diagnose_log


class DiagnosticsTests(unittest.TestCase):
    def test_host_key_failure_is_classified(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "scan.log"
            log.write_text(
                "Arguments: ls-remote --tags --heads ssh://git@bitbucket.example.local:7999/team/lib.git\n"
                "Host key verification failed.\n"
                "fatal: Could not read from remote repository.\n",
                encoding="utf-8",
            )
            d = diagnose_log(log)
            self.assertIsNotNone(d)
            self.assertEqual(d.code, "PRIVATE_GIT_SSH_HOST_KEY")
            self.assertIn("7999", d.hint or "")
            self.assertIn("bitbucket.example.local", d.hint or "")


if __name__ == "__main__":
    unittest.main()
