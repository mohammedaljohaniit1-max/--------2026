"""Installation regression tests: disposable files only, no system changes or target scans."""
import contextlib
import io
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import burhan as b

ROOT = Path(__file__).resolve().parent


class FilesystemTests(unittest.TestCase):
    def test_private_probe_cleans_up_and_preserves_existing_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix='installation with spaces ') as td:
            sentinel = Path(td)/'keep.txt'
            sentinel.write_text('existing user data')
            sentinel.chmod(0o640)
            with patch.object(socket, 'create_connection') as connect:
                result = b.filesystem_preflight(td)
            connect.assert_not_called()
            self.assertEqual(result['filesystem_probe'], 'passed')
            self.assertEqual(list(Path(td).iterdir()), [sentinel])
            self.assertEqual(sentinel.read_text(), 'existing user data')
            self.assertEqual(sentinel.stat().st_mode & 0o777, 0o640)

    def test_windows_mount_rejected_before_any_write(self):
        for name in ['/mnt/c/Users/test/app', '/mnt/D/app']:
            with self.subTest(name=name), patch.object(Path, 'resolve', return_value=Path(name)), patch.object(Path, 'is_dir', return_value=True), patch.object(b.tempfile, 'TemporaryDirectory') as temporary:
                with self.assertRaisesRegex(b.GuardError, 'Windows-mounted'):
                    b.filesystem_preflight(name)
                temporary.assert_not_called()

    def test_chmod_failure_is_actionable_and_clean(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            with patch.object(Path, 'chmod', side_effect=PermissionError('fixture chmod denied')):
                with self.assertRaisesRegex(b.GuardError, 'PermissionError'):
                    b.filesystem_preflight(td)
            self.assertEqual(list(Path(td).iterdir()), [])

    def test_symlink_failure_is_actionable_and_clean(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            with patch.object(Path, 'symlink_to', side_effect=OSError('fixture symlink denied')):
                with self.assertRaisesRegex(b.GuardError, 'filesystem preflight failed'):
                    b.filesystem_preflight(td)
            self.assertEqual(list(Path(td).iterdir()), [])

    def test_noexec_failure_is_actionable_and_clean(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            with patch.object(b.subprocess, 'run', side_effect=PermissionError('fixture noexec')):
                with self.assertRaisesRegex(b.GuardError, 'PermissionError'):
                    b.filesystem_preflight(td)
            self.assertEqual(list(Path(td).iterdir()), [])

    def test_rename_failure_cleans_up(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            with patch.object(Path, 'replace', side_effect=OSError('fixture rename denied')):
                with self.assertRaises(b.GuardError):
                    b.filesystem_preflight(td)
            self.assertEqual(list(Path(td).iterdir()), [])

    def test_filesystem_ignoring_private_modes_rejected(self):
        original_chmod = Path.chmod
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            with patch.object(Path, 'chmod', autospec=True, side_effect=lambda path, mode: original_chmod(path, 0o755)):
                with self.assertRaisesRegex(b.GuardError, 'private directory permissions'):
                    b.filesystem_preflight(td)
            self.assertEqual(list(Path(td).iterdir()), [])

    def test_cli_preflight_is_offline(self):
        with patch.object(socket, 'create_connection') as connect, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(b.main(['preflight']), 0)
        connect.assert_not_called()


class SetupShellTests(unittest.TestCase):
    def fixture_files(self, directory, preflight_code=0):
        root = Path(directory)
        shutil.copy2(ROOT/'setup.sh', root/'setup.sh')
        (root/'burhan.py').write_text('import sys\nfrom pathlib import Path\nwith Path("calls.log").open("a") as f: f.write(sys.argv[1]+"\\n")\nif sys.argv[1]=="preflight": raise SystemExit(' + str(preflight_code) + ')\n')
        (root/'verify.sh').write_text('#!/bin/sh\necho SHOULD_NOT_RUN\nexit 77\n')
        return root

    def test_failed_preflight_stops_before_environment_creation(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = self.fixture_files(td, preflight_code=17)
            result = subprocess.run(['bash', str(root/'setup.sh')], cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 17)
            self.assertFalse((root/'.venv').exists())
            self.assertEqual((root/'calls.log').read_text(), 'preflight\n')
            self.assertIn('No scan was started', result.stderr)
            self.assertNotIn('SHOULD_NOT_RUN', result.stdout)

    def test_check_mode_does_not_create_environment(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = self.fixture_files(td)
            result = subprocess.run(['bash', str(root/'setup.sh'), '--check'], cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root/'.venv').exists())
            self.assertEqual((root/'calls.log').read_text(), 'preflight\ndoctor\n')

    def test_incomplete_environment_is_preserved(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = self.fixture_files(td)
            (root/'.venv').mkdir()
            (root/'.venv'/'user-file').write_text('keep')
            result = subprocess.run(['bash', str(root/'setup.sh')], cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1)
            self.assertIn('incomplete', result.stderr)
            self.assertEqual((root/'.venv'/'user-file').read_text(), 'keep')

    def test_symlink_environment_rejected_without_modifying_target(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = self.fixture_files(td)
            other = root/'other'
            other.mkdir()
            (root/'.venv').symlink_to(other, target_is_directory=True)
            result = subprocess.run(['bash', str(root/'setup.sh')], cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1)
            self.assertIn('symbolic link', result.stderr)
            self.assertEqual(list(other.iterdir()), [])

    def test_unknown_arguments_do_not_run_preflight(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = self.fixture_files(td)
            result = subprocess.run(['bash', str(root/'setup.sh'), '--check', '--extra'], cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1)
            self.assertFalse((root/'calls.log').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
