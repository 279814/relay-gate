#!/usr/bin/env python3
"""Resource measurements must fail closed instead of fabricating a passing soak."""
import importlib.util
import pathlib
import tempfile
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('duration', pathlib.Path(__file__).with_name('verify-duration.py'))
duration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(duration)


class LinuxResourceContract(unittest.TestCase):
    def fixture(self, root):
        process = root / '123'
        process.mkdir()
        (process / 'fd').mkdir()
        for name in ('0', '1'):
            (process / 'fd' / name).touch()
        fields = ['0'] * 22
        fields[0], fields[11], fields[12], fields[19] = 'S', '120', '30', '98765'
        (process / 'stat').write_text('123 (worker (with spaces)) ' + ' '.join(fields))
        (process / 'status').write_text('Name:\tfixture\nVmRSS:\t1024 kB\nThreads:\t3\n')
        (process / 'smaps').write_text('Shared_Clean: 100 kB\nPrivate_Clean: 2 kB\nPrivate_Dirty: 3 kB\n')
        return process

    def test_measures_rss_private_resident_fds_threads_and_cpu(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.fixture(root)
            with mock.patch.object(duration.os, 'sysconf', return_value=100, create=True):
                result = duration.sample_linux_process(123, time.monotonic(), root)
            self.assertEqual(result['rss_bytes'], 1024 * 1024)
            self.assertEqual(result['private_bytes'], 5 * 1024)
            self.assertEqual(result['handles'], 2)
            self.assertEqual(result['threads'], 3)
            self.assertEqual(result['cpu_seconds'], 1.5)
            self.assertEqual(result['private_bytes_kind'], 'private_resident')

    def test_missing_or_unsupported_measurements_are_errors(self):
        for bad in ('missing_status', 'wrong_rss_unit', 'missing_smaps'):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                process = self.fixture(root)
                if bad == 'missing_status':
                    (process / 'status').unlink()
                elif bad == 'missing_smaps':
                    (process / 'smaps').unlink()
                else:
                    (process / 'status').write_text('VmRSS: 1024 B\nThreads: 3\n')
                with self.assertRaises((OSError, ValueError)):
                    duration.sample_linux_process(123, time.monotonic(), root)

    def test_pid_generation_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            process = self.fixture(root)
            original = pathlib.Path.read_text
            reads = 0

            def changed(path, *args, **kwargs):
                nonlocal reads
                text = original(path, *args, **kwargs)
                if path == process / 'stat':
                    reads += 1
                    if reads == 2:
                        return text.replace('98765', '98766')
                return text

            with mock.patch.object(pathlib.Path, 'read_text', changed):
                with self.assertRaises(RuntimeError):
                    duration.sample_linux_process(123, time.monotonic(), root)


if __name__ == '__main__':
    unittest.main()
