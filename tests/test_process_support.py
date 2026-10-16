"""Exercise the shared timeout path with a real stalled process tree."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from process_support import run_command


class ProcessSupport(unittest.TestCase):
    def test_timeout_reaps_command_with_inherited_pipe_writer(self):
        with tempfile.TemporaryDirectory() as temp:
            pid = Path(temp) / 'pid'
            child = (
                "import os, pathlib, signal, subprocess, sys, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(pid)!r}).write_text(str(os.getpid())); "
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
                "print('ready', flush=True); time.sleep(60)"
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                run_command([sys.executable, '-c', child], capture_output=True,
                            text=True, timeout=1)
            self.assertTrue(pid.exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid.read_text()), 0)
