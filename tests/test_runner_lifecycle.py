"""Cancellation at lifecycle boundaries and bounded output handling."""
import os
from pathlib import Path
import signal
import queue
import threading
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import run_tests as runner


class Lifecycle(unittest.TestCase):
    def test_signal_during_process_creation_is_cleaned_up(self):
        original = subprocess.Popen
        children = []
        def create(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            os.kill(os.getpid(), signal.SIGTERM)
            os.kill(os.getpid(), signal.SIGINT)
            return child
        with runner.interruption_handlers(), patch.object(runner.subprocess, 'Popen', create):
            with self.assertRaises(runner.RunInterrupted):
                with runner.command_process([sys.executable, '-c', 'import time; time.sleep(60)'],
                                            start_new_session=True):
                    self.fail('cancellation was lost')
        self.assertIsNotNone(children[0].poll())

    def test_signal_during_reader_start_is_cleaned_up(self):
        original = runner.threading.Thread.start
        def start(thread):
            original(thread)
            os.kill(os.getpid(), signal.SIGINT)
        with runner.interruption_handlers():
            with runner.command_process([sys.executable, '-c', 'import time; time.sleep(60)'],
                                        start_new_session=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True) as child:
                with patch.object(runner.threading.Thread, 'start', start):
                    with self.assertRaises(runner.RunInterrupted):
                        with runner.output_lines(child):
                            self.fail('cancellation was lost')
                self.assertIsNotNone(child.poll())

    def test_full_queue_can_be_abandoned(self):
        full = threading.Event()
        class ObservedQueue(queue.Queue):
            def put(self, item, *args, **kwargs):
                super().put(item, *args, **kwargs)
                if self.full():
                    full.set()
        with runner.command_process([sys.executable, '-c',
                                     "while True: print('data', flush=True)"],
                                    start_new_session=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True) as child:
            with patch.object(runner.queue, 'Queue', ObservedQueue), runner.output_lines(child) as lines:
                self.assertEqual(next(lines), (True, 'data\n'))
                self.assertTrue(full.wait(timeout=2), 'queue did not reach its capacity')
                # Simulate failure in the consumer, without draining queued lines.
            child.wait(timeout=2)

    def test_oversized_line_is_an_output_error(self):
        with runner.command_process([sys.executable, '-c', "print('x' * 70000)"],
                                    start_new_session=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True) as child:
            with self.assertRaisesRegex(OSError, 'exceeds 65536'):
                with runner.output_lines(child) as lines:
                    list(lines)
