"""Bounded command execution and cleanup shared by Python integration tests."""
from contextlib import contextmanager
import os
import signal
import subprocess


def signal_group(process, signum):
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass


@contextmanager
def managed_command(command, **kwargs):
    process = subprocess.Popen(command, start_new_session=True, **kwargs)
    try:
        yield process
    finally:
        # Give wrappers a chance to clean up their own isolated test sessions.
        signal_group(process, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        finally:
            signal_group(process, signal.SIGKILL)
            process.communicate(timeout=2)


def run_command(command, *, timeout=40, check=False, capture_output=False, **kwargs):
    if capture_output:
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with managed_command(command, **kwargs) as process:
        stdout, stderr = process.communicate(timeout=timeout)
        result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        if check:
            result.check_returncode()
        return result
