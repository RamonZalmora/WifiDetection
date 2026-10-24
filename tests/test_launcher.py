"""Actual subprocess and TCP checks; runs on Linux and Windows, no WiFi mocks."""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def launch(directory):
    return subprocess.Popen([sys.executable, '-m', 'wpa2lab', '--no-browser', '--data-dir', str(directory)],
                            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def test_live_startup_existing_instance_and_shutdown(tmp_path):
    process = launch(tmp_path)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        instance = tmp_path / 'instance.json'
        token = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert process.poll() is None, process.communicate()
            try:
                token = json.loads(instance.read_text())['token']
                request = urllib.request.Request('http://127.0.0.1:8765/api/session', headers={'X-Lab-Token': token})
                with opener.open(request, timeout=0.3) as response:
                    assert json.load(response)['status'] == 'ok'
                    break
            except (OSError, ValueError, KeyError):
                time.sleep(0.05)
        else:
            raise AssertionError('Server readiness timed out')
        duplicate = launch(tmp_path)
        out, err = duplicate.communicate(timeout=10)
        assert duplicate.returncode == 0, err
        assert 'Existing laboratory instance is ready' in out
        assert token not in out + err
        request = urllib.request.Request('http://127.0.0.1:8765/api/shutdown', data=b'{}',
                                         headers={'X-Lab-Token': token, 'Content-Type': 'application/json'})
        with opener.open(request, timeout=3) as response:
            assert json.load(response)['status'] == 'shutting down'
        out, err = process.communicate(timeout=10)
        assert process.returncode == 0, err
        assert token not in out + err
        assert not instance.exists()
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=10)


def test_live_port_conflict(tmp_path):
    with socket.socket() as blocker:
        if os.name == 'nt':
            blocker.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(('127.0.0.1', 8765))
        blocker.listen(1)
        process = launch(tmp_path)
        out, err = process.communicate(timeout=10)
        assert process.returncode == 1
        assert 'Port 8765 is occupied' in err
