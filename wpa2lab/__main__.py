"""Loopback launcher with authenticated instance detection and readiness polling."""
import argparse
import json
import os
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

import uvicorn

from .app import create_app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--data-dir', type=Path)
    args = parser.parse_args()
    base = args.data_dir or Path(os.environ.get('LOCALAPPDATA', Path.home() / '.local' / 'share')) / 'WPA2RecoveryLabPro'
    base.mkdir(parents=True, exist_ok=True)
    if os.name != 'nt':
        base.chmod(0o700)
    instance_file = base / 'instance.json'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token = secrets.token_urlsafe(32)
    url = 'http://127.0.0.1:8765'
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name == 'nt':
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        # Permit clean restarts through TCP TIME_WAIT, without allowing a second
        # listener on the same address (SO_REUSEPORT is deliberately not used).
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(('127.0.0.1', 8765))
    except OSError:
        sock.close()
        try:
            existing = json.loads(instance_file.read_text(encoding='utf-8'))
            request = urllib.request.Request(url + '/api/session', headers={'X-Lab-Token': existing['token']})
            with opener.open(request, timeout=2) as response:
                if json.load(response).get('status') != 'ok':
                    raise ValueError('Unrecognized server')
            if not args.no_browser:
                webbrowser.open(url + '/#token=' + existing['token'])
            print('Existing laboratory instance is ready.')
            return 0
        except (OSError, ValueError, KeyError):
            print('Port 8765 is occupied or another instance is still starting. Close the conflicting application and retry.', file=sys.stderr)
            return 1
    sock.listen(128)
    sock.setblocking(False)
    server = None

    def stop():
        server.should_exit = True

    app = create_app(base / 'data', token=token, shutdown=stop)
    server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=8765, access_log=False, log_level='warning'))
    # Per-user LocalAppData inherits the user's ACL on Windows. No token is logged.
    fd = os.open(instance_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as file:
        json.dump({'token': token, 'pid': os.getpid()}, file)

    def ready_browser():
        for _ in range(100):
            if server.should_exit:
                return
            try:
                request = urllib.request.Request(url + '/api/session', headers={'X-Lab-Token': token})
                with opener.open(request, timeout=0.4) as response:
                    if response.status == 200:
                        if not args.no_browser:
                            webbrowser.open(url + '/#token=' + token)
                        print('WPA2 Recovery Lab Pro ready at ' + url, flush=True)
                        return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.1)
        print('Backend did not become ready; stopping.', file=sys.stderr)
        server.should_exit = True

    thread = threading.Thread(target=ready_browser, daemon=True)
    thread.start()
    try:
        server.run(sockets=[sock])
    finally:
        server.should_exit = True
        thread.join(timeout=2)
        sock.close()
        try:
            if json.loads(instance_file.read_text())['token'] == token:
                instance_file.unlink()
        except (OSError, ValueError, KeyError):
            pass
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
