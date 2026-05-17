#!/usr/bin/env python3
"""Local WebDAV test server for pwsafe transport tests.

Usage:
    python3 webdav_test_server.py <port> <root_dir>

Starts a wsgidav server on 127.0.0.1:<port> serving <root_dir> with
anonymous write access and full WebDAV class 2 (locking) support.

Prints "READY" to stdout when the port accepts connections.
Exits cleanly on SIGTERM or SIGINT.

Pre-seeds <root_dir>/pwsafe_test.psafe3 which suite 2 tests §2 and §4
expect to exist before the test run.

Requires: wsgidav >= 4.0, cheroot >= 9.0
Install: pip install --user --break-system-packages wsgidav cheroot
"""

import os
import signal
import socket
import sys
import threading
import time

from wsgidav.wsgidav_app import WsgiDAVApp
from cheroot import wsgi as cheroot_wsgi


def seed_files(root_dir: str) -> None:
    """Pre-seed test fixtures that the tests expect to exist."""
    seed = os.path.join(root_dir, "pwsafe_test.psafe3")
    if not os.path.exists(seed):
        with open(seed, "wb") as f:
            f.write(b"PWS3seed-for-webdav-tests")


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Return True once the port accepts TCP connections, False on timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=0.2)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <port> <root_dir>", file=sys.stderr)
        sys.exit(1)

    try:
        port = int(sys.argv[1])
    except ValueError:
        print(f"ERROR: port must be an integer, got {sys.argv[1]!r}", file=sys.stderr)
        sys.exit(1)

    root_dir = sys.argv[2]
    os.makedirs(root_dir, exist_ok=True)
    seed_files(root_dir)

    config = {
        "provider_mapping": {"/": root_dir},
        # Allow anonymous read/write access to all paths.
        "http_authenticator": {
            "accept_basic": False,
            "accept_digest": False,
            "default_to_digest": False,
            "trusted_auth_header": None,
        },
        "simple_dc": {
            "user_mapping": {"*": True},
        },
        "verbose": 0,
        "logging": {"enable_loggers": []},
    }

    app = WsgiDAVApp(config)
    server = cheroot_wsgi.Server(("127.0.0.1", port), app)

    def shutdown(signum, frame):
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Start server in a daemon thread so the main thread can signal READY.
    t = threading.Thread(target=server.start, daemon=True)
    t.start()

    if wait_for_port("127.0.0.1", port):
        print("READY", flush=True)
    else:
        print("ERROR: server did not bind in time", file=sys.stderr, flush=True)
        server.stop()
        sys.exit(1)

    # Block until the server thread exits (SIGTERM triggers shutdown above).
    t.join()


if __name__ == "__main__":
    main()
