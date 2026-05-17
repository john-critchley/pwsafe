#!/usr/bin/env bash
# run_local_webdav_tests.sh
# -------------------------
# Start a local wsgidav WebDAV server, run transport suites 2 and 3
# against it, then tear the server down.
#
# Invoked by:
#   make -f Makefile.transport-tests local-live
#
# Requirements:
#   - build/ containing pwsafe-https.so (and pwsafe-http.so → symlink to it)
#   - /tmp/transport_webdav_test and /tmp/transport_lock_lifecycle_test compiled
#     (Makefile.transport-tests build target handles this)
#   - wsgidav + cheroot installed:
#       pip install --user --break-system-packages wsgidav cheroot

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$REPO_ROOT/build"

PORT=18080
ROOT_DIR="$(mktemp -d /tmp/pwsafe_webdav_XXXXXX)"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID"
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$ROOT_DIR"
}
trap cleanup EXIT

# ---- pre-flight checks ----

if ! python3 -c "import wsgidav, cheroot" 2>/dev/null; then
    echo "ERROR: wsgidav or cheroot not installed." >&2
    echo "  pip install --user --break-system-packages wsgidav cheroot" >&2
    exit 1
fi

for f in pwsafe-https.so pwsafe-http.so; do
    if [ ! -f "$BUILD_DIR/$f" ]; then
        echo "ERROR: $BUILD_DIR/$f not found." >&2
        echo "  Run: make -f Makefile.transport-tests build" >&2
        exit 1
    fi
done

for bin in /tmp/transport_webdav_test /tmp/transport_lock_lifecycle_test; do
    if [ ! -x "$bin" ]; then
        echo "ERROR: $bin not found or not executable." >&2
        echo "  Run: make -f Makefile.transport-tests build" >&2
        exit 1
    fi
done

# ---- start local WebDAV server ----

python3 "$SCRIPT_DIR/webdav_test_server.py" "$PORT" "$ROOT_DIR" &
SERVER_PID=$!

echo "Waiting for WebDAV server on port $PORT..."
for i in $(seq 1 50); do
    if curl --silent --head --max-time 0.5 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: WebDAV server exited prematurely (see output above)." >&2
        exit 1
    fi
    sleep 0.2
done

if ! curl --silent --head --max-time 1 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then
    echo "ERROR: WebDAV server did not start in time." >&2
    exit 1
fi

echo "WebDAV server ready at http://127.0.0.1:$PORT"
export PWSAFE_WEBDAV_TEST_URL="http://127.0.0.1:$PORT"

# ---- run suites from the build directory ----

cd "$BUILD_DIR"

echo ""
echo "=== Suite 2: WebDAV plugin  [local: $PWSAFE_WEBDAV_TEST_URL] ==="
/tmp/transport_webdav_test

echo ""
echo "=== Suite 3: Lock lifecycle  [local: $PWSAFE_WEBDAV_TEST_URL] ==="
/tmp/transport_lock_lifecycle_test

echo ""
echo "========================================"
echo "All local-live tests passed."
echo "========================================"
