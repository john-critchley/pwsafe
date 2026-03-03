WebDAV Transport Plugin
=======================
This document describes the WebDAV transport plugin added in the `webdav`
branch of this repository.  It covers the plugin architecture, the WebDAV
implementation, how to build and use it, and how to write new plugins.

For a narrative account of the design and implementation process, including
the security audit, see:

[Extending a Password Manager with a Plugin Network Module — And Letting AI Audit It](https://www.linkedin.com/posts/john-critchley_ugcPost-7434194687277686784-cNAJ)


Overview
--------
Password Safe normally stores its database in a local file.  This branch
extends it to support remote storage via HTTP/WebDAV (e.g. Nextcloud,
ownCloud, or a plain Apache/nginx WebDAV share) without touching any of
the cryptographic, record-parsing, or core UI layers.

The design has three principles:

1. **Minimal footprint in the main binary.**  All remote-storage logic lives
   in independently built plugin shared libraries (`.so` / `.dylib`).  The
   main binary gains only a small dispatch layer (~500 lines) that loads and
   calls them.

2. **Local cache as the working file.**  The application always reads and
   writes a local copy; the plugin layer synchronises that copy with the
   remote server on open and save.  Offline use is supported transparently.

3. **No changes to crypto or file format.**  The encrypted `.psafe3` format is
   unchanged.  The plugin layer intercepts at the `pws_os::FOpen` /
   `pws_os::FClose` boundary — below the record layer, above the filesystem.


Architecture: Transport Plugin Layer
-------------------------------------
The transport system consists of three components.

### 1. Plugin interface (`src/os/transport.h`)

A plain C struct for ABI stability:

```c
struct PWSTransport {
    int          abi_version;  /* PWSTransport_ABI_VERSION */
    const char  *scheme;       /* "http", "https", etc. */

    int  (*fetch  )(const char *url, const char *local_path);
    int  (*store  )(const char *local_path, const char *url);
    int  (*exists )(const char *url);
    int  (*lock   )(const char *url, char *token_out, size_t len);
    int  (*unlock )(const char *url, const char *token);
    void (*cleanup)(void);
};
```

Each function returns 0 on success or an `errno` value on failure
(`ENOENT`, `EACCES`, `EBUSY`, `ENOTSUP`, `EIO`, etc.).

### 2. Dispatch layer (`src/os/unix/transport.cpp`)

Compiled into the main binary.  Responsibilities:

- **Plugin discovery** — searches for `pwsafe-<scheme>.so` alongside the
  application binary on first use of a URL with that scheme.
- **Pre-scan security check** — reads the identity string embedded in the
  `.so` (e.g. `PWS_TRANSPORT_INFO:1:https,http:WebDAV transport`) without
  calling `dlopen()`.  Rejects the library if the string is absent or the
  declared scheme doesn't match the filename.
- **Cache path resolver** — maps `https://host/path/db.psafe3` to a
  deterministic local path `~/.pwsafe/cache/<sha256-of-url>.psafe3`.
- **Offline fallback** — if `fetch()` fails and a cache file exists, the
  user is offered the option to open in offline/read-only mode.
- **`FILE*` bridge** — maintains a map from open `FILE*` handles to their
  URL and cache path so that `FClose` knows which URL to call `store()` on.

### 3. Lock daemon (`src/os/unix/transport_lockd.cpp`)

A child process is forked on first use of a URL.  It holds the actual
WebDAV lock token and is responsible for releasing it if the parent
process exits or crashes.

Rationale: WebDAV LOCK tokens are stored in the plugin's own state.  After
`fork()`, the parent and child have independent copies of that state.  If
the lock is obtained in the parent, the child cannot release it (its token
map is empty).  The solution is to perform all lock/unlock/store operations
in the child (the daemon) and have the parent communicate with it over a
pipe using a lightweight binary IPC protocol.

The daemon also handles write-back via `store()` so that the If: header
carrying the lock token is always added by the process that holds the token.


WebDAV Plugin (`src/os/plugins/webdav/transport-webdav.cpp`)
--------------------------------------------------------------
~510 lines; links `libcurl` only.  The main binary has no `libcurl`
dependency.

| Operation | HTTP method          | Notes |
|-----------|----------------------|-------|
| `fetch`   | GET                  | Streams to local cache path |
| `store`   | PUT                  | Streams from local cache path; adds `If: (<token>)` header when a lock is held |
| `exists`  | HEAD                 | Returns `ENOENT` on 404 |
| `lock`    | OPTIONS then LOCK    | Probes for `DAV: 2` or `Allow: LOCK`; falls back to `ENOTSUP` gracefully |
| `unlock`  | UNLOCK               | Uses stored token; errors logged, not propagated |

**Credentials** are read from `~/.netrc` via `CURLOPT_NETRC_OPTIONAL`.
No credential management is needed in pwsafe itself.  Example `~/.netrc`
entry:

```
machine nextcloud.example.com login alice password s3cr3t
```

**TLS** is enabled by default for `https://` URLs.  For self-signed
certificates during development, set `PWSAFE_WEBDAV_SSL_NOVERIFY=1` in
the environment (never use in production).

**Locking behaviour:**
- On open, `OPTIONS` is sent to the resource URL.
- If `DAV: 2` or `Allow: LOCK` is found in the response, a `LOCK` request
  (exclusive write, depth 0, 1-hour timeout) is sent before `GET`.
- If the lock is denied with 423 Locked, `EBUSY` is returned and the open
  is blocked with a conflict message.
- If the server does not advertise locking, the file opens without a lock;
  the user receives a one-time warning.
- On save, the `If: (<token>)` conditional header is included in the `PUT`
  so the server rejects conflicting writes.
- On close (with or without save), `UNLOCK` is sent.


Plugin Identity String
-----------------------
Every plugin must embed a plain-text identity string readable with
`strings(1)`:

```
PWS_TRANSPORT_INFO:<abi>:<scheme[,scheme,...]>:<description>
```

Example:

```
PWS_TRANSPORT_INFO:1:https,http:WebDAV transport
```

The dispatch layer scans for this string before `dlopen()`.  If it is
absent, or the scheme does not match the library filename, the `.so` is
rejected.  This provides a lightweight guard against loading arbitrary
shared libraries from the plugin directory.


Building
---------
The WebDAV plugin is built with CMake.  It requires `libcurl` (development
headers and library).

```sh
cmake -B build -DWITH_WEBDAV=ON
cmake --build build
```

The resulting plugin is `build/src/os/plugins/webdav/pwsafe-https.so` (and
a symlink `pwsafe-http.so`).  Place them in the same directory as the
`pwsafe` binary.

To run the test suite for the transport layer:

```sh
cmake -B build -DWITH_WEBDAV=ON -DWITH_TRANSPORT_TESTS=ON
cmake --build build
ctest --test-dir build -R Transport
```

Tests include:
- `transport_standalone_test` — unit tests for the dispatch layer and
  offline fallback logic (no network required).
- `transport_lock_lifecycle_test` — lock acquire/release/crash-recovery via
  the daemon (no network required; uses the `file:` reference plugin).
- `transport_webdav_test` — integration tests against a real WebDAV server
  (requires `--url https://…` argument; skipped in CI unless configured).


Using WebDAV Databases
-----------------------
Pass an `http://` or `https://` URL anywhere a local file path is accepted:

- **GUI (wxWidgets):** File → Open → type or paste the URL in the file path
  field.
- **Command line:** `pwsafe --passthrough --open https://host/path/db.psafe3`

On first open, pwsafe downloads the database to
`~/.pwsafe/cache/<sha256>.psafe3` and opens that local copy.  On save, the
modified copy is uploaded back to the server.  The local cache is retained
between sessions so that offline use is always possible.


Writing New Plugins
--------------------
See `src/os/plugins/file/transport-file.cpp` for a minimal reference
implementation (~135 lines) that serves as both the template for new
plugins and a test harness for the dispatch layer.

Checklist for a new plugin:

1. Create `src/os/plugins/<name>/transport-<name>.cpp`.
2. Implement all six `PWSTransport` function pointers.
3. Export `extern "C" void pws_plugin_init(pws_register_fn_t reg)` and call
   `reg(&my_transport)` for each scheme.
4. Embed the identity string:
   `static const char kIdent[] = "PWS_TRANSPORT_INFO:1:<scheme>:<desc>";`
5. Name the output library `pwsafe-<primary-scheme>.so` (or `.dylib`).
   Symlink additional scheme names to the same file if needed.
6. Add a `CMakeLists.txt` and wire it into `src/os/plugins/CMakeLists.txt`
   under a `WITH_<NAME>` option.

The plugin has zero link dependency on the pwsafe main binary.  It links
only its own external libraries.


Security Notes
---------------
- The plugin directory is trusted: only place plugins there that you built
  or obtained from a trusted source.
- The identity-string pre-scan is a defence-in-depth measure, not an
  authentication boundary.
- Three external security audits were performed on this code (two AI-assisted
  plus a self-review).  All Critical and High findings were remediated before
  the branch was published.  See commit history for details.
- The lock daemon uses only `read(2)`/`write(2)` in its signal handlers
  (async-signal-safe).  The IPC protocol is a fixed-length binary framing
  to avoid string-parsing vulnerabilities.


Files Added / Modified
-----------------------
| Path | Description |
|------|-------------|
| `src/os/transport.h` | Plugin ABI definition and dispatch API |
| `src/os/unix/transport.cpp` | Dispatch layer: plugin loader, cache, offline fallback |
| `src/os/unix/transport_lockd.cpp` | Lock daemon: fork, IPC, crash recovery |
| `src/os/unix/file.cpp` | `FOpen`/`FClose`/`LockFile` hooks (modified) |
| `src/os/plugins/webdav/transport-webdav.cpp` | WebDAV plugin (libcurl) |
| `src/os/plugins/file/transport-file.cpp` | `file:` reference plugin |
| `src/test/transport_standalone_test.cpp` | Unit tests for dispatch layer |
| `src/test/transport_lock_lifecycle_test.cpp` | Lock daemon lifecycle tests |
| `src/test/transport_webdav_test.cpp` | WebDAV integration tests |
| `src/ui/wxWidgets/OpenUrlDlg.*` | URL-entry dialog for GUI |
| `src/ui/wxWidgets/DbSelectionPanel.*` | Modified to accept URLs |
