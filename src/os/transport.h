/*
 * Copyright (c) 2003-2026 Rony Shapiro <ronys@pwsafe.org>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */

#ifndef __TRANSPORT_H
#define __TRANSPORT_H

/**
 * Transport plugin interface.
 *
 * ## Plugin discovery
 * Plugins are shared libraries named `pwsafe-<scheme>.so`, placed alongside
 * the application binary (or the current directory in DEVELOPMENT builds).
 * They are loaded lazily on first use of a URL whose scheme matches.
 *
 * ## Identity string
 * Every plugin must embed one identity string, readable with `strings`:
 *
 *   PWS_TRANSPORT_INFO:<abi>:<scheme[,scheme,...]>:<description>
 *
 * Examples:
 *   "PWS_TRANSPORT_INFO:1:file:Local file transport (testing)"
 *   "PWS_TRANSPORT_INFO:1:https,http:WebDAV transport"
 *
 * The ABI field must be "1" (== PWSTransport_ABI_VERSION).
 * Multiple comma-separated schemes register the same .so for each scheme.
 * The string is scanned before dlopen() as a security check; if it is absent
 * or the scheme doesn't match the filename the .so is rejected.
 *
 * ## Entry point
 * The plugin must export exactly one C-linkage symbol:
 *
 *   extern "C" void pws_plugin_init(pws_register_fn_t reg);
 *
 * `pws_plugin_init` is called once at load time. Call `reg` once per
 * PWSTransport struct you want to register (one per scheme supported).
 * The struct must remain valid for the lifetime of the plugin.
 *
 * ## Calling context
 * All function pointers in PWSTransport are called from the lock daemon
 * child process (forked by transport_lockd.cpp on the first LockFile call).
 * The child is single-threaded, so no synchronisation is required inside the
 * plugin. The parent process never calls any plugin function directly once
 * the daemon is running.
 *
 * ## Lock token ownership
 * The plugin is responsible for storing its own lock token between `lock()`
 * and `unlock()`.  The `unlock()` function receives `token=""` from the
 * caller — do not rely on the token argument; look it up from internal state.
 * Likewise, `store()` must look up the token internally and add any required
 * conditional header (e.g. WebDAV `If: (<token>)`) without being told.
 */

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <string>

/* MSVC does not define ENOTSUP (a POSIX extension).  Use a value that does
 * not collide with any standard MSVC errno code (which top out around 138). */
#if defined(_MSC_VER) && !defined(ENOTSUP)
#  define ENOTSUP 252
#endif

#ifdef _WIN32
#  define PWS_EXPORT __declspec(dllexport)
#else
#  define PWS_EXPORT
#endif

#define PWSTransport_ABI_VERSION 1

struct PWSTransport {
  int          abi_version; /* must be PWSTransport_ABI_VERSION */
  const char  *scheme;      /* primary scheme string (e.g. "https") */

  /**
   * fetch — download the resource at `url` to the local file `local_path`.
   *
   * `local_path` will be overwritten if it exists.
   * Returns 0 on success, or an errno value:
   *   ENOENT   — resource not found (HTTP 404/410)
   *   EACCES   — authentication/authorisation failure (HTTP 401/403)
   *   ECONNREFUSED / ETIMEDOUT — network error
   *   EIO      — any other server or transfer error
   *
   * fetch() is called before the file is opened for reading.  It is NOT
   * called when the file is opened for writing (the app writes a new version
   * to a temp file and calls store() on close).
   */
  int  (*fetch)(const char *url, const char *local_path);

  /**
   * store — upload the local file `local_path` to `url`.
   *
   * Called when a modified database is closed (FClose with bIsWrite=true).
   * If the plugin holds a lock token for this URL, it must include any
   * required conditional header (e.g. WebDAV `If: (<token>)`) itself —
   * the caller does not know the token.
   *
   * Returns 0 on success, or an errno value.  A non-zero return causes the
   * FClose call to propagate the error to the caller (data remains in the
   * local cache file but is not written to the server).
   *
   * Note: when a lock is held, store() is invoked from the daemon child
   * process, which is where the lock token was obtained (see transport.h
   * header comment on lock token ownership).
   */
  int  (*store)(const char *local_path, const char *url);

  /**
   * exists — test whether the resource at `url` is accessible.
   *
   * Returns 0 if the resource exists, ENOENT if it does not, or another
   * errno value on error.  Typically implemented with an HTTP HEAD request.
   * No body transfer is expected.
   */
  int  (*exists)(const char *url);

  /**
   * lock — acquire an exclusive write lock on `url`.
   *
   * Returns:
   *   0        — lock acquired; plugin must store the token internally.
   *   ENOTSUP  — server does not support locking.  The caller treats this
   *              as success: the file opens read-write without a lock.
   *   EBUSY    — resource is currently locked by another client.
   *              The caller blocks the open and reports a conflict.
   *   ENOMEM   — allocation failure.
   *   EIO      — any other server or network error.
   *
   * `token_out` may be nullptr.  If non-null and `token_len > 0`, write the
   * opaque lock token (null-terminated) into the buffer — this is for
   * diagnostics only.  The token is NOT passed back to unlock(); the plugin
   * must retain it in internal state and look it up in unlock()/store().
   *
   * lock() is called in the daemon child process.  It is never called
   * concurrently with store() or unlock() for the same URL.
   */
  int  (*lock)(const char *url, char *token_out, size_t token_len);

  /**
   * unlock — release the lock on `url`.
   *
   * `token` is always "" in the current implementation; the plugin must
   * look up the token from its own internal map (populated by lock()).
   * If no lock is held for `url` (e.g. lock returned ENOTSUP), this is a
   * no-op and should return 0.
   *
   * Returns 0 on success.  Errors are logged but not propagated to the user.
   *
   * unlock() is called in the daemon child process.  On parent crash or
   * exit, the daemon calls unlock() for every URL in its held-lock map.
   */
  int  (*unlock)(const char *url, const char *token);

  /**
   * cleanup — release global plugin resources.
   *
   * Called once when the plugin is unloaded.  Use this to tear down any
   * library that was initialised in pws_plugin_init (e.g. curl_global_cleanup).
   * May be nullptr if no teardown is needed.
   *
   * cleanup() is called in the daemon child process on exit, and also in
   * the parent process when the plugin is explicitly unloaded.
   */
  void (*cleanup)(void);
};

typedef void (*pws_register_fn_t)(const PWSTransport *);

/* ---- called from file.cpp ---- */

/** Return true if path has a URL scheme prefix (e.g. "file:", "webdav:") */
bool pws_is_transport_url(const std::string &path);

/** Lazy-load plugin for URL's scheme; return its transport or nullptr */
const PWSTransport *pws_find_transport(const std::string &url);

/** Return local cache path for a URL (creates cache dir if needed) */
std::string pws_get_cache_path(const std::string &url);

/** Bridge FILE* to its URL/cache for FClose to pick up */
void pws_cache_register(FILE *fd, const std::string &url,
                        const std::string &cache_path, bool is_write);
bool pws_cache_lookup(FILE *fd, std::string &url,
                      std::string &cache_path, bool &is_write);
void pws_cache_remove(FILE *fd);

/** Unload the plugin for a scheme (called when DB using it is closed) */
void pws_transport_unload(const std::string &scheme);

/**
 * Return true if PWSAFE_DEBUG_TRANSPORT is set in the environment.
 * Used to gate verbose stderr tracing for transport operations.
 */
bool pws_transport_debug();

/*
 * Active-lock registry.
 *
 * LockFile (file.cpp) calls pws_lock_register() after a successful t->lock().
 * UnlockFile calls pws_lock_unregister() unconditionally.
 * IsLockedFile uses pws_has_lock() instead of checking for a .plk file, so
 * SafeUnlockFile correctly releases the server lock on close / exit.
 */
void pws_lock_register  (const std::string &url);
void pws_lock_unregister(const std::string &url);
bool pws_has_lock       (const std::string &url);

/*
 * Lock daemon (transport_lockd.cpp).
 *
 * A child process is forked on first use.  It holds the actual transport
 * (WebDAV) lock and releases it if the parent exits or crashes.
 *
 * pws_lockd_acquire / pws_lockd_release use only write(2) / read(2) and are
 * async-signal-safe, so they can be called from signal handlers.
 *
 * Return values of pws_lockd_acquire mirror the plugin's lock() return code:
 *   0        — locked successfully (caller should call pws_lock_register)
 *   ENOTSUP  — server does not support locks; proceed without one
 *   EBUSY    — locked by someone else
 *   other    — error
 */
int  pws_lockd_acquire (const std::string &url);
void pws_lockd_release (const std::string &url);
/*
 * Route a store (write-back) through the daemon so the child's lock token
 * is included in the If: (<token>) header.  Must be used instead of calling
 * t->store() directly whenever pws_has_lock(url) is true — the parent's copy
 * of the plugin's s_lock_tokens is always empty after the initial fork.
 */
int  pws_lockd_store   (const std::string &local_path, const std::string &url);
void pws_lockd_shutdown();

#endif /* __TRANSPORT_H */
