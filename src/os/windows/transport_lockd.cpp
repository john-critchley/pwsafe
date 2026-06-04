/*
 * Copyright (c) 2003-2026 Rony Shapiro <ronys@pwsafe.org>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */

/**
 * \file Windows transport lock "daemon" — synchronous in-process implementation.
 *
 * On Unix, a child process is forked on first lock() to hold the WebDAV lock
 * token and to call unlock() if the parent crashes.  A separate process is
 * necessary because after fork() the parent's copy of the plugin's
 * s_lock_tokens map is empty (copy-on-write), so store() in the parent would
 * not include the required If: (<token>) header.
 *
 * Windows has no fork().  All calls happen in the same process, so the
 * plugin's internal token map is always consistent between lock(), store(),
 * and unlock().  Each lockd API function therefore makes a direct synchronous
 * call to the plugin — no IPC, no daemon process, no socketpair.
 *
 * Graceful unlock-all on normal exit is provided by a static destructor.
 * There is no equivalent of the Unix "unlock on parent crash" guarantee, but
 * WebDAV locks carry a finite server-side timeout so stale locks expire on
 * their own.
 */

#include "../transport.h"

#include <cerrno>
#include <map>
#include <string>

static std::map<std::string, bool> s_held;   /* url → true while locked */

int pws_lockd_acquire(const std::string &url)
{
  const PWSTransport *t = pws_find_transport(url);
  if (!t) return ENOENT;
  int rc = t->lock(url.c_str(), nullptr, 0);
  if (rc == 0)
    s_held[url] = true;
  return rc;
}

void pws_lockd_release(const std::string &url)
{
  const PWSTransport *t = pws_find_transport(url);
  if (t) t->unlock(url.c_str(), "");
  s_held.erase(url);
}

int pws_lockd_store(const std::string &local_path, const std::string &url)
{
  /* On Windows, store() is called in the same process where lock() ran, so
   * the plugin's internal token map already contains the token — no IPC. */
  const PWSTransport *t = pws_find_transport(url);
  return t ? t->store(local_path.c_str(), url.c_str()) : ENOENT;
}

void pws_lockd_shutdown()
{
  for (auto &kv : s_held) {
    const PWSTransport *t = pws_find_transport(kv.first);
    if (t) t->unlock(kv.first.c_str(), "");
  }
  s_held.clear();
}

/* ---- static destructor ensures clean shutdown on normal exit ---- */
namespace {
struct LockdGuard {
  ~LockdGuard() { pws_lockd_shutdown(); }
};
static LockdGuard s_guard;
}
