/*
 * Copyright (c) 2003-2026 Rony Shapiro <ronys@pwsafe.org>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */

/**
 * \file Transport lock daemon.
 *
 * Motivation
 * ----------
 * WebDAV LOCK/UNLOCK requires live libcurl calls.  These cannot be made
 * safely from:
 *   - Signal handlers  (not async-signal-safe)
 *   - atexit/destructors (curl may already be torn down)
 *
 * Writing to a pipe / socket IS async-signal-safe (POSIX write(2)).
 *
 * Design
 * ------
 * On the first lock acquisition, a child process ("lock daemon") is forked.
 * The child inherits the loaded plugin(s) from the parent and executes a
 * simple command loop over a Unix socketpair.
 *
 * The child holds the actual server lock (calls t->lock / t->unlock).
 * The parent communicates intent via the socket; its signal handlers and
 * destructors only need to call write().
 *
 * If the parent exits normally:
 *   pws_lockd_shutdown() sends QUIT; child unlocks everything and exits.
 *
 * If the parent crashes (signal, abort, SIGKILL):
 *   Child detects EOF on the socket and unlocks all held locks.
 *
 * Protocol (binary, length-prefixed — NOT text / delimiter-split)
 * ---------------------------------------------------------------
 * A text protocol that splits on delimiters ('\n', ' ') is inherently
 * vulnerable to injection: a URL containing the delimiter character injects
 * extra commands.  Sanitising the input is a band-aid.  This protocol uses
 * explicit length-prefixed binary frames so that a URL can contain any byte
 * value without affecting framing — analogous to execve(argv[]) vs system().
 *
 * Parent → Child frame:
 *   [uint8_t  opcode]                         — CMD_LOCK / UNLOCK / STORE / QUIT
 *   [uint32_t url_len]  (little-endian)        — byte length of url field
 *   [uint8_t  url[url_len]]                    — URL, any bytes allowed
 *   For CMD_STORE only:
 *   [uint32_t path_len] (little-endian)
 *   [uint8_t  path[path_len]]
 *   CMD_QUIT has no payload beyond the opcode byte.
 *
 * Child → Parent response (fixed 5 bytes):
 *   [uint8_t  status]   — 0 = OK, 1 = ERR
 *   [uint32_t errcode]  (little-endian) — errno value (0 if OK)
 *
 * Thread safety
 * -------------
 * Lock operations in pwsafe happen on the main thread only.
 * No synchronisation is provided around the socket writes.
 */

#include "../transport.h"

#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>

/* ---- opcodes ---- */
static constexpr uint8_t CMD_LOCK   = 0x01;
static constexpr uint8_t CMD_UNLOCK = 0x02;
static constexpr uint8_t CMD_STORE  = 0x03;
static constexpr uint8_t CMD_QUIT   = 0x04;

/* ---- parent-side globals ---- */

static int   s_sock = -1;   /* socketpair fd, parent side */
static pid_t s_pid  = -1;   /* child PID */

/* ============================================================
 * Low-level I/O helpers (used by both parent and child)
 * ============================================================ */

/** Write exactly len bytes; handles short writes and EINTR.  Returns true on success. */
static bool send_all(int fd, const void *buf, size_t len)
{
  const char *p = static_cast<const char *>(buf);
  while (len > 0) {
    ssize_t n = write(fd, p, len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return false;
    }
    if (n == 0)
      return false;
    p   += n;
    len -= static_cast<size_t>(n);
  }
  return true;
}

/** Read exactly len bytes; handles short reads and EINTR.  Returns true on success. */
static bool recv_all(int fd, void *buf, size_t len)
{
  char *p = static_cast<char *>(buf);
  while (len > 0) {
    ssize_t n = read(fd, p, len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return false;
    }
    if (n == 0)
      return false;
    p   += n;
    len -= static_cast<size_t>(n);
  }
  return true;
}

/* Maximum field sizes for IPC protocol validation.
 * A URL longer than 8 KB is unreasonable; a local path longer than 4 KB
 * would exceed PATH_MAX on every known system.  Enforce these limits in the
 * child to prevent a corrupted or malicious frame from causing gigabyte
 * allocations. */
static constexpr uint32_t MAX_IPC_URL  = 8192;
static constexpr uint32_t MAX_IPC_PATH = 4096;

/** Read a length-prefixed string from fd into str.  Returns true on success. */
static bool recv_string(int fd, std::string &str, uint32_t max_len = MAX_IPC_URL)
{
  uint32_t len;
  if (!recv_all(fd, &len, sizeof(len)))
    return false;
  if (len > max_len)
    return false;   /* reject oversized field — protocol error or DoS attempt */
  str.assign(len, '\0');
  return len == 0 || recv_all(fd, &str[0], len);
}

/** Send a fixed 5-byte response to the parent. */
static void send_response(int fd, int errcode)
{
  uint8_t  status = (errcode == 0) ? 0 : 1;
  uint32_t code   = static_cast<uint32_t>(errcode);
  send_all(fd, &status, 1);
  send_all(fd, &code, 4);
}

/**
 * Read one response from the child.
 * Returns 0 on OK, the errno value on ERR, or EIO on read failure.
 */
static int recv_response(int fd)
{
  uint8_t  status;
  uint32_t code;
  if (!recv_all(fd, &status, 1) || !recv_all(fd, &code, 4))
    return EIO;
  return (status == 0) ? 0 : static_cast<int>(code);
}

/* ============================================================
 * Child process
 * ============================================================ */

static void child_unlock_all(int sock, std::map<std::string, bool> &held)
{
  for (auto &kv : held) {
    const PWSTransport *t = pws_find_transport(kv.first);
    if (t) {
      t->unlock(kv.first.c_str(), "");
#if defined(_DEBUG) || defined(DEBUG)
      fprintf(stderr, "[pwsafe-lockd] cleanup: unlocked %s\n", kv.first.c_str());
#endif
    }
  }
  held.clear();
}

static void lockd_child_main(int sock)
{
  /* Reset signals so the child isn't affected by pwsafe's handlers */
  signal(SIGTERM, SIG_DFL);
  signal(SIGINT,  SIG_DFL);
  signal(SIGHUP,  SIG_DFL);
  signal(SIGPIPE, SIG_IGN);   /* we handle write errors explicitly */

  std::map<std::string, bool> held;  /* url → true while we hold the lock */

  for (;;) {
    uint8_t opcode;
    if (!recv_all(sock, &opcode, 1)) {
      /* EOF: parent exited or crashed — release everything */
      child_unlock_all(sock, held);
      _exit(0);
    }

    /* --- QUIT --- */
    if (opcode == CMD_QUIT) {
      child_unlock_all(sock, held);
      send_response(sock, 0);
      close(sock);
      _exit(0);
    }

    /* All other commands carry a URL */
    std::string url;
    if (!recv_string(sock, url)) {
      child_unlock_all(sock, held);
      _exit(1);
    }

    if (opcode == CMD_LOCK) {
      /* --- LOCK <url> --- */
      const PWSTransport *t = pws_find_transport(url);
      int rc = t ? t->lock(url.c_str(), nullptr, 0) : ENOENT;
      if (rc == 0)
        held[url] = true;
      send_response(sock, rc);

    } else if (opcode == CMD_UNLOCK) {
      /* --- UNLOCK <url> --- */
      if (held.count(url)) {
        const PWSTransport *t = pws_find_transport(url);
        if (t) t->unlock(url.c_str(), "");
        held.erase(url);
      }
      send_response(sock, 0);

    } else if (opcode == CMD_STORE) {
      /* --- STORE <url> <local_path> --- */
      std::string local_path;
      if (!recv_string(sock, local_path, MAX_IPC_PATH)) {
        child_unlock_all(sock, held);
        _exit(1);
      }
      const PWSTransport *t = pws_find_transport(url);
      int rc = t ? t->store(local_path.c_str(), url.c_str()) : ENOENT;
      send_response(sock, rc);

    } else {
      /* Unknown opcode — protocol error, bail out safely */
      child_unlock_all(sock, held);
      _exit(1);
    }
  }
}

/* ============================================================
 * Parent-side helpers
 * ============================================================ */

static bool lockd_start()
{
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
    return false;

  pid_t pid = fork();
  if (pid < 0) {
    close(sv[0]);
    close(sv[1]);
    return false;
  }

  if (pid == 0) {
    /* ---- CHILD ---- */
    close(sv[0]);

    /* Close all fds >= 3 except sv[1] to avoid holding parent resources
     * (X11 sockets, wxWidgets pipes, etc.) */
    DIR *dir = opendir("/proc/self/fd");
    if (dir) {
      int dfd = dirfd(dir);
      struct dirent *de;
      while ((de = readdir(dir)) != nullptr) {
        if (de->d_name[0] == '.')
          continue;
        int fd = atoi(de->d_name);
        if (fd >= 3 && fd != sv[1] && fd != dfd)
          close(fd);
      }
      closedir(dir);
    }

    lockd_child_main(sv[1]);
    _exit(1);  /* not reached */
  }

  /* ---- PARENT ---- */
  close(sv[1]);
  s_sock = sv[0];
  s_pid  = pid;
  return true;
}

/**
 * Send a length-prefixed string field to the child.
 * url_len is sent as a uint32_t (LE), followed by the url bytes.
 * Suitable for async-signal-safe use when url is already in a C string
 * (no heap allocation; only write() calls which are signal-safe).
 */
static bool parent_send_string(int fd, const char *s, size_t slen)
{
  uint32_t len = static_cast<uint32_t>(slen);
  return send_all(fd, &len, 4) && (slen == 0 || send_all(fd, s, slen));
}

/* ============================================================
 * Public API
 * ============================================================ */

int pws_lockd_acquire(const std::string &url)
{
  /* Start daemon on first use */
  if (s_sock < 0 && !lockd_start()) {
    /* Fork failed — fall back to a direct (non-signal-safe) call */
    const PWSTransport *t = pws_find_transport(url);
    if (!t) return ENOENT;
    return t->lock(url.c_str(), nullptr, 0);
  }

  if (!send_all(s_sock, &CMD_LOCK, 1) ||
      !parent_send_string(s_sock, url.c_str(), url.size()))
    return EIO;

  return recv_response(s_sock);
}

void pws_lockd_release(const std::string &url)
{
  if (s_sock < 0) {
    /* Daemon never started (no locks were acquired) */
    const PWSTransport *t = pws_find_transport(url);
    if (t) t->unlock(url.c_str(), "");
    return;
  }

  /* Build the frame on the stack — no heap allocation, so this path is
   * async-signal-safe (write(2) is signal-safe; we avoid std::string ops). */
  const char *u    = url.c_str();   /* signal-safe: just a pointer read */
  size_t      ulen = url.size();    /* signal-safe: just a size_t read */
  if (ulen > MAX_IPC_URL)
    return;   /* child would reject this; don't bother sending */

  /* write() is async-signal-safe — safe to call from signal handlers */
  send_all(s_sock, &CMD_UNLOCK, 1);
  parent_send_string(s_sock, u, ulen);

  /* read() is also async-signal-safe */
  recv_response(s_sock);
}

/*
 * Store a file to a transport URL via the daemon.
 *
 * The daemon's child process holds the WebDAV lock token in its copy of the
 * plugin's s_lock_tokens map.  By routing the store through the child, the
 * plugin's webdav_store() finds the token and adds the required If: (<token>)
 * header.  Without this, the parent's copy of s_lock_tokens is always empty
 * after the fork and the server returns 423 Locked.
 *
 * If the daemon is not running (no lock was ever acquired), falls back to a
 * direct t->store() call (correct — no lock means no If: header needed).
 */
int pws_lockd_store(const std::string &local_path, const std::string &url)
{
  if (s_sock < 0) {
    /* Daemon never started — direct call is correct (no lock token needed) */
    const PWSTransport *t = pws_find_transport(url);
    return t ? t->store(local_path.c_str(), url.c_str()) : ENOENT;
  }

  if (!send_all(s_sock, &CMD_STORE, 1) ||
      !parent_send_string(s_sock, url.c_str(), url.size()) ||
      !parent_send_string(s_sock, local_path.c_str(), local_path.size()))
    return EIO;

  return recv_response(s_sock);
}

void pws_lockd_shutdown()
{
  if (s_sock < 0)
    return;

  /* Ask the child to unlock everything and exit cleanly */
  if (send_all(s_sock, &CMD_QUIT, 1))
    recv_response(s_sock);

  close(s_sock);
  s_sock = -1;

  if (s_pid > 0) {
    /* Reap the child to avoid a zombie */
    waitpid(s_pid, nullptr, 0);
    s_pid = -1;
  }
}

/* ---- static destructor ensures clean shutdown on normal exit ---- */
namespace {
struct LockdGuard {
  ~LockdGuard() { pws_lockd_shutdown(); }
};
static LockdGuard s_guard;
}
