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
 * Protocol (newline-terminated ASCII)
 * ------------------------------------
 *   Parent → Child:  "LOCK <url>\n"    "UNLOCK <url>\n"    "QUIT\n"
 *   Child  → Parent: "OK\n"            "ERR <errno>\n"
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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>

/* ---- parent-side globals ---- */

static int   s_sock = -1;   /* socketpair fd, parent side */
static pid_t s_pid  = -1;   /* child PID */

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

  std::string pending;   /* incomplete line buffer */
  char tmp[4096];

  for (;;) {
    ssize_t n = read(sock, tmp, sizeof(tmp));
    if (n <= 0) {
      /* EOF: parent exited or crashed — release everything */
      child_unlock_all(sock, held);
      _exit(0);
    }

    pending.append(tmp, static_cast<size_t>(n));

    size_t nl;
    while ((nl = pending.find('\n')) != std::string::npos) {
      std::string line = pending.substr(0, nl);
      pending.erase(0, nl + 1);

      /* --- LOCK <url> --- */
      if (line.size() > 5 && line.substr(0, 5) == "LOCK ") {
        std::string url = line.substr(5);
        const PWSTransport *t = pws_find_transport(url);
        int rc = t ? t->lock(url.c_str(), nullptr, 0) : ENOENT;
        if (rc == 0)
          held[url] = true;
        char resp[32];
        if (rc == 0)
          snprintf(resp, sizeof(resp), "OK\n");
        else
          snprintf(resp, sizeof(resp), "ERR %d\n", rc);
        write(sock, resp, strlen(resp));

      /* --- UNLOCK <url> --- */
      } else if (line.size() > 7 && line.substr(0, 7) == "UNLOCK ") {
        std::string url = line.substr(7);
        if (held.count(url)) {
          const PWSTransport *t = pws_find_transport(url);
          if (t) t->unlock(url.c_str(), "");
          held.erase(url);
        }
        write(sock, "OK\n", 3);

      /* --- STORE <url> <local_path> ---
       * The child holds the lock token in its s_lock_tokens copy, so calling
       * t->store() here includes the required If: (<token>) header.
       * URLs never contain spaces; local_path is everything after the first space. */
      } else if (line.size() > 6 && line.substr(0, 6) == "STORE ") {
        std::string rest = line.substr(6);
        size_t sp = rest.find(' ');
        if (sp == std::string::npos) {
          write(sock, "ERR 22\n", 7);   /* EINVAL */
        } else {
          std::string url        = rest.substr(0, sp);
          std::string local_path = rest.substr(sp + 1);
          const PWSTransport *t = pws_find_transport(url);
          int rc = t ? t->store(local_path.c_str(), url.c_str()) : ENOENT;
          char resp[32];
          if (rc == 0)
            snprintf(resp, sizeof(resp), "OK\n");
          else
            snprintf(resp, sizeof(resp), "ERR %d\n", rc);
          write(sock, resp, strlen(resp));
        }

      /* --- QUIT --- */
      } else if (line == "QUIT") {
        child_unlock_all(sock, held);
        write(sock, "OK\n", 3);
        close(sock);
        _exit(0);
      }
    }
  }
}

/* ============================================================
 * Parent-side helpers
 * ============================================================ */

static bool lockd_start()
{
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
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

/** Read one response line (up to '\n') into buf; strips the newline. */
static bool lockd_recv(char *buf, size_t bufsz)
{
  for (size_t i = 0; i < bufsz - 1; ++i) {
    ssize_t n = read(s_sock, &buf[i], 1);
    if (n <= 0) {
      buf[i] = '\0';
      return false;
    }
    if (buf[i] == '\n') {
      buf[i] = '\0';
      return true;
    }
  }
  buf[bufsz - 1] = '\0';
  return true;
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

  std::string cmd = "LOCK " + url + "\n";
  if (write(s_sock, cmd.c_str(), cmd.size()) < 0)
    return EIO;

  char resp[64];
  if (!lockd_recv(resp, sizeof(resp)))
    return EIO;

  if (strcmp(resp, "OK") == 0)
    return 0;
  if (strncmp(resp, "ERR ", 4) == 0)
    return atoi(resp + 4);
  return EIO;
}

void pws_lockd_release(const std::string &url)
{
  if (s_sock < 0) {
    /* Daemon never started (no locks were acquired) */
    const PWSTransport *t = pws_find_transport(url);
    if (t) t->unlock(url.c_str(), "");
    return;
  }

  std::string cmd = "UNLOCK " + url + "\n";
  /* write() is async-signal-safe — safe to call from signal handlers */
  if (write(s_sock, cmd.c_str(), cmd.size()) < 0)
    return;

  /* read() is also async-signal-safe */
  char resp[64];
  lockd_recv(resp, sizeof(resp));
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

  /* "STORE <url> <local_path>\n" — URL first so the space split is unambiguous */
  std::string cmd = "STORE " + url + " " + local_path + "\n";
  if (write(s_sock, cmd.c_str(), cmd.size()) < 0)
    return EIO;

  char resp[64];
  if (!lockd_recv(resp, sizeof(resp)))
    return EIO;

  if (strcmp(resp, "OK") == 0)
    return 0;
  if (strncmp(resp, "ERR ", 4) == 0)
    return atoi(resp + 4);
  return EIO;
}

void pws_lockd_shutdown()
{
  if (s_sock < 0)
    return;

  char resp[64];
  /* Ask the child to unlock everything and exit cleanly */
  if (write(s_sock, "QUIT\n", 5) == 5)
    lockd_recv(resp, sizeof(resp));

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
