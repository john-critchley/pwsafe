/*
 * Copyright (c) 2003-2026 Rony Shapiro <ronys@pwsafe.org>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */

/**
 * \file Linux implementation of the transport plugin loader.
 *
 * Plugins are named pwsafe-<scheme>.so. The loader:
 *   1. Constructs the filename from the URL scheme.
 *   2. Searches app-binary dir first, then cwd (DEVELOPMENT builds only).
 *   3. Pre-scans the .so bytes for PWS_TRANSPORT_INFO: to verify scheme.
 *   4. dlopen()s the file and calls pws_plugin_init().
 *   5. Keeps it loaded while in use; dlclose() on explicit unload.
 */

#include "../transport.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#  include <mach-o/dyld.h>
#  include <limits.h>
#endif

#include <cassert>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

/* ---- internal state ---- */

struct CacheEntry {
  std::string url;
  std::string cache_path;
  bool        is_write;
};

static std::map<std::string, const PWSTransport *> s_transports; /* scheme -> transport */
static std::map<std::string, void *>               s_handles;    /* scheme -> dlhandle  */
static std::map<FILE *, CacheEntry>                s_file_map;   /* fd     -> cache info */
static std::set<std::string>                       s_active_locks; /* urls we have locked */

/* ---- helpers ---- */

static std::string extract_scheme(const std::string &url)
{
  size_t pos = url.find(':');
  /* No colon → not a URL; fewer than 2 chars before colon → Windows drive letter ("C:") */
  if (pos == std::string::npos || pos < 2)
    return "";
  std::string scheme = url.substr(0, pos);
  /* Validate scheme characters per RFC 3986 §3.1:
   *   scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
   * Reject anything else (e.g. '/', '..') to prevent path-traversal in the
   * plugin filename constructed as "pwsafe-<scheme>.so". */
  for (char c : scheme) {
    if (!isalnum(static_cast<unsigned char>(c)) && c != '+' && c != '-' && c != '.')
      return "";
  }
  return scheme;
}

static std::string get_app_dir()
{
#ifdef __APPLE__
  char buf[PATH_MAX];
  uint32_t size = sizeof(buf);
  if (_NSGetExecutablePath(buf, &size) == 0) {
    std::string p(buf);
    size_t sl = p.rfind('/');
    if (sl != std::string::npos)
      return p.substr(0, sl);
  }
#else
  char buf[4096];
  ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (len > 0) {
    buf[len] = '\0';
    std::string p(buf);
    size_t sl = p.rfind('/');
    if (sl != std::string::npos)
      return p.substr(0, sl);
  }
#endif
  return ".";
}

static std::string get_cache_dir()
{
  const char *xdg = getenv("XDG_CACHE_HOME");
  std::string base;
  if (xdg && *xdg)
    base = xdg;
  else {
    const char *home = getenv("HOME");
    base = std::string(home ? home : "/tmp") + "/.cache";
  }
  return base + "/pwsafe";
}

/** Sanitise URL into a safe filename component */
static std::string url_to_filename(const std::string &url)
{
  std::string s;
  s.reserve(url.size());
  for (char c : url)
    s += (isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-') ? c : '_';
  if (s.size() > 180)
    s.resize(180);
  return s;
}

/**
 * Scan the raw bytes of an already-open .so fd for the PWS_TRANSPORT_INFO:
 * magic string and check whether it claims to handle the given scheme.
 *
 * Takes an open O_RDONLY fd so the caller can open the file once and pass
 * the same fd to both the identity check and dlopen(), eliminating the
 * TOCTOU race that would exist if we opened by path twice.
 */
static bool so_claims_scheme_fd(int fd, const std::string &scheme)
{
  struct stat st;
  bool result = false;

  if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
    void *mem = mmap(nullptr, static_cast<size_t>(st.st_size),
                     PROT_READ, MAP_PRIVATE, fd, 0);
    if (mem != MAP_FAILED) {
      const char  magic[] = "PWS_TRANSPORT_INFO:";
      const char *data    = static_cast<const char *>(mem);
      size_t      size    = static_cast<size_t>(st.st_size);

      const char *hit = static_cast<const char *>(
          memmem(data, size, magic, strlen(magic)));

      if (hit) {
        /* Format: PWS_TRANSPORT_INFO:<abi>:<schemes>:<desc> */
        const char *p = hit + strlen(magic);
        const char *end = data + size;

        /* skip abi field */
        const char *c1 = static_cast<const char *>(memchr(p, ':', end - p));
        if (c1) {
          ++c1;
          /* schemes field */
          const char *c2 = static_cast<const char *>(memchr(c1, ':', end - c1));
          if (c2) {
            std::string schemes(c1, c2 - c1);
            /* check comma-separated list */
            std::string haystack = schemes + ",";
            std::string needle   = scheme  + ",";
            result = (haystack.find(needle) != std::string::npos);
          }
        }
      }
      munmap(mem, static_cast<size_t>(st.st_size));
    }
  }
  return result;
}

/**
 * Find and open the plugin file for the given scheme.
 * Returns an open O_RDONLY | O_CLOEXEC | O_NOFOLLOW fd on success, -1 on failure.
 *
 * O_NOFOLLOW prevents a symlink substitution attack at the plugin path.
 * Returning an fd (rather than a path) eliminates the TOCTOU race between
 * find and use: the caller passes this same fd to so_claims_scheme_fd() and
 * then to dlopen() via /proc/self/fd/<n>, so only one kernel file object
 * is ever referenced.
 *
 * Tries: <app_dir>/pwsafe-<scheme>.so
 *        <cwd>/pwsafe-<scheme>.so  (DEVELOPMENT builds only)
 */
static int open_plugin_fd(const std::string &scheme)
{
  /* Plugins use SUFFIX ".so" on all Unix platforms (macOS included) */
  const std::string filename = "pwsafe-" + scheme + ".so";

  std::vector<std::string> dirs = { get_app_dir() };
#ifdef DEVELOPMENT
  dirs.push_back(".");
#endif

  for (const auto &dir : dirs) {
    std::string path = dir + "/" + filename;
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0)
      return fd;
  }
  return -1;
}

/* ---- public API ---- */

bool pws_is_transport_url(const std::string &path)
{
  return !extract_scheme(path).empty();
}

const PWSTransport *pws_find_transport(const std::string &url)
{
  std::string scheme = extract_scheme(url);
  if (scheme.empty())
    return nullptr;

  /* Already loaded? */
  auto it = s_transports.find(scheme);
  if (it != s_transports.end())
    return it->second;

  /* Open the plugin file once with O_NOFOLLOW to prevent symlink attacks.
   * We use the same fd for the identity check (mmap) and for dlopen via
   * /proc/self/fd/<n>, ensuring no TOCTOU race between check and load. */
  int plugin_fd = open_plugin_fd(scheme);
  if (plugin_fd < 0) {
    return nullptr;   /* caller shows "plugin not found" dialog */
  }

  /* Verify identity string before dlopen */
  if (!so_claims_scheme_fd(plugin_fd, scheme)) {
    close(plugin_fd);
    return nullptr;   /* wrong plugin or renamed file */
  }

  /* Load the plugin.  On Linux, dlopen via /proc/self/fd/<n> ensures the same
   * inode that was verified above is loaded (no TOCTOU race).  On macOS,
   * /proc does not exist; we recover the resolved path from the open fd with
   * F_GETPATH, which gives us the real path of the file we already opened with
   * O_NOFOLLOW — the TOCTOU window is negligible compared to that protection. */
#ifdef __APPLE__
  char fdpath[PATH_MAX];
  if (fcntl(plugin_fd, F_GETPATH, fdpath) != 0) {
    close(plugin_fd);
    return nullptr;
  }
  void *handle = dlopen(fdpath, RTLD_NOW | RTLD_LOCAL);
#else
  char fdpath[64];
  snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", plugin_fd);
  void *handle = dlopen(fdpath, RTLD_NOW | RTLD_LOCAL);
#endif
  close(plugin_fd);   /* dlopen has its own reference; we can close ours */
  if (!handle)
    return nullptr;

  auto *init_fn = reinterpret_cast<void (*)(pws_register_fn_t)>(
      dlsym(handle, "pws_plugin_init"));

  if (!init_fn) {
    dlclose(handle);
    return nullptr;
  }

  /* Plugin calls the registration callback with its PWSTransport* */
  init_fn([](const PWSTransport *t) {
    if (!t || t->abi_version != PWSTransport_ABI_VERSION)
      return;
    /* register all comma-separated schemes */
    std::string schemes = t->scheme;
    schemes += ",";
    size_t pos = 0, comma;
    while ((comma = schemes.find(',', pos)) != std::string::npos) {
      std::string s = schemes.substr(pos, comma - pos);
      if (!s.empty())
        s_transports[s] = t;
      pos = comma + 1;
    }
  });

  /* Did it register for our scheme? */
  it = s_transports.find(scheme);
  if (it == s_transports.end()) {
    dlclose(handle);
    return nullptr;
  }

  s_handles[scheme] = handle;
  return it->second;
}

std::string pws_get_cache_path(const std::string &url)
{
  std::string dir = get_cache_dir();
  /* Create cache dir (and parents) if they don't exist, then enforce 0700.
   * We use a manual mkdir loop rather than std::filesystem::create_directories
   * because std::filesystem is unavailable on macOS < 10.15 (we target 10.14).
   * The umask would open intermediate dirs to 0755, but the password manager
   * cache must be private; chmod() below locks down the leaf directory. */
  for (size_t i = 1; i <= dir.size(); ++i) {
    if (i == dir.size() || dir[i] == '/')
      mkdir(dir.substr(0, i).c_str(), 0777); /* EEXIST is fine; chmod fixes perms */
  }
  chmod(dir.c_str(), 0700);   /* ignore error: best-effort; open() will fail below if wrong */
  return dir + "/" + url_to_filename(url);
}

void pws_cache_register(FILE *fd, const std::string &url,
                        const std::string &cache_path, bool is_write)
{
  s_file_map[fd] = { url, cache_path, is_write };
}

bool pws_cache_lookup(FILE *fd, std::string &url,
                      std::string &cache_path, bool &is_write)
{
  auto it = s_file_map.find(fd);
  if (it == s_file_map.end())
    return false;
  url        = it->second.url;
  cache_path = it->second.cache_path;
  is_write   = it->second.is_write;
  return true;
}

void pws_cache_remove(FILE *fd)
{
  s_file_map.erase(fd);
}

void pws_transport_unload(const std::string &scheme)
{
  auto th = s_transports.find(scheme);
  if (th == s_transports.end())
    return;

  const PWSTransport *t = th->second;
  if (t->cleanup)
    t->cleanup();

  s_transports.erase(th);

  auto hh = s_handles.find(scheme);
  if (hh != s_handles.end()) {
    dlclose(hh->second);
    s_handles.erase(hh);
  }
}

/* ---- active-lock registry ---- */

void pws_lock_register(const std::string &url)
{
  s_active_locks.insert(url);
}

void pws_lock_unregister(const std::string &url)
{
  s_active_locks.erase(url);
}

bool pws_has_lock(const std::string &url)
{
  return s_active_locks.count(url) > 0;
}
