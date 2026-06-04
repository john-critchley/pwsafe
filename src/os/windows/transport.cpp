/*
 * Copyright (c) 2003-2026 Rony Shapiro <ronys@pwsafe.org>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */

/**
 * \file Windows implementation of the transport plugin loader.
 *
 * Plugins are named pwsafe-<scheme>.dll. The loader:
 *   1. Constructs the filename from the URL scheme.
 *   2. Searches app-binary dir first, then cwd (DEVELOPMENT builds only).
 *   3. Pre-scans the .dll bytes for PWS_TRANSPORT_INFO: to verify scheme.
 *   4. LoadLibrary()s the file and calls pws_plugin_init().
 *   5. Keeps it loaded while in use; FreeLibrary() on explicit unload.
 *
 * Security note: unlike Unix (which uses /proc/self/fd/<n> for a TOCTOU-free
 * dlopen), Windows has no equivalent.  The identity check (CreateFileMapping
 * scan) and LoadLibrary use the same path with a small TOCTOU window.  This
 * is acceptable for a local desktop application: an attacker who can write to
 * the application directory already has full control of the host.
 */

#include "../transport.h"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <Shlobj.h>

#include <cassert>
#include <cctype>
#include <cerrno>
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

static std::map<std::string, const PWSTransport *> s_transports;
static std::map<std::string, HMODULE>              s_handles;
static std::map<FILE *, CacheEntry>                s_file_map;
static std::set<std::string>                       s_active_locks;

/* ---- helpers ---- */

static std::string extract_scheme(const std::string &url)
{
  size_t pos = url.find(':');
  /* No colon → not a URL; fewer than 2 chars before colon → Windows drive letter ("C:") */
  if (pos == std::string::npos || pos < 2)
    return "";
  std::string scheme = url.substr(0, pos);
  /* Validate scheme characters per RFC 3986 §3.1 */
  for (char c : scheme) {
    if (!isalnum(static_cast<unsigned char>(c)) && c != '+' && c != '-' && c != '.')
      return "";
  }
  return scheme;
}

static std::string get_app_dir()
{
  wchar_t buf[MAX_PATH];
  DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
  if (len == 0 || len >= MAX_PATH)
    return ".";
  std::wstring path(buf, len);
  size_t sl = path.rfind(L'\\');
  if (sl != std::wstring::npos)
    path = path.substr(0, sl);
  int n = WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1,
                              nullptr, 0, nullptr, nullptr);
  if (n <= 0) return ".";
  std::string result(n - 1, '\0');
  WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, &result[0], n,
                      nullptr, nullptr);
  return result;
}

static std::string get_cache_dir()
{
  char buf[MAX_PATH];
  if (SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, buf) == S_OK)
    return std::string(buf) + "\\pwsafe\\cache";
  const char *appdata = getenv("LOCALAPPDATA");
  if (appdata && *appdata)
    return std::string(appdata) + "\\pwsafe\\cache";
  return ".\\pwsafe-cache";
}

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

static const void *memmem_win(const void *haystack, size_t hlen,
                               const void *needle,   size_t nlen)
{
  if (nlen == 0) return haystack;
  if (hlen < nlen) return nullptr;
  const char *h = static_cast<const char *>(haystack);
  const char *n = static_cast<const char *>(needle);
  for (size_t i = 0; i <= hlen - nlen; ++i)
    if (memcmp(h + i, n, nlen) == 0) return h + i;
  return nullptr;
}

static bool dll_claims_scheme(HANDLE hFile, const std::string &scheme)
{
  LARGE_INTEGER fileSize;
  if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0)
    return false;

  HANDLE hMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (!hMap) return false;

  const void *view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
  bool result = false;
  if (view) {
    const char  magic[] = "PWS_TRANSPORT_INFO:";
    size_t      size    = static_cast<size_t>(fileSize.QuadPart);

    const char *hit = static_cast<const char *>(
        memmem_win(view, size, magic, strlen(magic)));
    if (hit) {
      const char *end = static_cast<const char *>(view) + size;
      const char *p   = hit + strlen(magic);
      /* skip abi field */
      const char *c1 = static_cast<const char *>(memchr(p, ':', end - p));
      if (c1) {
        ++c1;
        const char *c2 = static_cast<const char *>(memchr(c1, ':', end - c1));
        if (c2) {
          std::string schemes(c1, c2 - c1);
          std::string haystack_s = schemes + ",";
          std::string needle_s   = scheme  + ",";
          result = (haystack_s.find(needle_s) != std::string::npos);
        }
      }
    }
    UnmapViewOfFile(view);
  }
  CloseHandle(hMap);
  return result;
}

static std::string find_plugin_path(const std::string &scheme)
{
  const std::string filename = "pwsafe-" + scheme + ".dll";

  std::vector<std::string> dirs = { get_app_dir() };
#ifdef DEVELOPMENT
  dirs.push_back(".");
#endif

  for (const auto &dir : dirs) {
    std::string path = dir + "\\" + filename;
    if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES)
      return path;
  }
  return "";
}

/* ---- public API ---- */

bool pws_transport_debug()
{
  static int v = -1;
  if (v < 0) v = (getenv("PWSAFE_DEBUG_TRANSPORT") != nullptr) ? 1 : 0;
  return v != 0;
}

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

  std::string plugin_path = find_plugin_path(scheme);
  if (plugin_path.empty()) {
    if (pws_transport_debug())
      fprintf(stderr, "[pwsafe-transport] plugin not found for scheme '%s' "
              "(searched app dir%s for pwsafe-%s.dll)\n",
              scheme.c_str(),
#ifdef DEVELOPMENT
              " + cwd",
#else
              "",
#endif
              scheme.c_str());
    return nullptr;
  }

  /* Verify identity before loading */
  HANDLE hFile = CreateFileA(plugin_path.c_str(), GENERIC_READ,
                             FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile == INVALID_HANDLE_VALUE) return nullptr;
  bool ok = dll_claims_scheme(hFile, scheme);
  CloseHandle(hFile);

  if (!ok) {
    if (pws_transport_debug())
      fprintf(stderr, "[pwsafe-transport] identity check failed for scheme '%s'\n",
              scheme.c_str());
    return nullptr;
  }

  HMODULE handle = LoadLibraryA(plugin_path.c_str());
  if (!handle) {
    if (pws_transport_debug())
      fprintf(stderr, "[pwsafe-transport] LoadLibrary failed for '%s' error=%lu\n",
              plugin_path.c_str(), GetLastError());
    return nullptr;
  }

  auto *init_fn = reinterpret_cast<void (*)(pws_register_fn_t)>(
      GetProcAddress(handle, "pws_plugin_init"));
  if (!init_fn) {
    FreeLibrary(handle);
    return nullptr;
  }

  init_fn([](const PWSTransport *t) {
    if (!t || t->abi_version != PWSTransport_ABI_VERSION)
      return;
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

  it = s_transports.find(scheme);
  if (it == s_transports.end()) {
    FreeLibrary(handle);
    return nullptr;
  }

  s_handles[scheme] = handle;
  if (pws_transport_debug())
    fprintf(stderr, "[pwsafe-transport] loaded plugin for scheme '%s'\n",
            scheme.c_str());
  return it->second;
}

std::string pws_get_cache_path(const std::string &url)
{
  std::string dir = get_cache_dir();
  /* Create cache dir tree, one path component at a time.
   * Skip the drive-letter component ("C:") — CreateDirectoryA rejects it. */
  for (size_t i = 1; i <= dir.size(); ++i) {
    if (i == dir.size() || dir[i] == '\\') {
      std::string prefix = dir.substr(0, i);
      if (!prefix.empty() && prefix.back() != ':')
        CreateDirectoryA(prefix.c_str(), nullptr); /* ERROR_ALREADY_EXISTS is fine */
    }
  }
  return dir + "\\" + url_to_filename(url);
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
  if (it == s_file_map.end()) return false;
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
  if (th == s_transports.end()) return;
  const PWSTransport *t = th->second;
  if (t->cleanup) t->cleanup();
  s_transports.erase(th);
  auto hh = s_handles.find(scheme);
  if (hh != s_handles.end()) {
    FreeLibrary(hh->second);
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
