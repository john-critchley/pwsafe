/*
 * Copyright (c) 2003-2026 Rony Shapiro <ronys@pwsafe.org>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */

/**
 * \file file: transport plugin
 *
 * Reference implementation of the PWSTransport interface using plain local
 * file operations. Used for testing the plugin infrastructure without any
 * network dependency.
 *
 * URL format:  file:///absolute/path/to/file.psafe3
 *              file://localhost/absolute/path   (also accepted)
 *
 * Identity string (readable with: strings pwsafe-file.so | grep PWS_TRANSPORT_INFO)
 */

#include "../../transport.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <sys/stat.h>

/* Embedded identity string — primary scheme is "file" */
static const char pws_transport_info[] =
    "PWS_TRANSPORT_INFO:1:file:Local file transport (testing)";

namespace fs = std::filesystem;

/*
 * Strip the "file:" scheme prefix and return the bare local path.
 *
 * Accepted forms (all RFC 8089 / common practice):
 *   file:///absolute/path      → /absolute/path   (canonical)
 *   file://localhost/path      → /path
 *   file://hostname/path       → /path  (hostname ignored for local ops)
 *   file:/absolute/path        → /absolute/path   (single-slash form)
 */
static std::string strip_file_scheme(const char *url)
{
  std::string s(url);

  if (s.substr(0, 7) == "file://") {
    s = s.substr(7);                         /* strip "file://" */
    /* strip optional authority (localhost, hostname, empty) up to next '/' */
    auto slash = s.find('/');
    if (slash != std::string::npos && slash > 0)
      s = s.substr(slash);                   /* "/absolute/path" */
    /* if slash==0 the authority was empty ("file:///path") — already correct */
  } else if (s.substr(0, 6) == "file:/") {
    s = s.substr(5);                         /* strip "file:" → "/absolute/path" */
  }

  fprintf(stderr, "[pwsafe-file] strip_file_scheme: url=%s  path=%s\n",
          url, s.c_str());
  return s;
}

static int file_fetch(const char *url, const char *local_path)
{
  std::string src = strip_file_scheme(url);
  std::error_code ec;
  fs::copy_file(src, local_path,
                fs::copy_options::overwrite_existing, ec);
  if (ec)
    fprintf(stderr, "[pwsafe-file] fetch failed: src=%s  dst=%s  error=%s\n",
            src.c_str(), local_path, ec.message().c_str());
  else
    fprintf(stderr, "[pwsafe-file] fetch ok: src=%s  dst=%s\n",
            src.c_str(), local_path);
  return ec ? ec.value() : 0;
}

static int file_store(const char *local_path, const char *url)
{
  std::string dst = strip_file_scheme(url);
  std::error_code ec;
  fs::copy_file(local_path, dst,
                fs::copy_options::overwrite_existing, ec);
  return ec ? ec.value() : 0;
}

static int file_exists(const char *url)
{
  std::string path = strip_file_scheme(url);
  struct stat st;
  return (::stat(path.c_str(), &st) == 0) ? 0 : ENOENT;
}

static int file_lock(const char * /*url*/, char * /*token_out*/, size_t /*len*/)
{
  return ENOTSUP; /* no-op: transport.cpp treats ENOTSUP as "proceed unlocked" */
}

static int file_unlock(const char * /*url*/, const char * /*token*/)
{
  return 0;
}

static void file_cleanup(void) {}

static const PWSTransport file_transport = {
  PWSTransport_ABI_VERSION,
  "file",
  file_fetch,
  file_store,
  file_exists,
  file_lock,
  file_unlock,
  file_cleanup
};

extern "C" void pws_plugin_init(pws_register_fn_t reg)
{
  reg(&file_transport);
}
