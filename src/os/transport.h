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
 * Plugins are named pwsafe-<scheme>.so and placed alongside the application
 * binary. They are loaded lazily on first use of a URL with that scheme.
 *
 * Each plugin embeds a PWS_TRANSPORT_INFO string readable with `strings`:
 *   PWS_TRANSPORT_INFO:<abi>:<scheme[,scheme,...]>:<description>
 * e.g. "PWS_TRANSPORT_INFO:1:file:Local file transport (testing)"
 *
 * Plugin entry point (extern "C"):
 *   void pws_plugin_init(pws_register_fn_t reg);
 */

#include <cstddef>
#include <cstdio>
#include <string>

#define PWSTransport_ABI_VERSION 1

struct PWSTransport {
  int          abi_version;
  const char  *scheme;       /* primary scheme name (e.g. "file", "webdav") */
  int  (*fetch )(const char *url, const char *local_path); /* download */
  int  (*store )(const char *local_path, const char *url); /* upload */
  int  (*exists)(const char *url);                         /* check existence */
  int  (*lock  )(const char *url, char *token_out, size_t token_len);
  int  (*unlock)(const char *url, const char *token);
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

#endif /* __TRANSPORT_H */
