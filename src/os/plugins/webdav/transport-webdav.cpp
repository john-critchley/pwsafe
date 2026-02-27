/*
 * Copyright (c) 2003-2026 Rony Shapiro <ronys@pwsafe.org>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */

/**
 * \file WebDAV transport plugin.
 *
 * Implements the PWSTransport interface over HTTP/HTTPS using libcurl.
 * Credentials are supplied via ~/.netrc (CURLOPT_NETRC = CURL_NETRC_OPTIONAL).
 *
 * URL format:  https://server/path/to/file.psafe3
 *              http://server/path/to/file.psafe3
 *
 * Lock/unlock uses WebDAV LOCK/UNLOCK if the server advertises DAV class 2
 * support (OPTIONS response includes "DAV: 2").  If the server does not
 * support locking, lock() returns ENOTSUP which transport.cpp treats as
 * "proceed without a lock".
 *
 * Identity string (readable with: strings pwsafe-https.so | grep PWS_TRANSPORT_INFO)
 */

#include "../../transport.h"

#include <curl/curl.h>

#include <fcntl.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <string>

/*
 * Embedded identity string in the ELF .comment section.
 * See transport-file.cpp for the rationale; same fix applies here.
 */
__asm__(".pushsection .comment\n"
        ".string \"PWS_TRANSPORT_INFO:1:https,http:WebDAV transport\"\n"
        ".popsection\n");

/*
 * Internal lock-token store.
 *
 * webdav_lock() stores the opaque token keyed by URL.
 * webdav_store() adds an "If: (<token>)" header when one is present so the
 * server accepts the PUT on a locked resource (RFC 4918 §10.4).
 * webdav_unlock() looks the token up here rather than trusting the caller —
 * the UnlockFile intercept in file.cpp currently passes "" as the token.
 */
static std::map<std::string, std::string> s_lock_tokens; /* url → opaque token */

/* --------------------------------------------------------------------------
 * libcurl write/read callbacks
 * -------------------------------------------------------------------------- */

struct WriteCtx {
  FILE  *fp;
  int    err;   /* errno on write failure */
};

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  auto *ctx = static_cast<WriteCtx *>(userdata);
  size_t n = fwrite(ptr, size, nmemb, ctx->fp);
  if (n < nmemb)
    ctx->err = errno;
  return n * size;   /* returning < size*nmemb signals write error to curl */
}

struct ReadCtx {
  FILE  *fp;
  long   total;   /* Content-Length sent to server */
};

static size_t read_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  auto *ctx = static_cast<ReadCtx *>(userdata);
  return fread(ptr, size, nmemb, ctx->fp);
}

/* --------------------------------------------------------------------------
 * Helper: initialise a CURL handle with common options
 * -------------------------------------------------------------------------- */

static CURL *make_curl(const char *url)
{
  CURL *c = curl_easy_init();
  if (!c)
    return nullptr;

  curl_easy_setopt(c, CURLOPT_URL, url);
  curl_easy_setopt(c, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
  curl_easy_setopt(c, CURLOPT_FAILONERROR, 1L);   /* treat 4xx/5xx as errors */
  curl_easy_setopt(c, CURLOPT_USERAGENT, "pwsafe-webdav/1.0");

  /* Restrict protocols to http and https only.  Without this a malicious
   * server could redirect a GET or PUT to file://, ftp://, etc., exposing
   * local files or writing to unintended destinations.
   * Requires libcurl >= 7.85.0. */
  curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR,       "https,http");
  curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, "https,http");

  /* Disable redirects by default.  libcurl follows PUT redirects which
   * could send the database to an attacker-controlled server.  Each
   * individual fetch/store/lock function enables redirects only if safe. */
  curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);

  /* Enforce TLS certificate verification (libcurl defaults to on, but
   * be explicit so a misconfigured build cannot silently disable it). */
  curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);

  /* Reasonable timeouts */
  curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
  curl_easy_setopt(c, CURLOPT_TIMEOUT, 120L);

  return c;
}

/** Map a CURLcode (or HTTP status embedded in it) to an errno-style value. */
static int curl_to_errno(CURL *c, CURLcode rc)
{
  if (rc == CURLE_OK)
    return 0;

  if (rc == CURLE_HTTP_RETURNED_ERROR) {
    long http_code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code == 404 || http_code == 410)
      return ENOENT;
    if (http_code == 401 || http_code == 403)
      return EACCES;
    if (http_code == 423)   /* Locked */
      return EBUSY;
    return EIO;
  }

  if (rc == CURLE_COULDNT_CONNECT || rc == CURLE_COULDNT_RESOLVE_HOST)
    return ECONNREFUSED;
  if (rc == CURLE_OPERATION_TIMEDOUT)
    return ETIMEDOUT;

  return EIO;
}

/* --------------------------------------------------------------------------
 * fetch — HTTP GET → local_path
 * -------------------------------------------------------------------------- */

static int webdav_fetch(const char *url, const char *local_path)
{
  /* Create cache file with 0600 permissions so other local users cannot
   * read the encrypted database.  Using open(O_CLOEXEC) + fdopen() rather
   * than fopen() ensures the mode is enforced regardless of the process umask. */
  int raw_fd = open(local_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (raw_fd < 0)
    return errno;
  FILE *fp = fdopen(raw_fd, "wb");
  if (!fp) {
    int e = errno;
    close(raw_fd);
    return e;
  }

  CURL *c = make_curl(url);
  if (!c) {
    fclose(fp);
    return ENOMEM;
  }

  WriteCtx ctx = { fp, 0 };
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &ctx);

  CURLcode rc = curl_easy_perform(c);
  int err = curl_to_errno(c, rc);

  if (err == 0 && ctx.err != 0)
    err = ctx.err;

#if defined(_DEBUG) || defined(DEBUG)
  fprintf(stderr, "[pwsafe-webdav] fetch %s → %s : curl=%d err=%d\n",
          url, local_path, (int)rc, err);
#endif
  curl_easy_cleanup(c);
  fclose(fp);
  return err;
}

/* --------------------------------------------------------------------------
 * store — local_path → HTTP PUT
 * -------------------------------------------------------------------------- */

static int webdav_store(const char *local_path, const char *url)
{
  FILE *fp = fopen(local_path, "rb");
  if (!fp)
    return errno;

  /* Get file size for Content-Length */
  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return EIO;
  }
  long fsize = ftell(fp);
  if (fsize < 0) {
    fclose(fp);
    return EIO;
  }
  rewind(fp);

  CURL *c = make_curl(url);
  if (!c) {
    fclose(fp);
    return ENOMEM;
  }

  ReadCtx ctx = { fp, fsize };
  curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(c, CURLOPT_READFUNCTION, read_cb);
  curl_easy_setopt(c, CURLOPT_READDATA, &ctx);
  curl_easy_setopt(c, CURLOPT_INFILESIZE_LARGE, (curl_off_t)fsize);
  /* Discard response body (e.g. "201 Created" HTML from Apache) */
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,
                   +[](char *, size_t s, size_t n, void *) -> size_t { return s * n; });

  /* If we hold a WebDAV lock on this URL, include the required If: header so
   * the server accepts the PUT (RFC 4918 §10.4.1). */
  struct curl_slist *hdrs = nullptr;
  auto tok_it = s_lock_tokens.find(url);
  if (tok_it != s_lock_tokens.end()) {
    std::string if_hdr = std::string("If: (<") + tok_it->second + ">)";
    hdrs = curl_slist_append(hdrs, if_hdr.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
  }

  CURLcode rc = curl_easy_perform(c);
  int err = curl_to_errno(c, rc);

  if (hdrs)
    curl_slist_free_all(hdrs);

#if defined(_DEBUG) || defined(DEBUG)
  fprintf(stderr, "[pwsafe-webdav] store %s → %s : curl=%d err=%d\n",
          local_path, url, (int)rc, err);
#endif
  curl_easy_cleanup(c);
  fclose(fp);
  return err;
}

/* --------------------------------------------------------------------------
 * exists — HTTP HEAD
 * -------------------------------------------------------------------------- */

static int webdav_exists(const char *url)
{
  CURL *c = make_curl(url);
  if (!c)
    return ENOMEM;

  curl_easy_setopt(c, CURLOPT_NOBODY, 1L);   /* HEAD */
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,
                   +[](char *, size_t s, size_t n, void *) -> size_t { return s * n; });

  CURLcode rc = curl_easy_perform(c);
  int err = curl_to_errno(c, rc);

  curl_easy_cleanup(c);
  return err;
}

/* --------------------------------------------------------------------------
 * DAV class 2 probe — does the server support LOCK?
 * -------------------------------------------------------------------------- */

struct HeaderCtx {
  bool dav2;
};

static size_t header_cb(char *buf, size_t size, size_t nmemb, void *userdata)
{
  auto *ctx = static_cast<HeaderCtx *>(userdata);
  std::string line(buf, size * nmemb);
  /* DAV: 1, 2  or  DAV: 1,2  — look for "2" after "DAV:"
   * HTTP headers are case-insensitive (RFC 7230 §3.2). */
  if (line.size() > 4 && strncasecmp(line.c_str(), "DAV:", 4) == 0) {
    if (line.find('2') != std::string::npos)
      ctx->dav2 = true;
  }
  return size * nmemb;
}

static bool server_supports_locking(const char *url)
{
  /* Use make_curl() so OPTIONS gets the same protocol restrictions, TLS
   * verification settings, and timeouts as all other requests. */
  CURL *c = make_curl(url);
  if (!c)
    return false;

  curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, "OPTIONS");
  curl_easy_setopt(c, CURLOPT_NOBODY, 1L);

  HeaderCtx hctx = { false };
  curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, header_cb);
  curl_easy_setopt(c, CURLOPT_HEADERDATA, &hctx);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,
                   +[](char *, size_t s, size_t n, void *) -> size_t { return s * n; });

  curl_easy_perform(c);
  curl_easy_cleanup(c);
  return hctx.dav2;
}

/* --------------------------------------------------------------------------
 * lock — WebDAV LOCK (exclusive, infinite timeout)
 * -------------------------------------------------------------------------- */

static const char LOCK_BODY[] =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
    "<D:lockinfo xmlns:D=\"DAV:\">"
      "<D:lockscope><D:exclusive/></D:lockscope>"
      "<D:locktype><D:write/></D:locktype>"
      "<D:owner><D:href>pwsafe</D:href></D:owner>"
    "</D:lockinfo>";

struct LockTokenCtx {
  std::string  body;
  std::string  token;   /* filled from Lock-Token response header */
};

static size_t lock_header_cb(char *buf, size_t size, size_t nmemb, void *ud)
{
  auto *ctx = static_cast<LockTokenCtx *>(ud);
  std::string line(buf, size * nmemb);
  /* Lock-Token: <opaquelocktoken:...>
   * HTTP headers are case-insensitive (RFC 7230 §3.2); compare with strncasecmp. */
  const char prefix[] = "Lock-Token:";
  if (line.size() > sizeof(prefix) - 1 &&
      strncasecmp(line.c_str(), prefix, sizeof(prefix) - 1) == 0)
  {
    std::string val = line.substr(sizeof(prefix) - 1);
    /* strip leading/trailing whitespace and angle brackets */
    size_t start = val.find('<');
    size_t end   = val.rfind('>');
    if (start != std::string::npos && end != std::string::npos && end > start)
      ctx->token = val.substr(start + 1, end - start - 1);
  }
  return size * nmemb;
}

static size_t lock_write_cb(char *ptr, size_t size, size_t nmemb, void *ud)
{
  auto *ctx = static_cast<LockTokenCtx *>(ud);
  /* Limit response body to 64 KB.  A LOCK XML response is typically < 1 KB;
   * a larger reply almost certainly indicates a misbehaving or malicious
   * server.  Returning 0 aborts the transfer with a curl error. */
  constexpr size_t MAX_BODY = 65536;
  size_t chunk = size * nmemb;
  if (ctx->body.size() + chunk > MAX_BODY)
    return 0;
  ctx->body.append(ptr, chunk);
  return chunk;
}

static int webdav_lock(const char *url, char *token_out, size_t token_len)
{
  if (!server_supports_locking(url))
    return ENOTSUP;

  CURL *c = make_curl(url);
  if (!c)
    return ENOMEM;

  struct curl_slist *hdrs = nullptr;
  hdrs = curl_slist_append(hdrs, "Content-Type: application/xml; charset=utf-8");
  hdrs = curl_slist_append(hdrs, "Depth: 0");
  hdrs = curl_slist_append(hdrs, "Timeout: Second-300");

  LockTokenCtx ctx;
  curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, "LOCK");
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
  curl_easy_setopt(c, CURLOPT_POSTFIELDS, LOCK_BODY);
  curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)strlen(LOCK_BODY));
  curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, lock_header_cb);
  curl_easy_setopt(c, CURLOPT_HEADERDATA, &ctx);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, lock_write_cb);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &ctx);

  CURLcode rc = curl_easy_perform(c);
  int err = curl_to_errno(c, rc);

  curl_slist_free_all(hdrs);
  curl_easy_cleanup(c);

  if (err != 0)
    return err;

  if (ctx.token.empty())
    return EIO;   /* unexpected: server returned 2xx but no Lock-Token */

  /* Store token internally so store() and unlock() can use it. */
  s_lock_tokens[url] = ctx.token;

  if (token_out && token_len > 0) {
    strncpy(token_out, ctx.token.c_str(), token_len - 1);
    token_out[token_len - 1] = '\0';
  }

#if defined(_DEBUG) || defined(DEBUG)
  fprintf(stderr, "[pwsafe-webdav] locked %s token=%s\n", url, ctx.token.c_str());
#endif
  return 0;
}

/* --------------------------------------------------------------------------
 * unlock — WebDAV UNLOCK
 * -------------------------------------------------------------------------- */

static int webdav_unlock(const char *url, const char * /*token*/)
{
  /* Look up the token from our internal map; the caller (UnlockFile in
   * file.cpp) always passes "" because it never sees the token. */
  auto it = s_lock_tokens.find(url);
  if (it == s_lock_tokens.end()) {
    /* Nothing to unlock (may have been locked with ENOTSUP, or already unlocked) */
    return 0;
  }

  CURL *c = make_curl(url);
  if (!c)
    return ENOMEM;

  std::string lock_token_hdr = std::string("Lock-Token: <") + it->second + ">";
  struct curl_slist *hdrs = nullptr;
  hdrs = curl_slist_append(hdrs, lock_token_hdr.c_str());

  curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, "UNLOCK");
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
  curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,
                   +[](char *, size_t s, size_t n, void *) -> size_t { return s * n; });

  CURLcode rc = curl_easy_perform(c);
  int err = curl_to_errno(c, rc);

  curl_slist_free_all(hdrs);
  curl_easy_cleanup(c);

  if (err == 0)
    s_lock_tokens.erase(it);   /* token consumed */

#if defined(_DEBUG) || defined(DEBUG)
  fprintf(stderr, "[pwsafe-webdav] unlocked %s err=%d\n", url, err);
#endif
  return err;
}

/* --------------------------------------------------------------------------
 * cleanup — curl global cleanup
 * -------------------------------------------------------------------------- */

static void webdav_cleanup(void)
{
  curl_global_cleanup();
}

/* --------------------------------------------------------------------------
 * Registration
 * -------------------------------------------------------------------------- */

static const PWSTransport https_transport = {
  PWSTransport_ABI_VERSION,
  "https",
  webdav_fetch,
  webdav_store,
  webdav_exists,
  webdav_lock,
  webdav_unlock,
  webdav_cleanup
};

static const PWSTransport http_transport = {
  PWSTransport_ABI_VERSION,
  "http",
  webdav_fetch,
  webdav_store,
  webdav_exists,
  webdav_lock,
  webdav_unlock,
  nullptr   /* cleanup handled by https_transport */
};

extern "C" void pws_plugin_init(pws_register_fn_t reg)
{
  curl_global_init(CURL_GLOBAL_DEFAULT);
  reg(&https_transport);
  reg(&http_transport);
}
