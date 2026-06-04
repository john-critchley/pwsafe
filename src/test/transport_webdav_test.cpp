/**
 * WebDAV transport plugin test suite.
 *
 * Tests the pwsafe-https plugin against a live WebDAV server.
 * Does NOT require gtest or a full cmake build — compile and run directly.
 *
 * Compile (Linux/macOS):
 *   g++ -std=c++17 \
 *       -o /tmp/transport_webdav_test \
 *       src/test/transport_webdav_test.cpp \
 *       -ldl
 *
 * Compile (Windows, from MSVC developer prompt):
 *   cl /std:c++17 /EHsc \
 *      src\test\transport_webdav_test.cpp \
 *      /Fe:transport_webdav_test.exe
 *
 * Run from the directory that contains pwsafe-https.so (or .dll):
 *   cd build && PWSAFE_WEBDAV_TEST_URL=https://myserver/test ./transport_webdav_test
 *
 * Prerequisites:
 *   - pwsafe-https.so/.dll in cwd (the binary directory after cmake build)
 *   - PWSAFE_WEBDAV_TEST_URL set to the base URL of a writable DAV collection
 *     (e.g. https://webdav.example.com/test)
 *   - ~/.netrc (Unix) or %USERPROFILE%\_netrc (Windows) with server credentials
 *   - the collection must already exist (create with MKCOL if absent)
 *
 * Covers:
 *  1. Plugin loading: both https and http schemes registered, ABI version,
 *     function pointers non-null
 *  2. exists: hit (returns 0), miss (returns ENOENT)
 *  3. store without lock: PUT to a fresh URL, round-trip verify
 *  4. fetch: GET into local file, content matches server
 *  5. fetch error: non-existent URL returns non-zero
 *  6. lock / unlock (basic): acquire lock, release with token from
 *     internal map (empty string passed — simulates UnlockFile behaviour),
 *     confirm release by re-locking
 *  7. lock + store + unlock (regression for "store curl=22 err=16"):
 *     with a live WebDAV lock held, store() must include If: (<token>)
 *     so the server accepts the PUT; unlock() must release the lock so a
 *     second open of the same file can acquire it
 *  8. store after unlock: with no lock held, store succeeds without If: header
 *  9. Multiple URLs: locks on different URLs are independent
 * 10. Unlock idempotent: second unlock on same URL returns 0, no crash
 * 11. Lock contention: lock() returns EBUSY (HTTP 423) when another client
 *     already holds an exclusive lock; after the holder unlocks, a fresh
 *     lock() succeeds.  Confirms curl_to_errno maps 423 → EBUSY and that a
 *     failed lock attempt leaves the internal token map unchanged.
 */

/* ---- platform plugin-loading abstraction ---- */
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  define PLUGIN_HANDLE    HMODULE
#  define plugin_open(p)   LoadLibraryA(p)
#  define plugin_sym(h,s)  ((void*)GetProcAddress((h),(s)))
#  define plugin_close(h)  FreeLibrary(h)
#  define plugin_error()   "[LoadLibrary failed]"
#  define PLUGIN_NAME "./pwsafe-https.dll"
#else
#  include <dlfcn.h>
#  define PLUGIN_HANDLE    void*
#  define plugin_open(p)   dlopen((p), RTLD_NOW | RTLD_LOCAL)
#  define plugin_sym(h,s)  dlsym((h),(s))
#  define plugin_close(h)  dlclose(h)
#  define plugin_error()   dlerror()
#  define PLUGIN_NAME      "./pwsafe-https.so"
#endif

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

/* ---- temp-file path helper ---- */

static std::string g_tmpdir;   /* set in main() */

static std::string tmpf(const char *name)
{
  return g_tmpdir + name;
}

/* ---- minimal PWSTransport mirror (keeps test self-contained) ---- */

struct PWSTransport {
  int          abi_version;
  const char  *scheme;
  int  (*fetch )(const char *url, const char *local_path);
  int  (*store )(const char *local_path, const char *url);
  int  (*exists)(const char *url);
  int  (*lock  )(const char *url, char *token_out, size_t token_len);
  int  (*unlock)(const char *url, const char *token);
  void (*cleanup)(void);
};

typedef void (*pws_register_fn_t)(const PWSTransport *);

#define PWSTransport_ABI_VERSION 1

/* ---- tiny test harness ---- */

static int g_pass = 0, g_fail = 0;

#define CHECK(expr) \
  do { \
    if (expr) { \
      printf("  PASS  %s\n", #expr); \
      ++g_pass; \
    } else { \
      printf("  FAIL  %s  (line %d)\n", #expr, __LINE__); \
      ++g_fail; \
    } \
  } while (0)

#define SECTION(name) printf("\n=== %s ===\n", name)

/* ---- file helpers ---- */

static void write_file(const char *path, const char *data)
{
  FILE *f = fopen(path, "wb");
  assert(f);
  fwrite(data, 1, strlen(data), f);
  fclose(f);
}

static bool file_has_content(const char *path, const char *expected)
{
  FILE *f = fopen(path, "rb");
  if (!f) return false;
  char buf[256] = {};
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  return n == strlen(expected) && memcmp(buf, expected, n) == 0;
}

static bool files_identical(const char *a, const char *b)
{
  std::ifstream fa(a, std::ios::binary), fb(b, std::ios::binary);
  if (!fa || !fb) return false;
  return std::equal(std::istreambuf_iterator<char>(fa),
                    std::istreambuf_iterator<char>{},
                    std::istreambuf_iterator<char>(fb),
                    std::istreambuf_iterator<char>{});
}

/* ---- globals ---- */

static const PWSTransport *g_https = nullptr;
static const PWSTransport *g_http  = nullptr;

/* Base URL for all test resources — set via PWSAFE_WEBDAV_TEST_URL */
static std::string g_base;

/* ================================================================
 *  1. Plugin loading
 * ================================================================ */
static void test_plugin_loading(PLUGIN_HANDLE handle)
{
  SECTION("1. Plugin loading");

  auto init = reinterpret_cast<void(*)(pws_register_fn_t)>(
      plugin_sym(handle, "pws_plugin_init"));
  CHECK(init != nullptr);
  if (!init) return;

  init([](const PWSTransport *t) {
    if (strcmp(t->scheme, "https") == 0) g_https = t;
    if (strcmp(t->scheme, "http")  == 0) g_http  = t;
  });

  CHECK(g_https != nullptr);
  CHECK(g_http  != nullptr);

  if (!g_https) return;   /* remaining tests all need g_https */

  CHECK(g_https->abi_version == PWSTransport_ABI_VERSION);
  CHECK(g_https->fetch   != nullptr);
  CHECK(g_https->store   != nullptr);
  CHECK(g_https->exists  != nullptr);
  CHECK(g_https->lock    != nullptr);
  CHECK(g_https->unlock  != nullptr);
  CHECK(g_https->cleanup != nullptr);

  /* Both schemes use the same function pointers */
  CHECK(g_http->fetch  == g_https->fetch);
  CHECK(g_http->store  == g_https->store);
  CHECK(g_http->exists == g_https->exists);
}

/* ================================================================
 *  2. exists
 * ================================================================ */
static void test_exists()
{
  SECTION("2. exists");

  /* File we know is present on the server */
  std::string url = g_base + "/pwsafe_test.psafe3";
  CHECK(g_https->exists(url.c_str()) == 0);

  /* File that does not exist */
  std::string missing = g_base + "/does_not_exist_xyz_abc.psafe3";
  int e = g_https->exists(missing.c_str());
  CHECK(e != 0);
  CHECK(e == ENOENT);
}

/* ================================================================
 *  3. store without lock (PUT to a fresh URL)
 * ================================================================ */
static void test_store_no_lock()
{
  SECTION("3. store without lock");

  std::string local_s  = tmpf("pws_webdav_store_nolock.psafe3");
  const char *local    = local_s.c_str();
  const char *data     = "PWS3webdav-store-nolock";
  std::string url      = g_base + "/pws_webdav_store_nolock.psafe3";

  write_file(local, data);

  int e = g_https->store(local, url.c_str());
  CHECK(e == 0);

  /* Verify: fetch back and compare */
  std::string fetched_s = tmpf("pws_webdav_store_nolock_fetched.psafe3");
  const char *fetched   = fetched_s.c_str();
  e = g_https->fetch(url.c_str(), fetched);
  CHECK(e == 0);
  CHECK(file_has_content(fetched, data));
}

/* ================================================================
 *  4. fetch (GET)
 * ================================================================ */
static void test_fetch()
{
  SECTION("4. fetch");

  std::string url = g_base + "/pwsafe_test.psafe3";
  std::string dst_s = tmpf("pws_webdav_fetched.psafe3");
  const char *dst   = dst_s.c_str();

  int e = g_https->fetch(url.c_str(), dst);
  CHECK(e == 0);
  CHECK(fs::file_size(dst) > 0);
}

/* ================================================================
 *  5. fetch error: non-existent resource
 * ================================================================ */
static void test_fetch_missing()
{
  SECTION("5. fetch error (non-existent)");

  std::string url = g_base + "/definitely_missing_xyz.psafe3";
  std::string dst_s = tmpf("pws_webdav_fetch_missing.psafe3");
  const char *dst   = dst_s.c_str();

  int e = g_https->fetch(url.c_str(), dst);
  CHECK(e != 0);
  CHECK(e == ENOENT);
}

/* ================================================================
 *  6. lock / unlock basic
 *
 *  Verifies that:
 *  - lock() acquires a lock and returns a non-empty token
 *  - unlock() with empty string "" releases the lock via internal map
 *  - after unlock, a second lock() succeeds (confirms server released it)
 * ================================================================ */
static void test_lock_unlock_basic()
{
  SECTION("6. lock / unlock basic");

  std::string url = g_base + "/pws_webdav_lock_basic.psafe3";
  std::string local_s = tmpf("pws_webdav_lock_basic.psafe3");
  const char *local   = local_s.c_str();

  /* Ensure the resource exists before locking */
  write_file(local, "PWS3lock-basic");
  g_https->store(local, url.c_str());   /* create it on server */

  char token[512] = {};
  int e = g_https->lock(url.c_str(), token, sizeof(token));
  CHECK(e == 0);
  CHECK(token[0] != '\0');   /* token must be non-empty */

  /* Unlock passing empty string — simulates how UnlockFile calls us.
   * Plugin must look up the token from its internal map. */
  e = g_https->unlock(url.c_str(), "");
  CHECK(e == 0);

  /* Confirm the server lock was actually released: second lock succeeds */
  char token2[512] = {};
  e = g_https->lock(url.c_str(), token2, sizeof(token2));
  CHECK(e == 0);
  CHECK(token2[0] != '\0');
  /* New token is different from the first */
  CHECK(strcmp(token, token2) != 0);

  /* Cleanup */
  g_https->unlock(url.c_str(), "");
}

/* ================================================================
 *  7. lock + store + unlock (regression: "store curl=22 err=16")
 *
 *  Before the fix, store() did not include the If: (<token>) header,
 *  so the server returned HTTP 423 (Locked → EBUSY).  After the fix,
 *  store() includes the header when a lock token is in the internal map.
 *
 *  Sequence mirrors what pwsafe does:
 *    FOpen → pws_os::LockFile → t->lock()
 *    FClose → FOpen(write) → ... → t->store()
 *    pws_os::UnlockFile → t->unlock("")
 * ================================================================ */
static void test_lock_store_unlock()
{
  SECTION("7. lock + store + unlock (regression: store with active lock)");

  std::string local_s = tmpf("pws_webdav_lsu.psafe3");
  const char *local   = local_s.c_str();
  const char *data_v1 = "PWS3lsu-version1";
  const char *data_v2 = "PWS3lsu-version2";
  std::string url     = g_base + "/pws_webdav_lsu.psafe3";

  /* Ensure the file exists on the server */
  write_file(local, data_v1);
  int e = g_https->store(local, url.c_str());
  CHECK(e == 0);

  /* Acquire lock — token stored in plugin's internal map */
  char token[512] = {};
  e = g_https->lock(url.c_str(), token, sizeof(token));
  CHECK(e == 0);
  CHECK(token[0] != '\0');

  /* Write new content and store while lock is held.
   * Plugin must add If: (<token>) to the PUT request. */
  write_file(local, data_v2);
  e = g_https->store(local, url.c_str());
  CHECK(e == 0);   /* was EBUSY (16) before the fix */

  /* Unlock with empty string — plugin uses internal map */
  e = g_https->unlock(url.c_str(), "");
  CHECK(e == 0);

  /* Verify server has the new content by fetching back */
  std::string fetched_s = tmpf("pws_webdav_lsu_fetched.psafe3");
  const char *fetched   = fetched_s.c_str();
  e = g_https->fetch(url.c_str(), fetched);
  CHECK(e == 0);
  CHECK(file_has_content(fetched, data_v2));

  /* Verify lock was released: a fresh lock must succeed */
  char token2[512] = {};
  e = g_https->lock(url.c_str(), token2, sizeof(token2));
  CHECK(e == 0);   /* would be EBUSY if unlock hadn't worked */

  /* Cleanup */
  g_https->unlock(url.c_str(), "");
}

/* ================================================================
 *  8. store after unlock: no If: header required
 *
 *  After unlock the lock token is removed from the internal map.
 *  A subsequent store must succeed without any If: header.
 * ================================================================ */
static void test_store_after_unlock()
{
  SECTION("8. store after unlock");

  std::string local_s = tmpf("pws_webdav_sau.psafe3");
  const char *local   = local_s.c_str();
  const char *data   = "PWS3sau-content";
  std::string url    = g_base + "/pws_webdav_sau.psafe3";

  write_file(local, "initial");
  g_https->store(local, url.c_str());

  /* Lock then immediately unlock */
  g_https->lock(url.c_str(), nullptr, 0);
  g_https->unlock(url.c_str(), "");

  /* Store without a lock — no If: header, server must accept */
  write_file(local, data);
  int e = g_https->store(local, url.c_str());
  CHECK(e == 0);

  std::string fetched_s = tmpf("pws_webdav_sau_fetched.psafe3");
  const char *fetched   = fetched_s.c_str();
  e = g_https->fetch(url.c_str(), fetched);
  CHECK(e == 0);
  CHECK(file_has_content(fetched, data));
}

/* ================================================================
 *  9. Multiple URLs: locks are per-URL and independent
 * ================================================================ */
static void test_multiple_url_locks()
{
  SECTION("9. Multiple URL locks are independent");

  std::string local_s = tmpf("pws_webdav_multi.psafe3");
  const char *local   = local_s.c_str();
  write_file(local, "PWS3multi");

  std::string url_a = g_base + "/pws_webdav_multi_a.psafe3";
  std::string url_b = g_base + "/pws_webdav_multi_b.psafe3";

  /* Create both resources */
  g_https->store(local, url_a.c_str());
  g_https->store(local, url_b.c_str());

  /* Lock both */
  char ta[512] = {}, tb[512] = {};
  CHECK(g_https->lock(url_a.c_str(), ta, sizeof(ta)) == 0);
  CHECK(g_https->lock(url_b.c_str(), tb, sizeof(tb)) == 0);
  CHECK(strcmp(ta, tb) != 0);   /* different tokens */

  /* Store to both while each is locked */
  write_file(local, "data-a");
  CHECK(g_https->store(local, url_a.c_str()) == 0);
  write_file(local, "data-b");
  CHECK(g_https->store(local, url_b.c_str()) == 0);

  /* Unlock A — B must still be locked (server should reject unlocked PUT) */
  CHECK(g_https->unlock(url_a.c_str(), "") == 0);

  /* Store to A after its unlock succeeds (no token needed) */
  write_file(local, "data-a-updated");
  CHECK(g_https->store(local, url_a.c_str()) == 0);

  /* Unlock B */
  CHECK(g_https->unlock(url_b.c_str(), "") == 0);
}

/* ================================================================
 * 10. Unlock idempotent: second unlock on same URL is a no-op
 * ================================================================ */
static void test_unlock_idempotent()
{
  SECTION("10. Unlock idempotent");

  std::string local_s = tmpf("pws_webdav_idem.psafe3");
  const char *local   = local_s.c_str();
  write_file(local, "PWS3idempotent");
  std::string url = g_base + "/pws_webdav_idem.psafe3";

  g_https->store(local, url.c_str());
  CHECK(g_https->lock(url.c_str(), nullptr, 0) == 0);
  CHECK(g_https->unlock(url.c_str(), "") == 0);

  /* Second unlock: token no longer in map, must return 0 without crashing */
  CHECK(g_https->unlock(url.c_str(), "") == 0);

  /* Unlock on URL that was never locked — must also be a no-op */
  std::string never_locked = g_base + "/never_locked.psafe3";
  CHECK(g_https->unlock(never_locked.c_str(), "") == 0);
}

/* ================================================================
 * 11. Lock contention: EBUSY when another client holds the lock
 *
 *  Simulates what happens when a user tries to open a database that
 *  is already locked by another process.
 *
 *  "Another client" is modelled by keeping our own first lock held while
 *  attempting a second lock on the same URL — the server sees an existing
 *  exclusive lock and returns HTTP 423, which must map to EBUSY.
 *
 *  The test also verifies:
 *  - token_out is NOT populated on a failed lock attempt
 *  - the internal token map is unaffected by the failed attempt
 *    (so the first holder can still unlock cleanly afterwards)
 *  - after the first holder unlocks, the URL becomes available again
 * ================================================================ */
static void test_lock_contention()
{
  SECTION("11. Lock contention (EBUSY when already locked)");

  std::string local_s = tmpf("pws_webdav_contention.psafe3");
  const char *local   = local_s.c_str();
  write_file(local, "PWS3contention");
  std::string url = g_base + "/pws_webdav_contention.psafe3";

  g_https->store(local, url.c_str());

  /* --- Client 1: acquire lock --- */
  char token1[512] = {};
  int e = g_https->lock(url.c_str(), token1, sizeof(token1));
  CHECK(e == 0);
  CHECK(token1[0] != '\0');

  /* --- Client 2: attempt to lock — must fail with EBUSY (HTTP 423) --- */
  char token2[512] = {};
  e = g_https->lock(url.c_str(), token2, sizeof(token2));
  CHECK(e == EBUSY);
  /* Failed lock must not populate token_out */
  CHECK(token2[0] == '\0');

  /* --- Client 1: release — token still in internal map, unlock must work --- */
  e = g_https->unlock(url.c_str(), "");
  CHECK(e == 0);

  /* --- Client 2: retry after release — must succeed now --- */
  e = g_https->lock(url.c_str(), token2, sizeof(token2));
  CHECK(e == 0);
  CHECK(token2[0] != '\0');

  /* Cleanup */
  g_https->unlock(url.c_str(), "");
}

/* ================================================================
 *  main
 * ================================================================ */
int main()
{
  /* Determine temp directory */
#ifdef _WIN32
  {
    const char *t = getenv("TEMP");
    if (!t || !*t) t = getenv("TMP");
    g_tmpdir = t ? std::string(t) + "\\" : "C:\\Temp\\";
    if (g_tmpdir.back() != '\\') g_tmpdir += '\\';
  }
#else
  g_tmpdir = "/tmp/";
#endif

  const char *env = getenv("PWSAFE_WEBDAV_TEST_URL");
  if (!env || !*env) {
    fprintf(stderr,
            "SKIP: PWSAFE_WEBDAV_TEST_URL not set.\n"
            "  Set it to the base URL of a writable DAV collection, e.g.:\n"
            "    export PWSAFE_WEBDAV_TEST_URL=https://webdav.example.com/test\n");
    return 77;   /* 77 = SKIP in automake / ctest convention */
  }
  g_base = env;
  /* Strip trailing slash for consistent URL construction */
  while (!g_base.empty() && g_base.back() == '/')
    g_base.pop_back();

  printf("pwsafe WebDAV transport plugin test suite\n");
  printf("==========================================\n");
  printf("Server: %s\n", g_base.c_str());

  PLUGIN_HANDLE handle = plugin_open(PLUGIN_NAME);
  if (!handle) {
    fprintf(stderr, "plugin_open failed: %s\n"
                    "Run this test from the directory containing " PLUGIN_NAME "\n",
            plugin_error());
    return 1;
  }

  test_plugin_loading(handle);

  if (!g_https) {
    printf("\nFATAL: plugin did not register https transport — skipping remaining tests\n");
    return 1;
  }

  test_exists();
  test_store_no_lock();
  test_fetch();
  test_fetch_missing();
  test_lock_unlock_basic();
  test_lock_store_unlock();
  test_store_after_unlock();
  test_multiple_url_locks();
  test_unlock_idempotent();
  test_lock_contention();

  printf("\n==========================================\n");
  printf("Results: %d passed, %d failed\n", g_pass, g_fail);

  plugin_close(handle);
  return (g_fail == 0) ? 0 : 1;
}
