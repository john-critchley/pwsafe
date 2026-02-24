/**
 * Standalone transport infrastructure test suite.
 *
 * Does NOT require gtest or a full cmake build — compile and run directly:
 *
 *   g++ -std=c++17 -DDEVELOPMENT \
 *       -I <repo>/src \
 *       -o /tmp/transport_standalone_test \
 *       src/test/transport_standalone_test.cpp \
 *       src/os/unix/transport.cpp \
 *       -ldl \
 *   && cd /tmp && ./transport_standalone_test
 *
 * pwsafe-file.so must be in /tmp (cwd, found via DEVELOPMENT search path).
 * Build it first: g++ -std=c++17 -shared -fPIC -I src/os \
 *                     -o /tmp/pwsafe-file.so \
 *                     src/os/plugins/file/transport-file.cpp
 *
 * Covers:
 *  1. Scheme detection (pws_is_transport_url)
 *  2. Plugin loading via pws_find_transport (uses identity-string pre-scan)
 *  3. All four plugin operations: exists / fetch / store / lock
 *  4. Cache path generation and sanitisation
 *  5. FILE* map: register / lookup / remove round-trip
 *  6. Unload and reload cycle
 *  7. Error cases: missing scheme, bad scheme, empty URL
 *
 * Build and run:
 *   g++ -std=c++17 -DDEVELOPMENT -I /home/john/git/pwsafe/src \
 *       -o /tmp/test_transport_suite \
 *       /tmp/test_transport_suite.cpp \
 *       /home/john/git/pwsafe/src/os/unix/transport.cpp \
 *       -ldl && cd /tmp && ./test_transport_suite
 *
 * pwsafe-file.so must be present in /tmp (the cwd, found via DEVELOPMENT path).
 */

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>

#include "os/transport.h"

namespace fs = std::filesystem;

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

/* ---- helpers ---- */

static void write_file(const char *path, const char *data)
{
  FILE *f = fopen(path, "wb");
  assert(f);
  fwrite(data, 1, strlen(data), f);
  fclose(f);
}

static bool file_has_content(const char *path, const char *data)
{
  FILE *f = fopen(path, "rb");
  if (!f) return false;
  char buf[256] = {};
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  return n == strlen(data) && memcmp(buf, data, n) == 0;
}

/* ================================================================
 *  1. Scheme detection
 * ================================================================ */
static void test_scheme_detection()
{
  SECTION("1. Scheme detection");

  /* Positive cases */
  CHECK(pws_is_transport_url("file:///tmp/foo.psafe3"));
  CHECK(pws_is_transport_url("file://localhost/tmp/foo.psafe3"));
  CHECK(pws_is_transport_url("webdav://example.com/db.psafe3"));
  CHECK(pws_is_transport_url("https://host/path"));
  /* Exactly two chars before colon is accepted */
  CHECK(pws_is_transport_url("ab:something"));

  /* Negative cases */
  CHECK(!pws_is_transport_url("/local/absolute/path"));
  CHECK(!pws_is_transport_url("relative/path"));
  CHECK(!pws_is_transport_url(""));
  /* Single char before colon — would be a Windows drive letter */
  CHECK(!pws_is_transport_url("C:/Windows/path"));
  CHECK(!pws_is_transport_url("x:something"));
  /* No colon */
  CHECK(!pws_is_transport_url("no_scheme_at_all"));
}

/* ================================================================
 *  2. Plugin loading — happy path
 * ================================================================ */
static void test_plugin_loading_happy()
{
  SECTION("2. Plugin loading (happy path)");

  const std::string url = "file:///tmp/pws_load_test.psafe3";

  /* First call: loads and caches */
  const PWSTransport *t1 = pws_find_transport(url);
  CHECK(t1 != nullptr);

  if (!t1) return; /* abort this section */

  CHECK(t1->abi_version == PWSTransport_ABI_VERSION);
  CHECK(strcmp(t1->scheme, "file") == 0);
  CHECK(t1->fetch   != nullptr);
  CHECK(t1->store   != nullptr);
  CHECK(t1->exists  != nullptr);
  CHECK(t1->lock    != nullptr);
  CHECK(t1->unlock  != nullptr);
  CHECK(t1->cleanup != nullptr);

  /* Second call: returns same pointer (cached) */
  const PWSTransport *t2 = pws_find_transport(url);
  CHECK(t2 == t1);
}

/* ================================================================
 *  3. Plugin loading — error cases
 * ================================================================ */
static void test_plugin_loading_errors()
{
  SECTION("3. Plugin loading (error cases)");

  /* Unknown scheme: no plugin .so exists */
  CHECK(pws_find_transport("nosuchscheme://example.com/db.psafe3") == nullptr);

  /* URL with only one char before colon (Windows drive letter syntax) */
  CHECK(pws_find_transport("C:/Windows/Temp/db.psafe3") == nullptr);

  /* Empty URL */
  CHECK(pws_find_transport("") == nullptr);
}

/* ================================================================
 *  4. Plugin operations: exists / fetch / store / lock
 * ================================================================ */
static void test_plugin_operations()
{
  SECTION("4. Plugin operations");

  const char *src_path  = "/tmp/pws_ops_src.psafe3";
  const char *dst_path  = "/tmp/pws_ops_dst.psafe3";
  const char *dst2_path = "/tmp/pws_ops_dst2.psafe3";
  const char *data      = "PWS3fake-payload";

  write_file(src_path, data);

  const PWSTransport *t = pws_find_transport("file:///tmp/anything.psafe3");
  assert(t); /* ensured by earlier test */

  /* exists: present file returns 0 */
  std::string src_url = std::string("file://") + src_path;
  CHECK(t->exists(src_url.c_str()) == 0);

  /* exists: absent file returns ENOENT */
  CHECK(t->exists("file:///tmp/does_not_exist_xyz.psafe3") == ENOENT);

  /* fetch: copies remote to local */
  int rc = t->fetch(src_url.c_str(), dst_path);
  CHECK(rc == 0);
  CHECK(file_has_content(dst_path, data));

  /* store: copies local back to remote location */
  std::string dst2_url = std::string("file://") + dst2_path;
  rc = t->store(dst_path, dst2_url.c_str());
  CHECK(rc == 0);
  CHECK(file_has_content(dst2_path, data));

  /* lock: returns ENOTSUP (file transport is local, no locking needed) */
  char token[64] = {};
  rc = t->lock(src_url.c_str(), token, sizeof(token));
  CHECK(rc == ENOTSUP);

  /* unlock: returns 0 (no-op) */
  CHECK(t->unlock(src_url.c_str(), "") == 0);
}

/* ================================================================
 *  5. Cache path generation
 * ================================================================ */
static void test_cache_path()
{
  SECTION("5. Cache path generation");

  std::string p1 = pws_get_cache_path("file:///tmp/my-db.psafe3");
  CHECK(!p1.empty());
  /* Must contain "pwsafe" directory component */
  CHECK(p1.find("pwsafe") != std::string::npos);
  /* Must not contain raw '/' from the URL path (sanitised) */
  std::string basename = fs::path(p1).filename().string();
  CHECK(basename.find('/') == std::string::npos);
  /* Cache directory must have been created */
  CHECK(fs::is_directory(fs::path(p1).parent_path()));

  /* Same URL → same path */
  CHECK(pws_get_cache_path("file:///tmp/my-db.psafe3") == p1);

  /* Different URL → different path */
  std::string p2 = pws_get_cache_path("file:///tmp/other-db.psafe3");
  CHECK(p2 != p1);

  /* Long URL is truncated to 180 chars in the filename component */
  std::string long_url = "file:///" + std::string(300, 'a') + ".psafe3";
  std::string plong    = pws_get_cache_path(long_url);
  CHECK(fs::path(plong).filename().string().size() <= 180);
}

/* ================================================================
 *  6. FILE* map: register / lookup / remove
 * ================================================================ */
static void test_file_map()
{
  SECTION("6. FILE* map round-trip");

  /* Use a real (open) FILE* so the pointer is valid */
  FILE *f = fopen("/tmp/pws_map_dummy.tmp", "wb");
  assert(f);

  const std::string url   = "file:///tmp/map-test.psafe3";
  const std::string cache = "/tmp/pws-cache-maptest";

  /* Nothing registered yet */
  std::string u, c; bool w;
  CHECK(!pws_cache_lookup(f, u, c, w));

  /* Register read entry */
  pws_cache_register(f, url, cache, false);
  CHECK(pws_cache_lookup(f, u, c, w));
  CHECK(u == url);
  CHECK(c == cache);
  CHECK(w == false);

  /* Register write entry (overwrite) */
  pws_cache_register(f, url, cache, true);
  CHECK(pws_cache_lookup(f, u, c, w));
  CHECK(w == true);

  /* Remove */
  pws_cache_remove(f);
  CHECK(!pws_cache_lookup(f, u, c, w));

  /* Remove non-existent — should not crash */
  pws_cache_remove(f);

  fclose(f);
  remove("/tmp/pws_map_dummy.tmp");
}

/* ================================================================
 *  7. Unload and reload cycle
 * ================================================================ */
static void test_unload_reload()
{
  SECTION("7. Unload and reload cycle");

  /* Ensure loaded */
  const PWSTransport *t1 = pws_find_transport("file:///tmp/x.psafe3");
  CHECK(t1 != nullptr);

  /* Unload */
  pws_transport_unload("file");

  /* Reload: must succeed and return a valid (possibly new) pointer */
  const PWSTransport *t2 = pws_find_transport("file:///tmp/x.psafe3");
  CHECK(t2 != nullptr);
  if (t2) {
    CHECK(t2->abi_version == PWSTransport_ABI_VERSION);
  }

  /* Unload again — idempotent for unknown scheme */
  pws_transport_unload("file");
  pws_transport_unload("nosuchscheme");
}

/* ================================================================
 *  8. Identity string pre-scan rejects wrong scheme
 * ================================================================ */
static void test_identity_scan_rejection()
{
  SECTION("8. Identity pre-scan: wrong scheme rejected");

  /* pwsafe-file.so is present but the scheme requested is "webdav".
   * The loader constructs "pwsafe-webdav.so" which doesn't exist, so
   * pws_find_transport returns nullptr.  This also confirms the filename
   * convention is enforced before the identity scan. */
  CHECK(pws_find_transport("webdav://host/db.psafe3") == nullptr);

  /* Sanity: the "file" scheme still loads fine */
  CHECK(pws_find_transport("file:///tmp/x.psafe3") != nullptr);

  pws_transport_unload("file");
}

/* ================================================================
 *  9. Fetch/store round-trip: cache vs destination are identical
 *
 * This mirrors Phase G of TransportTest.cpp (the GTest integration
 * test) which can't be run without a full cmake build.  We verify
 * here that after a store() the destination file is byte-for-byte
 * identical to what was in the cache, and that after a subsequent
 * fetch() the cache is restored identically.
 * ================================================================ */
static bool files_identical(const char *a, const char *b)
{
  FILE *fa = fopen(a, "rb");
  FILE *fb = fopen(b, "rb");
  if (!fa || !fb) { if (fa) fclose(fa); if (fb) fclose(fb); return false; }
  bool same = true;
  int ca, cb;
  while ((ca = fgetc(fa)) != EOF) {
    cb = fgetc(fb);
    if (ca != cb) { same = false; break; }
  }
  if (same && fgetc(fb) != EOF) same = false; /* b longer than a */
  fclose(fa); fclose(fb);
  return same;
}

static void test_cache_vs_destination()
{
  SECTION("9. Cache vs destination byte identity after store/fetch");

  const char *payload  = "PWS3fake-roundtrip-payload-9";
  const char *src_path = "/tmp/pws_rt_src.psafe3";
  const char *url_str  = "file:///tmp/pws_rt_src.psafe3";

  write_file(src_path, payload);

  const PWSTransport *t = pws_find_transport(url_str);
  assert(t);

  /* --- store: src_path → url --- */
  std::string dst_url   = std::string("file://") + src_path;
  std::string cache     = pws_get_cache_path(url_str);
  /* Use fetch to pull into cache, then compare with source */
  int rc = t->fetch(url_str, cache.c_str());
  CHECK(rc == 0);

  /* After fetch: cache == src_path */
  CHECK(files_identical(cache.c_str(), src_path));

  /* Modify the cache in place */
  const char *modified = "PWS3fake-MODIFIED";
  write_file(cache.c_str(), modified);

  /* Store cache back to a new destination */
  const char *dst_path = "/tmp/pws_rt_dst.psafe3";
  std::string dst_url2 = std::string("file://") + dst_path;
  rc = t->store(cache.c_str(), dst_url2.c_str());
  CHECK(rc == 0);

  /* After store: dst_path == cache (modified content) */
  CHECK(files_identical(dst_path, cache.c_str()));

  /* Fetch destination back into cache and verify again */
  rc = t->fetch(dst_url2.c_str(), cache.c_str());
  CHECK(rc == 0);
  CHECK(files_identical(cache.c_str(), dst_path));

  /* Original source is unchanged */
  CHECK(file_has_content(src_path, payload));

  remove(src_path);
  remove(dst_path);
}

/* ================================================================
 *  main
 * ================================================================ */
int main()
{
  printf("pwsafe transport infrastructure test suite\n");
  printf("==========================================\n");

  /* Setup: remove any stale files from previous runs */
  for (auto p : { "/tmp/pws_ops_src.psafe3", "/tmp/pws_ops_dst.psafe3",
                  "/tmp/pws_ops_dst2.psafe3", "/tmp/pws_load_test.psafe3" }) {
    remove(p);
  }

  test_scheme_detection();
  test_plugin_loading_happy();
  test_plugin_loading_errors();
  test_plugin_operations();
  test_cache_path();
  test_file_map();
  test_unload_reload();
  test_identity_scan_rejection();
  test_cache_vs_destination();

  printf("\n==========================================\n");
  printf("Results: %d passed, %d failed\n", g_pass, g_fail);
  return (g_fail == 0) ? 0 : 1;
}
