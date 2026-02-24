/*
* Copyright (c) 2003-2026 Rony Shapiro <ronys@pwsafe.org>.
* All rights reserved. Use of the code is allowed under the
* Artistic License 2.0 terms, as specified in the LICENSE file
* distributed with this code, or available from
* http://www.opensource.org/licenses/artistic-license-2.0.php
*/
// TransportTest.cpp — end-to-end integration test for the transport plugin
// infrastructure, exercised through the high-level PWScore API.
//
// Every database open/save goes through pws_os::FOpen / FClose so the full
// transport intercept (fetch-on-open, store-on-close) is exercised.
//
// DEVELOPMENT is defined so find_plugin_path() also searches the directory of
// the test binary itself (where CMake copies pwsafe-file.so at build time).

#ifndef DEVELOPMENT
#define DEVELOPMENT 1
#endif

#ifdef WIN32
#include "../ui/Windows/stdafx.h"
#endif

#include "core/PWScore.h"
#include "core/PWCharPool.h"
#include "core/PWPolicy.h"
#include "os/file.h"
#include "os/transport.h"

#include <filesystem>
#include <fstream>
#include <vector>

#include "gtest/gtest.h"

namespace fs = std::filesystem;

// ---- local helpers ----------------------------------------------------------

static std::string toUtf8(const StringX &s)
{
  size_t n = wcstombs(nullptr, s.c_str(), 0);
  if (n == static_cast<size_t>(-1)) return "";
  std::string out(n, '\0');
  wcstombs(&out[0], s.c_str(), n + 1);
  return out;
}

static std::vector<uint8_t> read_file_bytes(const std::string &path)
{
  std::ifstream f(path, std::ios::binary);
  return { std::istreambuf_iterator<char>(f), {} };
}

// Strip "file://" (and optional "localhost") prefix → bare local path
static std::string url_to_path(const std::string &url)
{
  std::string s = url;
  if (s.substr(0, 7) == "file://") {
    s = s.substr(7);
    if (s.substr(0, 9) == "localhost")
      s = s.substr(9);
  }
  return s;
}

// ---- fixture ----------------------------------------------------------------

class TransportTest : public ::testing::Test
{
protected:
  TransportTest()
    : passkey(L"transport-test-passphrase-2026"),
      url(L"file:///tmp/pwsafe_transport_test.psafe3"),
      group(L"Test.Transport"),
      kEntry2Password(L"known-entry2-password"),
      kEntry1ChangedPassword(L"changed-entry1-password"),
      kEntry3Password(L"entry3-password")
  {}

  void TearDown() override
  {
    std::string dest  = url_to_path(toUtf8(url));
    std::string cache = pws_get_cache_path(toUtf8(url));
    remove(dest.c_str());
    remove(cache.c_str());
    pws_transport_unload("file");
  }

  const StringX passkey;
  const StringX url;
  const StringX group;
  const StringX kEntry2Password;
  const StringX kEntry1ChangedPassword;
  const StringX kEntry3Password;
};

// ---- the test ---------------------------------------------------------------

TEST_F(TransportTest, FullLifecycle)
{
  // ===========================================================================
  // Phase A: create database, add entries 1 and 2
  // ===========================================================================
  PWScore core;
  core.NewFile(passkey);

  // Generate a random password for Entry 1 using the PWScore password generator
  PWPolicy policy;
  policy.flags = PWPolicy::UseLowercase | PWPolicy::UseUppercase | PWPolicy::UseDigits;
  policy.length = 16;
  policy.lowerminlength = policy.upperminlength = 1;
  policy.digitminlength = policy.symbolminlength = 0;
  StringX entry1_generated_pw = CPasswordCharPool(policy).MakePassword();
  ASSERT_FALSE(entry1_generated_pw.empty());

  // Entry 1 — generated password
  CItemData item1;
  item1.CreateUUID();
  item1.SetGroup(group);
  item1.SetTitle(L"Entry1");
  item1.SetPassword(entry1_generated_pw);
  core.Execute(AddEntryCommand::Create(&core, item1));

  // Entry 2 — known constant password
  CItemData item2;
  item2.CreateUUID();
  item2.SetGroup(group);
  item2.SetTitle(L"Entry2");
  item2.SetPassword(kEntry2Password);
  core.Execute(AddEntryCommand::Create(&core, item2));

  // ===========================================================================
  // Phase B: read back Entry 1 by group+title, verify generated password
  // ===========================================================================
  {
    ItemListIter it = core.Find(group, L"Entry1", L"");
    ASSERT_NE(core.GetEntryEndIter(), it) << "Entry1 not found after add";
    EXPECT_EQ(entry1_generated_pw, core.GetEntry(it).GetPassword())
      << "Entry1 password should match the generated value";
  }

  // ===========================================================================
  // Phase C: change Entry 1's password
  // ===========================================================================
  {
    ItemListIter it = core.Find(group, L"Entry1", L"");
    ASSERT_NE(core.GetEntryEndIter(), it);
    CItemData updated = core.GetEntry(it);
    updated.SetPassword(kEntry1ChangedPassword);
    core.Execute(EditEntryCommand::Create(&core, core.GetEntry(it), updated));
  }

  // ===========================================================================
  // Phase D: add Entry 3
  // ===========================================================================
  {
    CItemData item3;
    item3.CreateUUID();
    item3.SetGroup(group);
    item3.SetTitle(L"Entry3");
    item3.SetPassword(kEntry3Password);
    core.Execute(AddEntryCommand::Create(&core, item3));
  }

  EXPECT_EQ(3U, core.GetNumEntries());

  // ===========================================================================
  // Phase E: save via file:// URL
  //   pws_os::FOpen opens the local cache for writing;
  //   pws_os::FClose stores the cache to the file:// destination.
  // ===========================================================================
  ASSERT_EQ(PWScore::SUCCESS, core.WriteFile(url, PWSfile::V30))
    << "WriteFile via file:// URL failed";
  core.ClearCommands();

  std::string cache_path = pws_get_cache_path(toUtf8(url));
  std::string dest_path  = url_to_path(toUtf8(url));

  ASSERT_TRUE(fs::exists(dest_path))  << "Destination file not created by store()";
  ASSERT_TRUE(fs::exists(cache_path)) << "Cache file missing after write";

  // ===========================================================================
  // Phase F: reopen via the same file:// URL
  //   FOpen fetches the destination back into the local cache and opens it.
  // ===========================================================================
  {
    PWScore core2;
    ASSERT_EQ(PWScore::SUCCESS, core2.ReadFile(url, passkey))
      << "ReadFile via file:// URL failed";

    EXPECT_EQ(3U, core2.GetNumEntries()) << "Expected 3 entries after reload";

    // Entry 1 must have the *changed* password
    ItemListIter r1 = core2.Find(group, L"Entry1", L"");
    ASSERT_NE(core2.GetEntryEndIter(), r1) << "Entry1 not found after reload";
    EXPECT_EQ(kEntry1ChangedPassword, core2.GetEntry(r1).GetPassword())
      << "Entry1 should have the changed password after reload";

    // Entry 2 unchanged
    ItemListIter r2 = core2.Find(group, L"Entry2", L"");
    ASSERT_NE(core2.GetEntryEndIter(), r2) << "Entry2 not found after reload";
    EXPECT_EQ(kEntry2Password, core2.GetEntry(r2).GetPassword())
      << "Entry2 password should be unchanged";

    // Entry 3 present
    ItemListIter r3 = core2.Find(group, L"Entry3", L"");
    ASSERT_NE(core2.GetEntryEndIter(), r3) << "Entry3 not found after reload";
    EXPECT_EQ(kEntry3Password, core2.GetEntry(r3).GetPassword())
      << "Entry3 password mismatch";
  }

  // ===========================================================================
  // Phase G: compare cache file vs destination file byte-for-byte
  //   file_fetch is a plain copy so they must be identical.
  //   A mismatch means store() or fetch() is corrupting data.
  // ===========================================================================
  {
    auto cache_bytes = read_file_bytes(cache_path);
    auto dest_bytes  = read_file_bytes(dest_path);

    ASSERT_FALSE(cache_bytes.empty()) << "Cache file is empty";
    ASSERT_FALSE(dest_bytes.empty())  << "Destination file is empty";
    EXPECT_EQ(cache_bytes.size(), dest_bytes.size())
      << "Cache and destination have different sizes";
    EXPECT_EQ(cache_bytes, dest_bytes)
      << "Cache and destination are not byte-for-byte identical; "
         "store() or fetch() is corrupting data";
  }
}
