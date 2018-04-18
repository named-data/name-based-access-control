/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2018, Regents of the University of California
 *
 * This file is part of NAC (Name-Based Access Control for NDN).
 * See AUTHORS.md for complete list of NAC authors and contributors.
 *
 * NAC is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NAC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NAC, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Zhiyi Zhang <zhiyi@cs.ucla.edu>
 */

#include "consumer-db.hpp"
#include "boost-test.hpp"
#include "algo/aes.hpp"
#include "algo/rsa.hpp"

#include <boost/filesystem.hpp>

namespace ndn {
namespace nac {
namespace tests {

class ConsumerDBFixture
{
public:
  ConsumerDBFixture()
    : tmpPath(boost::filesystem::path(TMP_TESTS_PATH))
  {
    boost::filesystem::create_directories(tmpPath);
  }

  ~ConsumerDBFixture()
  {
    boost::filesystem::remove_all(tmpPath);
  }

  void
  generateRsaKey(Buffer& encryptionKeyBuf, Buffer& decryptionKeyBuf)
  {
    RsaKeyParams params;
    DecryptKey<algo::Rsa> dKey = algo::Rsa::generateKey(params);
    decryptionKeyBuf = dKey.getKeyBits();
    EncryptKey<algo::Rsa> eKey = algo::Rsa::deriveEncryptKey(decryptionKeyBuf);
    encryptionKeyBuf = eKey.getKeyBits();
  }

  void
  generateAesKey(Buffer& encryptionKeyBuf, Buffer& decryptionKeyBuf)
  {
    AesKeyParams params;
    DecryptKey<algo::Aes> memberDecryptKey = algo::Aes::generateKey(params);
    decryptionKeyBuf = memberDecryptKey.getKeyBits();
    EncryptKey<algo::Aes> memberEncryptKey = algo::Aes::deriveEncryptKey(decryptionKeyBuf);
    encryptionKeyBuf = memberEncryptKey.getKeyBits();
  }

public:
  boost::filesystem::path tmpPath;
};

BOOST_FIXTURE_TEST_SUITE(TestConsumerDB, ConsumerDBFixture)

BOOST_AUTO_TEST_CASE(OperateAesDecryptionKey)
{
  // construction
  std::string dbDir = tmpPath.c_str();
  dbDir += "/test.db";
  ConsumerDB db(dbDir);

  // generate key buffer
  Buffer eKeyBuf;
  Buffer dKeyBuf;
  generateAesKey(eKeyBuf, dKeyBuf);

  Name keyName("/alice/health/samples/activity/steps/C-KEY/20150928080000/20150928090000!");
  keyName.append("FOR/alice/health/read/activity!");
  db.addKey(keyName, dKeyBuf);
  Buffer resultBuf = db.getKey(keyName);

  BOOST_CHECK_EQUAL_COLLECTIONS(dKeyBuf.begin(), dKeyBuf.end(), resultBuf.begin(), resultBuf.end());

  db.deleteKey(keyName);
  resultBuf = db.getKey(keyName);

  BOOST_CHECK_EQUAL(resultBuf.size(), 0);
}

BOOST_AUTO_TEST_CASE(OperateRsaDecryptionKey)
{
  // construction
  std::string dbDir = tmpPath.c_str();
  dbDir += "/test.db";
  ConsumerDB db(dbDir);

  // generate key buffer
  Buffer eKeyBuf;
  Buffer dKeyBuf;
  generateRsaKey(eKeyBuf, dKeyBuf);

  Name keyName("/alice/health/samples/activity/steps/D-KEY/20150928080000/20150928090000!");
  keyName.append("FOR/test/member/KEY/123!");
  db.addKey(keyName, dKeyBuf);
  Buffer resultBuf = db.getKey(keyName);

  BOOST_CHECK_EQUAL_COLLECTIONS(dKeyBuf.begin(), dKeyBuf.end(), resultBuf.begin(), resultBuf.end());

  db.deleteKey(keyName);
  resultBuf = db.getKey(keyName);

  BOOST_CHECK_EQUAL(resultBuf.size(), 0);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nac
} // namespace ndn
