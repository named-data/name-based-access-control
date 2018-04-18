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
 * @author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "consumer.hpp"
#include "boost-test.hpp"
#include "unit-test-time-fixture.hpp"
#include "algo/encryptor.hpp"

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/dummy-client-face.hpp>
#include <ndn-cxx/util/time-unit-test-clock.hpp>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>

namespace ndn {
namespace nac {
namespace tests {

static const uint8_t DATA_CONTEN[] = {0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
                                      0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
                                      0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
                                      0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c};

static const uint8_t AES_KEY[] =
  {0xdd, 0x60, 0x77, 0xec, 0xa9, 0x6b, 0x23, 0x1b, 0x40, 0x6b, 0x5a, 0xf8, 0x7d, 0x3d, 0x55, 0x32};

static const uint8_t IV[] =
  {0x73, 0x6f, 0x6d, 0x65, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72};

class ConsumerFixture : public UnitTestTimeFixture
{
public:
  ConsumerFixture()
    : tmpPath(boost::filesystem::path(TMP_TESTS_PATH))
    , face1(io, keyChain, {true, true})
    , face2(io, keyChain, {true, true})
    , readInterestOffset1(0)
    , readDataOffset1(0)
    , readInterestOffset2(0)
    , readDataOffset2(0)
    , groupName("/Prefix/READ")
    , contentName("/Prefix/SAMPLE/Content")
    , cKeyName("/Prefix/SAMPLE/Content/C-KEY/1")
    , eKeyName("/Prefix/READ/E-KEY/1/2")
    , dKeyName("/Prefix/READ/D-KEY/1/2")
    , uKeyName("/U/Key")
    , uName("/U")
  {
    boost::filesystem::create_directories(tmpPath);

    // generate e/d key
    RsaKeyParams params;
    fixtureDKeyBuf = algo::Rsa::generateKey(params).getKeyBits();
    fixtureEKeyBuf = algo::Rsa::deriveEncryptKey(fixtureDKeyBuf).getKeyBits();

    // generate user key
    fixtureUDKeyBuf = algo::Rsa::generateKey(params).getKeyBits();
    fixtureUEKeyBuf = algo::Rsa::deriveEncryptKey(fixtureUDKeyBuf).getKeyBits();

    // load C-KEY
    fixtureCKeyBuf = Buffer(AES_KEY, sizeof(AES_KEY));
  }

  ~ConsumerFixture()
  {
    boost::filesystem::remove_all(tmpPath);
  }

  shared_ptr<Data>
  createEncryptedContent()
  {
    shared_ptr<Data> contentData = make_shared<Data>(contentName);
    algo::EncryptParams eparams(tlv::AlgorithmAesCbc);
    eparams.setIV(IV, sizeof(IV));
    algo::encryptData(*contentData,
                      DATA_CONTEN,
                      sizeof(DATA_CONTEN),
                      cKeyName,
                      fixtureCKeyBuf.data(),
                      fixtureCKeyBuf.size(),
                      eparams);
    keyChain.sign(*contentData);
    return contentData;
  }

  shared_ptr<Data>
  createEncryptedCKey()
  {
    shared_ptr<Data> cKeyData = make_shared<Data>(cKeyName);
    algo::EncryptParams eparams(tlv::AlgorithmRsaOaep);
    algo::encryptData(*cKeyData,
                      fixtureCKeyBuf.data(),
                      fixtureCKeyBuf.size(),
                      dKeyName,
                      fixtureEKeyBuf.data(),
                      fixtureEKeyBuf.size(),
                      eparams);
    keyChain.sign(*cKeyData);
    return cKeyData;
  }

  shared_ptr<Data>
  createEncryptedDKey()
  {
    shared_ptr<Data> dKeyData = make_shared<Data>(dKeyName);
    algo::EncryptParams eparams(tlv::AlgorithmRsaOaep);
    algo::encryptData(*dKeyData,
                      fixtureDKeyBuf.data(),
                      fixtureDKeyBuf.size(),
                      uKeyName,
                      fixtureUEKeyBuf.data(),
                      fixtureUEKeyBuf.size(),
                      eparams);
    keyChain.sign(*dKeyData);
    return dKeyData;
  }

  bool
  passPacket()
  {
    bool hasPassed = false;

    checkFace(face1.sentInterests, readInterestOffset1, face2, hasPassed);
    checkFace(face1.sentData, readDataOffset1, face2, hasPassed);
    checkFace(face2.sentInterests, readInterestOffset2, face1, hasPassed);
    checkFace(face2.sentData, readDataOffset2, face1, hasPassed);

    return hasPassed;
  }

  template<typename Packet>
  void
  checkFace(std::vector<Packet>& receivedPackets,
            size_t& readPacketOffset,
            util::DummyClientFace& receiver,
            bool& hasPassed)
  {
    while (receivedPackets.size() > readPacketOffset) {
      receiver.receive(receivedPackets[readPacketOffset]);
      readPacketOffset++;
      hasPassed = true;
    }
  }

public:
  boost::filesystem::path tmpPath;

  util::DummyClientFace face1;
  util::DummyClientFace face2;

  size_t readInterestOffset1;
  size_t readDataOffset1;
  size_t readInterestOffset2;
  size_t readDataOffset2;

  KeyChain keyChain;

  Buffer fixtureCKeyBuf;
  Buffer fixtureEKeyBuf;
  Buffer fixtureDKeyBuf;
  Buffer fixtureUEKeyBuf;
  Buffer fixtureUDKeyBuf;

  Name groupName;
  Name contentName;
  Name cKeyName;
  Name eKeyName;
  Name dKeyName;
  Name uKeyName;
  Name uName;
};

BOOST_FIXTURE_TEST_SUITE(TestConsumer, ConsumerFixture)

BOOST_AUTO_TEST_CASE(DecryptContent)
{
  std::string dbDir = tmpPath.c_str();
  dbDir += "/test.db";

  // generate AES key pairs
  Buffer aesKeyBuf = Buffer(AES_KEY, sizeof(AES_KEY));

  // generate C-KEY packet
  auto cKeyData = createEncryptedCKey();
  // generate Content packet
  auto contentData = createEncryptedContent();

  // create consumer
  Consumer consumer(face1, Name("/Group"), Name("/U"), dbDir);

  // decrypt
  consumer.decrypt(cKeyData->getContent().blockFromValue(),
                   fixtureDKeyBuf,
                   [=] (const Buffer& result) {
                     BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(),
                                                   result.end(),
                                                   aesKeyBuf.begin(),
                                                   aesKeyBuf.end());
                   },
                   [=] (const ErrorCode&, const std::string&) { BOOST_CHECK(false); });

  // decrypt
  consumer.decrypt(contentData->getContent().blockFromValue(),
                   fixtureCKeyBuf,
                   [=] (const Buffer& result) {
                     BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(),
                                                   result.end(),
                                                   DATA_CONTEN,
                                                   DATA_CONTEN + sizeof(DATA_CONTEN));
                   },
                   [=] (const ErrorCode&, const std::string&) { BOOST_CHECK(false); });
}

BOOST_AUTO_TEST_CASE(Consume)
{
  auto contentData = createEncryptedContent();
  auto cKeyData = createEncryptedCKey();
  auto dKeyData = createEncryptedDKey();

  int contentCount = 0;
  int cKeyCount = 0;
  int dKeyCount = 0;

  Name prefix("/Prefix");
  // prepare face1
  face1.setInterestFilter(prefix,
                          [&] (const InterestFilter&, const Interest& i) {
                            if (i.matchesData(*contentData)) {
                              contentCount = 1;
                              face1.put(*contentData);
                              return;
                            }
                            if (i.matchesData(*cKeyData)) {
                              cKeyCount = 1;
                              face1.put(*cKeyData);
                              return;
                            }
                            if (i.matchesData(*dKeyData)) {
                              dKeyCount = 1;
                              face1.put(*dKeyData);
                              return;
                            }
                            return;
                          },
                          RegisterPrefixSuccessCallback(),
                          [] (const Name&, const std::string& e) {});

  do {
    advanceClocks(time::milliseconds(10), 20);
  } while (passPacket());

  // create consumer
  std::string dbDir = tmpPath.c_str();
  dbDir += "/test.db";
  Consumer consumer(face2, groupName, uName, dbDir);
  consumer.addDecryptionKey(uKeyName, fixtureUDKeyBuf);

  int finalCount = 0;
  consumer.consume(contentName,
                   [&] (const Data& data, const Buffer& result) {
                     finalCount = 1;
                     BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(),
                                                   result.end(),
                                                   DATA_CONTEN,
                                                   DATA_CONTEN + sizeof(DATA_CONTEN));
                   },
                   [&] (const ErrorCode& code, const std::string& str) { BOOST_CHECK(false); });

  do {
    advanceClocks(time::milliseconds(10), 20);
  } while (passPacket());

  BOOST_CHECK_EQUAL(contentCount, 1);
  BOOST_CHECK_EQUAL(cKeyCount, 1);
  BOOST_CHECK_EQUAL(dKeyCount, 1);
  BOOST_CHECK_EQUAL(finalCount, 1);
}

BOOST_AUTO_TEST_CASE(CosumerWithLink)
{
  auto contentData = createEncryptedContent();
  auto cKeyData = createEncryptedCKey();
  auto dKeyData = createEncryptedDKey();

  int contentCount = 0;
  int cKeyCount = 0;
  int dKeyCount = 0;
  int resultCount = 0;

  Name prefix("/Prefix");
  // prepare face1
  face1.setInterestFilter(prefix,
                          [&] (const InterestFilter&, const Interest& i) {
                            BOOST_CHECK(i.getForwardingHint().size() == 3);
                            if (i.matchesData(*contentData)) {
                              contentCount++;
                              face1.put(*contentData);
                              return;
                            }
                            if (i.matchesData(*cKeyData)) {
                              cKeyCount++;
                              face1.put(*cKeyData);
                              return;
                            }
                            if (i.matchesData(*dKeyData)) {
                              dKeyCount++;
                              face1.put(*dKeyData);
                              return;
                            }
                            return;
                          },
                          RegisterPrefixSuccessCallback(),
                          [] (const Name&, const std::string& e) {});

  do {
    advanceClocks(time::milliseconds(10), 20);
  } while (passPacket());

  // create consumer
  std::string dbDir = tmpPath.c_str();
  dbDir += "/test.db";

  Link ckeylink("ckey", {{10, "/ckey1"}, {20, "/ckey2"}, {100, "/ckey3"}});
  Link dkeylink("dkey", {{10, "/dkey1"}, {20, "/dkey2"}, {100, "/dkey3"}});
  Link datalink("data", {{10, "/data1"}, {20, "/data2"}, {100, "/data3"}});
  keyChain.sign(ckeylink);
  keyChain.sign(dkeylink);
  keyChain.sign(datalink);

  Consumer consumer(face2, groupName, uName, dbDir, ckeylink, dkeylink);
  consumer.addDecryptionKey(uKeyName, fixtureUDKeyBuf);

  consumer.consume(contentName,
                   [&] (const Data& data, const Buffer& result) {
                     BOOST_CHECK(true);
                     resultCount++;
                   },
                   [] (const ErrorCode& code, const std::string& str) { BOOST_CHECK(false); },
                   datalink);

  do {
    advanceClocks(time::milliseconds(10), 200);
  } while (passPacket());

  BOOST_CHECK_EQUAL(resultCount, 1);
  BOOST_CHECK_EQUAL(contentCount, 1);
  BOOST_CHECK_EQUAL(cKeyCount, 1);
  BOOST_CHECK_EQUAL(dKeyCount, 1);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nac
} // namespace ndn
