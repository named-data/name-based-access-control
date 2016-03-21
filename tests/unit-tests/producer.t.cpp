/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2015,  Regents of the University of California
 *
 * This file is part of ndn-group-encrypt (Group-based Encryption Protocol for NDN).
 * See AUTHORS.md for complete list of ndn-group-encrypt authors and contributors.
 *
 * ndn-group-encrypt is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * ndn-group-encrypt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndn-group-encrypt, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "producer.hpp"
#include "algo/encryptor.hpp"
#include "algo/rsa.hpp"
#include "algo/aes.hpp"
#include "encrypted-content.hpp"
#include "unit-test-time-fixture.hpp"
#include "random-number-generator.hpp"

#include <ndn-cxx/util/dummy-client-face.hpp>

#include "boost-test.hpp"
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>

namespace ndn {
namespace gep {
namespace tests {

static const uint8_t DATA_CONTEN[] = {
  0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
  0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
  0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
  0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
};

class ProducerFixture : public UnitTestTimeFixture
{
public:
  ProducerFixture()
    : tmpPath(boost::filesystem::path(TMP_TESTS_PATH))
    , face1(util::makeDummyClientFace(io, {true, true}))
    , face2(util::makeDummyClientFace(io, {true, true}))
    , readInterestOffset1(0)
    , readDataOffset1(0)
    , readInterestOffset2(0)
    , readDataOffset2(0)
  {
    boost::filesystem::create_directories(tmpPath);
  }

  ~ProducerFixture()
  {
    boost::filesystem::remove_all(tmpPath);
  }

  void
  createEncryptionKey(Name eKeyName, const Name& timeMarker)
  {
    RandomNumberGenerator rng;
    RsaKeyParams params;
    eKeyName.append(timeMarker);

    Buffer dKeyBuf = algo::Rsa::generateKey(rng, params).getKeyBits();
    Buffer eKeyBuf = algo::Rsa::deriveEncryptKey(dKeyBuf).getKeyBits();
    decryptionKeys[eKeyName] = dKeyBuf;

    shared_ptr<Data> keyData = make_shared<Data>(eKeyName);
    keyData->setContent(eKeyBuf.buf(), eKeyBuf.size());
    keyChain.sign(*keyData);
    encryptionKeys[eKeyName] = keyData;
  }

  bool
  passPacket()
  {
    bool hasPassed = false;

    checkFace(face1->sentInterests, readInterestOffset1, *face2, hasPassed);
    checkFace(face1->sentDatas, readDataOffset1, *face2, hasPassed);
    checkFace(face2->sentInterests, readInterestOffset2, *face1, hasPassed);
    checkFace(face2->sentDatas, readDataOffset2, *face1, hasPassed);

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

  shared_ptr<util::DummyClientFace> face1;
  shared_ptr<util::DummyClientFace> face2;

  size_t readInterestOffset1;
  size_t readDataOffset1;
  size_t readInterestOffset2;
  size_t readDataOffset2;

  KeyChain keyChain;

  std::unordered_map<Name, Buffer> decryptionKeys;
  std::unordered_map<Name, shared_ptr<Data>> encryptionKeys;
};

BOOST_FIXTURE_TEST_SUITE(TestProducer, ProducerFixture)

BOOST_AUTO_TEST_CASE(ContentKeyRequest)
{
  std::string dbDir = tmpPath.c_str();
  dbDir += "/test.db";

  Name prefix("/prefix");
  Name suffix("/a/b/c");
  Name expectedInterest = prefix;
  expectedInterest.append(NAME_COMPONENT_READ);
  expectedInterest.append(suffix);
  expectedInterest.append(NAME_COMPONENT_E_KEY);

  Name cKeyName = prefix;
  cKeyName.append(NAME_COMPONENT_SAMPLE);
  cKeyName.append(suffix);
  cKeyName.append(NAME_COMPONENT_C_KEY);

  Name timeMarker("20150101T100000/20150101T120000");
  time::system_clock::TimePoint testTime1 = time::fromIsoString("20150101T100001");
  time::system_clock::TimePoint testTime2 = time::fromIsoString("20150101T110001");
  name::Component testTimeRounded1("20150101T100000");
  name::Component testTimeRounded2("20150101T110000");
  name::Component testTimeComponent2("20150101T110001");

  // Create content keys required for this test case:
  for (size_t i = 0; i < suffix.size(); i++) {
    createEncryptionKey(expectedInterest, timeMarker);
    expectedInterest = expectedInterest.getPrefix(-2).append(NAME_COMPONENT_E_KEY);
  }

  face2->setInterestFilter(prefix,
         [&] (const InterestFilter&, const Interest& i) {
            Name interestName = i.getName();
            interestName.append(timeMarker);
            BOOST_REQUIRE_EQUAL(encryptionKeys.find(interestName) !=
                                encryptionKeys.end(), true);
            face2->put(*(encryptionKeys[interestName]));
            return;
         },
         RegisterPrefixSuccessCallback(),
         [] (const Name&, const std::string& e) { });

  do {
    advanceClocks(time::milliseconds(10), 20);
  } while (passPacket());

  /*
  Verify that content key is correctly encrypted for each domain, and the
  produce method encrypts provided data with the same content key.
  */
  Producer producer(prefix, suffix, *face1, dbDir);
  ProducerDB testDb(dbDir);
  Buffer contentKey;

  auto checkEncryptionKeys =
          [&](const std::vector<Data>& result,
              const time::system_clock::TimePoint& testTime,
              const name::Component& roundedTime) {
            BOOST_CHECK_EQUAL(testDb.hasContentKey(testTime), true);
            contentKey = testDb.getContentKey(testTime);

            algo::EncryptParams params(tlv::AlgorithmRsaOaep);
            std::vector<Data>::const_iterator it;
            for (it = result.begin(); it != result.end(); ++it) {
              Name keyName = it->getName();
              BOOST_CHECK_EQUAL(keyName.getSubName(0,6), cKeyName);
              BOOST_CHECK_EQUAL(keyName.get(6), roundedTime);
              BOOST_CHECK_EQUAL(keyName.get(7), NAME_COMPONENT_FOR);
              BOOST_CHECK_EQUAL(decryptionKeys.find(keyName.getSubName(8)) !=
                                decryptionKeys.end(), true);
              Name testName = it->getName().getSubName(-8);
              Buffer decryptionKey;

              decryptionKey = decryptionKeys.at(keyName.getSubName(8));
              BOOST_CHECK_EQUAL(decryptionKey.size() != 0, true);
              Block encryptedKeyBlock = it->getContent();
              encryptedKeyBlock.parse();

              EncryptedContent content(*(encryptedKeyBlock.elements_begin()));
              const Buffer& encryptedKey = content.getPayload();
              Buffer retrievedKey = algo::Rsa::decrypt(decryptionKey.buf(),
                                                       decryptionKey.size(),
                                                       encryptedKey.buf(),
                                                       encryptedKey.size(),
                                                       params);

              BOOST_CHECK_EQUAL_COLLECTIONS(contentKey.begin(),
                                            contentKey.end(),
                                            retrievedKey.begin(),
                                            retrievedKey.end());
            }
            BOOST_CHECK_EQUAL(result.size(), 3);
          };

  // Initial test to confirm that keys are created for this timeslot
  Name contentKeyName1 =
      producer.createContentKey(testTime1,
      std::bind(checkEncryptionKeys, _1, testTime1, testTimeRounded1));

  do {
    advanceClocks(time::milliseconds(10), 20);
  } while (passPacket());

  // Verify that we do not repeat the search for e-keys, don't advance clock
  Name contentKeyName2 =
      producer.createContentKey(testTime2,
      std::bind(checkEncryptionKeys, _1, testTime2, testTimeRounded2));

  // Confirm content key names are correct
  BOOST_CHECK_EQUAL(contentKeyName1.getPrefix(-1), cKeyName);
  BOOST_CHECK_EQUAL(contentKeyName1.get(6), testTimeRounded1);
  BOOST_CHECK_EQUAL(contentKeyName2.getPrefix(-1), cKeyName);
  BOOST_CHECK_EQUAL(contentKeyName2.get(6), testTimeRounded2);

  // Confirm produce encrypts with correct key and has right name
  Data testData;
  producer.produce(testData, testTime2, DATA_CONTEN, sizeof(DATA_CONTEN));

  Name producedName = testData.getName();
  BOOST_CHECK_EQUAL(producedName.getSubName(0,5), cKeyName.getPrefix(-1));
  BOOST_CHECK_EQUAL(producedName.get(5), testTimeComponent2);
  BOOST_CHECK_EQUAL(producedName.get(6), NAME_COMPONENT_FOR);
  BOOST_CHECK_EQUAL(producedName.getSubName(7,6), cKeyName);
  BOOST_CHECK_EQUAL(producedName.get(13), testTimeRounded2);

  Block dataBlock = testData.getContent();
  dataBlock.parse();

  EncryptedContent dataContent(*(dataBlock).elements_begin());
  const Buffer& encData = dataContent.getPayload();
  const Buffer& iv = dataContent.getInitialVector();

  algo::EncryptParams params(tlv::AlgorithmAesCbc, 16);
  params.setIV(iv.buf(), iv.size());
  Buffer decryptTest = algo::Aes::decrypt(contentKey.buf(), contentKey.size(),
                                          encData.buf(), encData.size(), params);
  BOOST_CHECK_EQUAL_COLLECTIONS(decryptTest.begin(),
                                decryptTest.end(),
                                DATA_CONTEN,
                                DATA_CONTEN + sizeof(DATA_CONTEN));
}

BOOST_AUTO_TEST_CASE(ContentKeySearch)
{
  std::string dbDir = tmpPath.c_str();
  dbDir += "/test.db";

  Name timeMarkerFirstHop("20150101T070000/20150101T080000");
  Name timeMarkerSecondHop("20150101T080000/20150101T090000");
  Name timeMarkerThirdHop("20150101T100000/20150101T110000");

  Name prefix("/prefix");
  Name suffix("/suffix");
  Name expectedInterest = prefix;
  expectedInterest.append(NAME_COMPONENT_READ);
  expectedInterest.append(suffix);
  expectedInterest.append(NAME_COMPONENT_E_KEY);

  Name cKeyName = prefix;
  cKeyName.append(NAME_COMPONENT_SAMPLE);
  cKeyName.append(suffix);
  cKeyName.append(NAME_COMPONENT_C_KEY);

  time::system_clock::TimePoint testTime = time::fromIsoString("20150101T100001");

  // Create content keys required for this test case:
  createEncryptionKey(expectedInterest, timeMarkerFirstHop);
  createEncryptionKey(expectedInterest, timeMarkerSecondHop);
  createEncryptionKey(expectedInterest, timeMarkerThirdHop);

  size_t requestCount = 0;
  face2->setInterestFilter(prefix,
         [&] (const InterestFilter&, const Interest& i) {
            BOOST_REQUIRE_EQUAL(i.getName(), expectedInterest);
            Name interestName = i.getName();
            switch(requestCount) {
              case 0:
                interestName.append(timeMarkerFirstHop);
                break;

              case 1:
                interestName.append(timeMarkerSecondHop);
                break;

              case 2:
                interestName.append(timeMarkerThirdHop);
                break;

              default:
                break;
            }
            face2->put(*(encryptionKeys[interestName]));
            requestCount++;
            return;
         },
         RegisterPrefixSuccessCallback(),
         [] (const Name&, const std::string& e) { });

  do {
    advanceClocks(time::milliseconds(10), 20);
  } while (passPacket());

  /*
  Verify that if a key is found, but not within the right timeslot, the search
  is refined until a valid timeslot is found.
  */
  Producer producer(prefix, suffix, *face1, dbDir);
  producer.createContentKey(testTime,
          [&](const std::vector<Data>& result){
            BOOST_CHECK_EQUAL(requestCount, 3);
            BOOST_CHECK_EQUAL(result.size(), 1);

            Data keyData = result[0];
            Name keyName = keyData.getName();
            BOOST_CHECK_EQUAL(keyName.getSubName(0,4), cKeyName);
            BOOST_CHECK_EQUAL(keyName.get(4), timeMarkerThirdHop[0]);
            BOOST_CHECK_EQUAL(keyName.get(5), NAME_COMPONENT_FOR);
            BOOST_CHECK_EQUAL(keyName.getSubName(6),
                              expectedInterest.append(timeMarkerThirdHop));
          });
  do {
    advanceClocks(time::milliseconds(10), 20);
  } while (passPacket());
}

BOOST_AUTO_TEST_CASE(ContentKeyTimeout)
{
  std::string dbDir = tmpPath.c_str();
  dbDir += "/test.db";

  Name prefix("/prefix");
  Name suffix("/suffix");
  Name expectedInterest = prefix;
  expectedInterest.append(NAME_COMPONENT_READ);
  expectedInterest.append(suffix);
  expectedInterest.append(NAME_COMPONENT_E_KEY);

  time::system_clock::TimePoint testTime = time::fromIsoString("20150101T100001");

  size_t timeoutCount = 0;
  face2->setInterestFilter(prefix,
         [&] (const InterestFilter&, const Interest& i) {
            BOOST_CHECK_EQUAL(i.getName(), expectedInterest);
            timeoutCount++;
            return;
         },
         RegisterPrefixSuccessCallback(),
         [] (const Name&, const std::string& e) { });

  do {
    advanceClocks(time::milliseconds(10), 20);
  } while (passPacket());

  /*
  Verify that if no response is received, the producer appropriately times out.
  The result vector should not contain elements that have timed out.
  */
  Producer producer(prefix, suffix, *face1, dbDir);
  producer.createContentKey(testTime,
          [&](const std::vector<Data>& result){
            BOOST_CHECK_EQUAL(timeoutCount, 4);
            BOOST_CHECK_EQUAL(result.size(), 0);
          });

  do {
    advanceClocks(time::milliseconds(10), 500);
  } while (passPacket());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace gep
} // namespace ndn
