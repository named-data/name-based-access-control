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
 *
 * @author Zhiyi Zhang <dreamerbarrychang@gmail.com>
 */

#include "group-manager.hpp"
#include "boost-test.hpp"
#include "algo/rsa.hpp"
#include "algo/aes.hpp"
#include "encrypted-content.hpp"

#include <boost/filesystem.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <string>

namespace ndn {
namespace gep {
namespace tests {

using namespace boost::posix_time;

const uint8_t SIG_INFO[] = {
  0x16, 0x1b, // SignatureInfo
      0x1b, 0x01, // SignatureType
          0x01,
      0x1c, 0x16, // KeyLocator
          0x07, 0x14, // Name
              0x08, 0x04,
                  0x74, 0x65, 0x73, 0x74,
              0x08, 0x03,
                  0x6b, 0x65, 0x79,
              0x08, 0x07,
                  0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72
};

const uint8_t SIG_VALUE[] = {
  0x17, 0x80, // SignatureValue
      0x2f, 0xd6, 0xf1, 0x6e, 0x80, 0x6f, 0x10, 0xbe, 0xb1, 0x6f, 0x3e, 0x31, 0xec,
      0xe3, 0xb9, 0xea, 0x83, 0x30, 0x40, 0x03, 0xfc, 0xa0, 0x13, 0xd9, 0xb3, 0xc6,
      0x25, 0x16, 0x2d, 0xa6, 0x58, 0x41, 0x69, 0x62, 0x56, 0xd8, 0xb3, 0x6a, 0x38,
      0x76, 0x56, 0xea, 0x61, 0xb2, 0x32, 0x70, 0x1c, 0xb6, 0x4d, 0x10, 0x1d, 0xdc,
      0x92, 0x8e, 0x52, 0xa5, 0x8a, 0x1d, 0xd9, 0x96, 0x5e, 0xc0, 0x62, 0x0b, 0xcf,
      0x3a, 0x9d, 0x7f, 0xca, 0xbe, 0xa1, 0x41, 0x71, 0x85, 0x7a, 0x8b, 0x5d, 0xa9,
      0x64, 0xd6, 0x66, 0xb4, 0xe9, 0x8d, 0x0c, 0x28, 0x43, 0xee, 0xa6, 0x64, 0xe8,
      0x55, 0xf6, 0x1c, 0x19, 0x0b, 0xef, 0x99, 0x25, 0x1e, 0xdc, 0x78, 0xb3, 0xa7,
      0xaa, 0x0d, 0x14, 0x58, 0x30, 0xe5, 0x37, 0x6a, 0x6d, 0xdb, 0x56, 0xac, 0xa3,
      0xfc, 0x90, 0x7a, 0xb8, 0x66, 0x9c, 0x0e, 0xf6, 0xb7, 0x64, 0xd1
};

class GroupManagerFixture
{
public:
  GroupManagerFixture()
    : tmpPath(boost::filesystem::path(TMP_TESTS_PATH))
  {
    boost::filesystem::create_directories(tmpPath);

    // generate the certificate public key
    RandomNumberGenerator rng;
    RsaKeyParams params;
    DecryptKey<algo::Rsa> memberDecryptKey = algo::Rsa::generateKey(rng, params);
    decryptKeyBuf = memberDecryptKey.getKeyBits();
    EncryptKey<algo::Rsa> memberEncryptKey = algo::Rsa::deriveEncryptKey(decryptKeyBuf);
    encryptKeyBuf = memberEncryptKey.getKeyBits();

    // generate certificate
    cert.setName(Name("/ndn/memberA/KEY/ksk-123/ID-CERT/123"));
    PublicKey contentPubKey(encryptKeyBuf.buf(), encryptKeyBuf.size());
    cert.setPublicKeyInfo(contentPubKey);
    cert.encode();

    Block sigInfoBlock(SIG_INFO, sizeof(SIG_INFO));
    Block sigValueBlock(SIG_VALUE, sizeof(SIG_VALUE));

    Signature sig(sigInfoBlock, sigValueBlock);
    cert.setSignature(sig);

    auto dataBlock = cert.wireEncode();
  }

  void
  setManager(GroupManager& manager)
  {
    // set the first schedule
    Schedule schedule1;
    RepetitiveInterval interval11(from_iso_string("20150825T000000"),
                                  from_iso_string("20150827T000000"),
                                  5, 10, 2, RepetitiveInterval::RepeatUnit::DAY);
    RepetitiveInterval interval12(from_iso_string("20150825T000000"),
                                  from_iso_string("20150827T000000"),
                                  6, 8, 1, RepetitiveInterval::RepeatUnit::DAY);
    RepetitiveInterval interval13(from_iso_string("20150827T000000"),
                                  from_iso_string("20150827T000000"),
                                  7, 8);
    schedule1.addWhiteInterval(interval11);
    schedule1.addWhiteInterval(interval12);
    schedule1.addBlackInterval(interval13);

    // set the second schedule
    Schedule schedule2;
    RepetitiveInterval interval21(from_iso_string("20150825T000000"),
                                  from_iso_string("20150827T000000"),
                                  9, 12, 1, RepetitiveInterval::RepeatUnit::DAY);
    RepetitiveInterval interval22(from_iso_string("20150827T000000"),
                                  from_iso_string("20150827T000000"),
                                  6, 8);
    RepetitiveInterval interval23(from_iso_string("20150827T000000"),
                                  from_iso_string("20150827T000000"),
                                  2, 4);
    schedule2.addWhiteInterval(interval21);
    schedule2.addWhiteInterval(interval22);
    schedule2.addBlackInterval(interval23);

    // add to the group manager db
    manager.addSchedule("schedule1", schedule1);
    manager.addSchedule("schedule2", schedule2);

    // do some adaptions to certificate
    Block dataBlock = cert.wireEncode();

    Data memberA(dataBlock);
    memberA.setName(Name("/ndn/memberA/KEY/ksk-123/ID-CERT/123"));
    Data memberB(dataBlock);
    memberB.setName(Name("/ndn/memberB/KEY/ksk-123/ID-CERT/123"));
    Data memberC(dataBlock);
    memberC.setName(Name("/ndn/memberC/KEY/ksk-123/ID-CERT/123"));

    // add members to the database
    manager.addMember("schedule1", memberA);
    manager.addMember("schedule1", memberB);
    manager.addMember("schedule2", memberC);
  }

  ~GroupManagerFixture()
  {
    boost::filesystem::remove_all(tmpPath);
  }

public:
  boost::filesystem::path tmpPath;
  Buffer decryptKeyBuf;
  Buffer encryptKeyBuf;
  IdentityCertificate cert;
};

BOOST_FIXTURE_TEST_SUITE(TestGroupManager, GroupManagerFixture)

BOOST_AUTO_TEST_CASE(CreateDKeyData)
{
  // create the group manager database
  std::string dbDir = tmpPath.c_str();
  dbDir += "/manager-d-key-test.db";
  GroupManager manager(Name("Alice"), Name("data_type"), dbDir, 2048, 1);

  Block newCertBlock = cert.wireEncode();
  IdentityCertificate newCert(newCertBlock);

  // encrypt D-KEY
  Data data = manager.createDKeyData("20150825T000000", "20150827T000000", Name("/ndn/memberA/KEY"),
                                     decryptKeyBuf, newCert.getPublicKeyInfo().get());

  // verify encrypted D-KEY
  Block dataContent = data.getContent();
  dataContent.parse();
  BOOST_CHECK_EQUAL(dataContent.elements_size(), 2);

  // get nonce key
  Block::element_const_iterator contentIterator = dataContent.elements_begin();
  Block nonceContent(*contentIterator);
  BOOST_CHECK_EQUAL(nonceContent.type(), tlv::EncryptedContent);
  EncryptedContent encryptedNonce(nonceContent);
  BOOST_CHECK_EQUAL(encryptedNonce.getInitialVector().size(), 0);
  BOOST_CHECK_EQUAL(encryptedNonce.getAlgorithmType(), tlv::AlgorithmRsaOaep);

  const Buffer& bufferNonce = encryptedNonce.getPayload();
  algo::EncryptParams decryptParams(tlv::AlgorithmRsaOaep);
  Buffer nonce = algo::Rsa::decrypt(decryptKeyBuf.buf(), decryptKeyBuf.size(),
                                    bufferNonce.buf(), bufferNonce.size(), decryptParams);

  // get D-KEY
  contentIterator++;
  Block payloadContent(*contentIterator);
  BOOST_CHECK_EQUAL(payloadContent.type(), tlv::EncryptedContent);
  EncryptedContent encryptedPayload(payloadContent);
  BOOST_CHECK_EQUAL(encryptedPayload.getInitialVector().size(), 16);
  BOOST_CHECK_EQUAL(encryptedPayload.getAlgorithmType(), tlv::AlgorithmAesCbc);

  decryptParams.setAlgorithmType(tlv::AlgorithmAesCbc);
  decryptParams.setIV(encryptedPayload.getInitialVector().buf(),
                      encryptedPayload.getInitialVector().size());
  const Buffer& bufferPayload = encryptedPayload.getPayload();
  Buffer largePayload = algo::Aes::decrypt(nonce.buf(), nonce.size(),
                                           bufferPayload.buf(), bufferPayload.size(),
                                           decryptParams);

  BOOST_CHECK_EQUAL_COLLECTIONS(largePayload.begin(), largePayload.end(),
                                decryptKeyBuf.begin(), decryptKeyBuf.end());
}

BOOST_AUTO_TEST_CASE(CreateEKeyData)
{
  // create the group manager database
  std::string dbDir = tmpPath.c_str();
  dbDir += "/manager-e-key-test.db";

  // create group manager
  GroupManager manager(Name("Alice"), Name("data_type"), dbDir, 1024, 1);
  setManager(manager);

  Data data = manager.createEKeyData("20150825T090000", "20150825T110000", encryptKeyBuf);
  BOOST_CHECK_EQUAL(data.getName().toUri(),
                    "/Alice/READ/data_type/E-KEY/20150825T090000/20150825T110000");

  Buffer contentBuf(data.getContent().value(), data.getContent().value_size());
  BOOST_CHECK_EQUAL_COLLECTIONS(encryptKeyBuf.begin(), encryptKeyBuf.end(),
                                contentBuf.begin(), contentBuf.end());

}

BOOST_AUTO_TEST_CASE(CalculateInterval)
{
  // create the group manager database
  std::string dbDir = tmpPath.c_str();
  dbDir += "/manager-interval-test.db";

  // create group manager
  GroupManager manager(Name("Alice"), Name("data_type"), dbDir, 1024, 1);
  setManager(manager);

  std::map<Name, Buffer> memberKeys;
  Interval result;

  TimeStamp tp1(from_iso_string("20150825T093000"));
  result = manager.calculateInterval(tp1, memberKeys);
  BOOST_CHECK_EQUAL(to_iso_string(result.getStartTime()), "20150825T090000");
  BOOST_CHECK_EQUAL(to_iso_string(result.getEndTime()), "20150825T100000");

  TimeStamp tp2(from_iso_string("20150827T073000"));
  result = manager.calculateInterval(tp2, memberKeys);
  BOOST_CHECK_EQUAL(to_iso_string(result.getStartTime()), "20150827T070000");
  BOOST_CHECK_EQUAL(to_iso_string(result.getEndTime()), "20150827T080000");

  TimeStamp tp3(from_iso_string("20150827T043000"));
  result = manager.calculateInterval(tp3, memberKeys);
  BOOST_CHECK_EQUAL(result.isValid(), false);

  TimeStamp tp4(from_iso_string("20150827T053000"));
  result = manager.calculateInterval(tp4, memberKeys);
  BOOST_CHECK_EQUAL(to_iso_string(result.getStartTime()), "20150827T050000");
  BOOST_CHECK_EQUAL(to_iso_string(result.getEndTime()), "20150827T060000");
}

BOOST_AUTO_TEST_CASE(GetGroupKey)
{
  // create the group manager database
  std::string dbDir = tmpPath.c_str();
  dbDir += "/manager-group-key-test.db";

  // create group manager
  GroupManager manager(Name("Alice"), Name("data_type"), dbDir, 1024, 1);
  setManager(manager);

  // get data list from group manager
  TimeStamp tp1(from_iso_string("20150825T093000"));
  std::list<Data> result = manager.getGroupKey(tp1);

  BOOST_CHECK_EQUAL(result.size(), 4);

  // first data contain the group encrypt key(public key)
  std::list<Data>::iterator dataIterator = result.begin();
  BOOST_CHECK_EQUAL(dataIterator->getName().toUri(),
                    "/Alice/READ/data_type/E-KEY/20150825T090000/20150825T100000");
  EncryptKey<algo::Rsa> groupEKey(Buffer(dataIterator->getContent().value(),
                                         dataIterator->getContent().value_size()));

  // second data and decrypt
  dataIterator++;
  BOOST_CHECK_EQUAL(dataIterator->getName().toUri(),
                    "/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberA/ksk-123");

  //////////////////////////////////////////////////////////////////////// start decryption
  Block dataContent = dataIterator->getContent();

  dataContent.parse();
  BOOST_CHECK_EQUAL(dataContent.elements_size(), 2);

  // get nonce key
  Block::element_const_iterator contentIterator = dataContent.elements_begin();
  Block nonceContent(*contentIterator);
  BOOST_CHECK_EQUAL(nonceContent.type(), tlv::EncryptedContent);
  EncryptedContent encryptedNonce(nonceContent);
  BOOST_CHECK_EQUAL(encryptedNonce.getInitialVector().size(), 0);
  BOOST_CHECK_EQUAL(encryptedNonce.getAlgorithmType(), tlv::AlgorithmRsaOaep);

  algo::EncryptParams decryptParams(tlv::AlgorithmRsaOaep);
  const Buffer& bufferNonce = encryptedNonce.getPayload();
  Buffer nonce = algo::Rsa::decrypt(decryptKeyBuf.buf(), decryptKeyBuf.size(),
                                    bufferNonce.buf(), bufferNonce.size(), decryptParams);

  // get buffer payload
  contentIterator++;
  Block payloadContent(*contentIterator);
  BOOST_CHECK_EQUAL(payloadContent.type(), tlv::EncryptedContent);
  EncryptedContent encryptedPayload(payloadContent);
  BOOST_CHECK_EQUAL(encryptedPayload.getInitialVector().size(), 16);
  BOOST_CHECK_EQUAL(encryptedPayload.getAlgorithmType(), tlv::AlgorithmAesCbc);

  decryptParams.setAlgorithmType(tlv::AlgorithmAesCbc);
  decryptParams.setIV(encryptedPayload.getInitialVector().buf(),
                      encryptedPayload.getInitialVector().size());
  const Buffer& bufferPayload = encryptedPayload.getPayload();
  Buffer largePayload = algo::Aes::decrypt(nonce.buf(), nonce.size(),
                                           bufferPayload.buf(), bufferPayload.size(),
                                           decryptParams);

  // get group D-KEY
  DecryptKey<algo::Rsa> groupDKey(Buffer(largePayload.buf(), largePayload.size()));

  /////////////////////////////////////////////////////////////////////// end decryption

  // check the D-KEY
  EncryptKey<algo::Rsa> derivedGroupEKey = algo::Rsa::deriveEncryptKey(groupDKey.getKeyBits());
  BOOST_CHECK_EQUAL_COLLECTIONS(groupEKey.getKeyBits().begin(), groupEKey.getKeyBits().end(),
                                derivedGroupEKey.getKeyBits().begin(),
                                derivedGroupEKey.getKeyBits().end());

  // third data and decrypt
  dataIterator++;
  BOOST_CHECK_EQUAL(dataIterator->getName().toUri(),
                    "/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberB/ksk-123");

  // second data and decrypt
  dataIterator++;
  BOOST_CHECK_EQUAL(dataIterator->getName().toUri(),
                    "/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberC/ksk-123");

  // invalid time stamp to get group key
  TimeStamp tp2(from_iso_string("20150826T083000"));
  BOOST_CHECK_EQUAL(manager.getGroupKey(tp2).size(), 0);

  TimeStamp tp3(from_iso_string("20150827T023000"));
  BOOST_CHECK_EQUAL(manager.getGroupKey(tp3).size(), 0);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace gep
} // namespace ndn
