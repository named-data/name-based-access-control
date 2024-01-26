/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2024, Regents of the University of California
 *
 * NAC library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * NAC library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of NAC library authors and contributors.
 */

#include "encryptor.hpp"

#include "tests/boost-test.hpp"
#include "tests/io-key-chain-fixture.hpp"
#include "tests/unit/static-data.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/validator-null.hpp>
#include <ndn-cxx/util/dummy-client-face.hpp>
#include <ndn-cxx/util/string-helper.hpp>

#include <iostream>

namespace ndn::nac::tests {

class EncryptorStaticDataEnvironment : public IoKeyChainFixture
{
public:
  EncryptorStaticDataEnvironment(bool shouldPublishData)
  {
    if (shouldPublishData) {
      publishData();
    }

    auto serveFromIms = [this] (const Name&, const Interest& interest) {
      auto data = m_ims.find(interest);
      if (data != nullptr) {
        m_imsFace.put(*data);
      }
    };
    m_imsFace.setInterestFilter("/", serveFromIms, [] (auto...) {});
    advanceClocks(1_ms, 10);

    m_imsFace.sentData.clear();
    m_imsFace.sentInterests.clear();
  }

  void
  publishData()
  {
    StaticData data;
    for (const auto& block : data.managerPackets) {
      m_ims.insert(*std::make_shared<Data>(block));
    }
    advanceClocks(1_ms, 10);
  }

protected:
  DummyClientFace m_imsFace{m_io, m_keyChain, {true, true}};

private:
  InMemoryStoragePersistent m_ims;
};

template<bool shouldPublishData = true>
class EncryptorFixture : public EncryptorStaticDataEnvironment
{
public:
  EncryptorFixture()
    : EncryptorStaticDataEnvironment(shouldPublishData)
    , face(m_io, m_keyChain, {true, true})
    , encryptor("/access/policy/identity/NAC/dataset", "/some/ck/prefix", signingWithSha256(),
                [=] (const ErrorCode& code, const std::string& error) {
                  onFailure(code, error);
                },
                validator, m_keyChain, face)
  {
    face.linkTo(m_imsFace);
    advanceClocks(1_ms, 10);
  }

public:
  DummyClientFace face;
  security::ValidatorNull validator;
  Encryptor encryptor;
  signal::Signal<EncryptorFixture, ErrorCode, std::string> onFailure;
};

BOOST_FIXTURE_TEST_SUITE(TestEncryptor, EncryptorFixture<>)

BOOST_AUTO_TEST_CASE(EncryptAndPublishedCk)
{
  encryptor.m_kek.reset();
  BOOST_CHECK_EQUAL(encryptor.m_isKekRetrievalInProgress, false);
  encryptor.regenerateCk();
  BOOST_CHECK_EQUAL(encryptor.m_isKekRetrievalInProgress, true);

  const std::string plaintext = "Data to encrypt";
  auto block = encryptor.encrypt({reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()});

  EncryptedContent content(block);
  auto ckPrefix = content.getKeyLocator();
  BOOST_CHECK_EQUAL(ckPrefix.getPrefix(-1), "/some/ck/prefix/CK");

  BOOST_CHECK(content.hasIv());
  BOOST_CHECK_NE(std::string(reinterpret_cast<const char*>(content.getPayload().value()),
                             content.getPayload().value_size()),
                 plaintext);

  advanceClocks(1_ms, 10);

  // check that KEK interests has been sent
  BOOST_CHECK_EQUAL(face.sentInterests.at(0).getName().getPrefix(6),
                    Name("/access/policy/identity/NAC/dataset/KEK"));

  auto kek = m_imsFace.sentData.at(0);
  BOOST_CHECK_EQUAL(kek.getName().getPrefix(6), Name("/access/policy/identity/NAC/dataset/KEK"));
  BOOST_CHECK_EQUAL(kek.getName().size(), 7);

  face.sentData.clear();
  face.sentInterests.clear();

  face.receive(Interest(ckPrefix)
               .setCanBePrefix(true).setMustBeFresh(true));
  advanceClocks(1_ms, 10);

  auto ckName = face.sentData.at(0).getName();
  BOOST_CHECK_EQUAL(ckName.getPrefix(4), "/some/ck/prefix/CK");
  BOOST_CHECK_EQUAL(ckName.get(5), name::Component("ENCRYPTED-BY"));

  auto extractedKek = ckName.getSubName(6);
  BOOST_CHECK_EQUAL(extractedKek, kek.getName());

  BOOST_CHECK_EQUAL(encryptor.m_isKekRetrievalInProgress, false);
}

BOOST_FIXTURE_TEST_CASE(KekRetrievalFailure, EncryptorFixture<false>)
{
  size_t nErrors = 0;
  onFailure.connect([&] (auto&&...) { ++nErrors; });

  const std::string plaintext = "Data to encrypt";
  auto block = encryptor.encrypt({reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()});
  advanceClocks(1_ms, 10);

  // check that KEK interests has been sent
  BOOST_CHECK_EQUAL(face.sentInterests.at(0).getName().getPrefix(6), Name("/access/policy/identity/NAC/dataset/KEK"));

  // and failed
  BOOST_CHECK_EQUAL(m_imsFace.sentData.size(), 0);

  advanceClocks(1_s, 13); // 4_s default interest lifetime x 3
  BOOST_CHECK_EQUAL(nErrors, 1);
  BOOST_CHECK_EQUAL(m_imsFace.sentData.size(), 0);

  advanceClocks(1_s, 730); // 60 seconds between attempts + ~12 seconds for each attempt
  BOOST_CHECK_EQUAL(nErrors, 11);
  BOOST_CHECK_EQUAL(m_imsFace.sentData.size(), 0);

  // check recovery

  publishData();

  advanceClocks(1_s, 73);

  auto kek = m_imsFace.sentData.at(0);
  BOOST_CHECK_EQUAL(kek.getName().getPrefix(6), Name("/access/policy/identity/NAC/dataset/KEK"));
  BOOST_CHECK_EQUAL(kek.getName().size(), 7);
}

BOOST_AUTO_TEST_CASE(EnumerateDataFromIms)
{
  encryptor.regenerateCk();
  advanceClocks(1_ms, 10);

  encryptor.regenerateCk();
  advanceClocks(1_ms, 10);

  BOOST_CHECK_EQUAL(encryptor.size(), 3);
  size_t nCk = 0;
  for (const auto& data : encryptor) {
    BOOST_TEST_MESSAGE(data.getName());
    if (data.getName().getPrefix(4) == Name("/some/ck/prefix/CK")) {
      ++nCk;
    }
  }
  BOOST_CHECK_EQUAL(nCk, 3);
}

BOOST_AUTO_TEST_CASE(GenerateTestData,
  * ut::description("regenerates the static test data used by other test cases")
  * ut::disabled())
{
  const auto plaintext = "Data to encrypt"s;

  std::cerr << "const std::vector<Block> encryptedBlobs = {\n";
  for (size_t i = 0; i < 3; ++i) {
    std::cerr << "  \"";
    auto block = encryptor.encrypt({reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()});
    printHex(std::cerr, block.wireEncode(), true);
    std::cerr << "\"_block,\n";

    encryptor.regenerateCk();
    advanceClocks(1_ms, 10);
  }
  std::cerr << "};\n\n";

  std::cerr << "const std::vector<Block> encryptorPackets = {\n";
  for (const auto& data : encryptor) {
    std::cerr << "  \"";
    printHex(std::cerr, data.wireEncode(), true);
    std::cerr << "\"_block,\n";
  }
  std::cerr << "};\n\n";
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace ndn::nac::tests
