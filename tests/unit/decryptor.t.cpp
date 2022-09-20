/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2022, Regents of the University of California
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

#include "decryptor.hpp"

#include "access-manager.hpp"
#include "encrypted-content.hpp"
#include "encryptor.hpp"

#include "tests/boost-test.hpp"
#include "tests/io-key-chain-fixture.hpp"
#include "tests/unit/static-data.hpp"

#include <boost/mpl/vector.hpp>
#include <ndn-cxx/security/validator-null.hpp>
#include <ndn-cxx/util/dummy-client-face.hpp>

namespace ndn {
namespace nac {
namespace tests {

class DecryptorStaticDataEnvironment : public IoKeyChainFixture
{
public:
  DecryptorStaticDataEnvironment()
  {
    StaticData data;
    for (const auto& block : data.managerPackets) {
      m_ims.insert(*make_shared<Data>(block));
    }
    for (const auto& block : data.encryptorPackets) {
      m_ims.insert(*make_shared<Data>(block));
    }

    auto serveFromIms = [this] (const Name&, const Interest& interest) {
      auto data = m_ims.find(interest);
      if (data != nullptr) {
        m_imsFace.put(*data);
      }
    };
    m_imsFace.setInterestFilter("/", serveFromIms, [] (auto...) {});
    advanceClocks(1_ms, 10);

    // import "/first/user" identity
    m_keyChain.importSafeBag(SafeBag(data.userIdentities.at(0)), "password", strlen("password"));
    // credentialIdentity = m_keyChain.getPib().getIdentity("/first/user");

    m_keyChain.createIdentity("/not/authorized");
  }

protected:
  util::DummyClientFace m_imsFace{m_io, m_keyChain, {false, true}};

private:
  InMemoryStoragePersistent m_ims;
};

template<class T>
class DecryptorFixture : public DecryptorStaticDataEnvironment
{
public:
  DecryptorFixture()
    : face(m_io, m_keyChain, {false, true})
    , decryptor(m_keyChain.getPib().getIdentity(T().identity).getDefaultKey(), validator, m_keyChain, face)
  {
    face.linkTo(m_imsFace);
    advanceClocks(1_ms, 10);
  }

public:
  util::DummyClientFace face;
  security::ValidatorNull validator;
  Decryptor decryptor;
};

BOOST_AUTO_TEST_SUITE(TestDecryptor)

struct Valid
{
  std::string identity = "/first/user";
  bool expectToSucceed = true;
};

struct Invalid
{
  std::string identity = "/not/authorized";
  bool expectToSucceed = false;
};

using Identities = boost::mpl::vector<Valid, Invalid>;

BOOST_FIXTURE_TEST_CASE_TEMPLATE(DecryptSuccess, T, Identities, DecryptorFixture<T>)
{
  StaticData data;

  size_t nSuccesses = 0;
  size_t nFailures = 0;
  this->decryptor.decrypt(data.encryptedBlobs.at(0),
                    [&] (ConstBufferPtr buffer) {
                      ++nSuccesses;
                      BOOST_CHECK_EQUAL(buffer->size(), 15);
                      std::string content(buffer->get<char>(), buffer->size());
                      BOOST_CHECK_EQUAL(content, "Data to encrypt");
                    },
                    [&] (const ErrorCode&, const std::string& msg) {
                      BOOST_TEST_MESSAGE(msg);
                      ++nFailures;
                    });
  this->advanceClocks(2_s, 10);

  BOOST_CHECK_EQUAL(nSuccesses, T().expectToSucceed ? 1 : 0);
  BOOST_CHECK_EQUAL(nFailures, T().expectToSucceed ? 0 : 1);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nac
} // namespace ndn
