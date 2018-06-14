/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2018, Regents of the University of California
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

#include "access-manager.hpp"

#include "tests-common.hpp"
#include "dummy-forwarder.hpp"

#include <iostream>
#include <ndn-cxx/util/string-helper.hpp>

namespace ndn {
namespace nac {
namespace tests {

class AccessManagerFixture : public UnitTestTimeFixture
{
public:
  AccessManagerFixture()
    : fw(m_io, m_keyChain)
    , face(static_cast<util::DummyClientFace&>(fw.addFace()))
    , accessIdentity(addIdentity("/access/policy/identity"))
    , nacIdentity(addIdentity("/access/policy/identity/NAC/dataset", RsaKeyParams())) // hack to get access to KEK key-id
    , userIdentities{addIdentity("/first/user", RsaKeyParams()),
                     addIdentity("/second/user", RsaKeyParams())}
    , manager(accessIdentity, Name("/dataset"), m_keyChain, face)
  {
    advanceClocks(1_ms, 10);

    for (auto& user : userIdentities) {
      manager.addMember(user.getDefaultKey().getDefaultCertificate());
    }
  }

public:
  DummyForwarder fw;
  util::DummyClientFace& face;
  Identity accessIdentity;
  Identity nacIdentity;
  std::vector<Identity> userIdentities;
  AccessManager manager;
};

BOOST_FIXTURE_TEST_SUITE(TestAccessManager, AccessManagerFixture)

BOOST_AUTO_TEST_CASE(PublishedKek)
{
  face.receive(Interest(Name("/access/policy/identity/NAC/dataset/KEK"))
               .setCanBePrefix(true).setMustBeFresh(true));
  advanceClocks(1_ms, 10);

  BOOST_CHECK_EQUAL(face.sentData.at(0).getName().getPrefix(-1), "/access/policy/identity/NAC/dataset/KEK");
  BOOST_CHECK_EQUAL(face.sentData.at(0).getName().get(-1), nacIdentity.getDefaultKey().getName().get(-1));
}

BOOST_AUTO_TEST_CASE(PublishedKdks)
{
  for (auto& user : userIdentities) {
    Name kdk("/access/policy/identity/NAC/dataset/KDK");
    kdk
      .append(nacIdentity.getDefaultKey().getName().get(-1))
      .append("ENCRYPTED-BY")
      .append(user.getDefaultKey().getName());

    face.receive(Interest(kdk)
                 .setCanBePrefix(true).setMustBeFresh(true));
    advanceClocks(1_ms, 10);

    BOOST_TEST_MESSAGE(kdk);
    BOOST_CHECK_EQUAL(face.sentData.at(0).getName(), kdk);
    face.sentData.clear();
  }
}

BOOST_AUTO_TEST_CASE(EnumerateDataFromIms)
{
  BOOST_CHECK_EQUAL(manager.size(), 3);
  size_t nKek = 0;
  size_t nKdk = 0;
  for (const auto& data : manager) {
    BOOST_TEST_MESSAGE(data.getName());
    if (data.getName().at(5) == KEK) {
      ++nKek;
    }
    else if (data.getName().at(5) == KDK) {
      ++nKdk;
    }
  }
  BOOST_CHECK_EQUAL(nKek, 1);
  BOOST_CHECK_EQUAL(nKdk, 2);
}

BOOST_AUTO_TEST_CASE(DumpPackets) // use this to update content of other test cases
{
  if (std::getenv("NAC_DUMP_PACKETS") == nullptr) {
    return;
  }

  std::cerr << "Block nacIdentity = \"";
  auto block = m_keyChain.exportSafeBag(nacIdentity.getDefaultKey().getDefaultCertificate(),
                                        "password", strlen("password"))->wireEncode();
  printHex(std::cerr, block.wire(), block.size(), true);
  std::cerr << "\"_block;\n\n";

  std::cerr << "std::vector<Block> userIdentities = {\n";
  for (size_t i = 0; i < userIdentities.size(); ++i) {
    std::cerr << "    \"";

    block = m_keyChain.exportSafeBag(userIdentities[i].getDefaultKey().getDefaultCertificate(),
                                     "password", strlen("password"))->wireEncode();
    printHex(std::cerr, block.wire(), block.size(), true);
    if (i < userIdentities.size() - 1) {
      std::cerr << "\"_block,\n";
    }
    else {
      std::cerr << "\"_block\n";
    }
  }
  std::cerr  << "  };\n\n";

  std::cerr << "std::vector<Block> managerPackets = {\n";
  size_t i = 0;
  for (const auto& data : manager) {
    std::cerr << "    \"";
    printHex(std::cerr, data.wireEncode().wire(), data.wireEncode().size(), true);

    if (i < manager.size() - 1) {
      std::cerr << "\"_block,\n";
    }
    else {
      std::cerr << "\"_block\n";
    }

    ++i;
  }
  std::cerr  << "  };\n\n";
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nac
} // namespace ndn
