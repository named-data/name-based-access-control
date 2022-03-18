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

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/validator-config.hpp>

#include "encryptor.hpp"
#include "access-manager.hpp"

#include <iostream>

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
namespace nac {
// Additional nested namespaces can be used to prevent/limit name conflicts
namespace examples {

class Producer : noncopyable
{
public:
  Producer()
    : m_accessManager(m_keyChain.createIdentity("/nac/example", RsaKeyParams()), "test",
                      m_keyChain, m_face)
    , m_encryptor("/nac/example/NAC/test",
                  "/nac/example/CK", signingWithSha256(),
                  [] (auto&&...) { std::cerr << "Failed to publish CK"; },
                  m_validator, m_keyChain, m_face)
  {
    m_validator.load(R"CONF(
        trust-anchor
        {
          type any
        }
      )CONF", "fake-config");
  }

  void
  run()
  {
    // Give access to default identity. If consumer uses the same default identity, it will be able to decrypt
    m_accessManager.addMember(m_keyChain.getPib().getDefaultIdentity().getDefaultKey().getDefaultCertificate());

    m_face.setInterestFilter("/example/testApp",
                             std::bind(&Producer::onInterest, this, _1, _2),
                             nullptr, // RegisterPrefixSuccessCallback is optional
                             std::bind(&Producer::onRegisterFailed, this, _1, _2));
    m_face.processEvents();
  }

private:
  void
  onInterest(const InterestFilter&, const Interest& interest)
  {
    std::cout << "<< I: " << interest << std::endl;

    // Create new name, based on Interest's name
    Name dataName(interest.getName());
    dataName
      .append("testApp") // add "testApp" component to Interest name
      .appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)

    // Create Data packet
    auto data = std::make_shared<Data>();
    data->setName(dataName);
    data->setFreshnessPeriod(10_s); // 10 seconds

    static const std::string content = "HELLO KITTY";
    auto blob = m_encryptor.encrypt({reinterpret_cast<const uint8_t*>(content.data()), content.size()});
    data->setContent(blob.wireEncode());

    // Sign Data packet with default identity
    m_keyChain.sign(*data);
    // m_keyChain.sign(data, <identityName>);
    // m_keyChain.sign(data, <certificate>);

    // Return Data packet to the requester
    std::cout << ">> D: " << *data << std::endl;
    m_face.put(*data);
  }


  void
  onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    std::cerr << "ERROR: Failed to register prefix '" << prefix
              << "' with the local forwarder (" << reason << ")" << std::endl;
    m_face.shutdown();
  }

private:
  KeyChain m_keyChain;
  Face m_face{nullptr, m_keyChain};
  ValidatorConfig m_validator{m_face};
  AccessManager m_accessManager;
  Encryptor m_encryptor;
};

} // namespace examples
} // namespace nac
} // namespace ndn

int
main(int argc, char** argv)
{
  try {
    ndn::nac::examples::Producer producer;
    producer.run();
    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}
