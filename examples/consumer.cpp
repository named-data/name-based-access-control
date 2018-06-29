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

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/validator-config.hpp>

// #include <ndn-nac/decryptor.hpp>
#include "decryptor.hpp"

#include <iostream>

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
namespace nac {
// Additional nested namespaces can be used to prevent/limit name conflicts
namespace examples {

class Consumer : noncopyable
{
public:
  Consumer()
    : m_face(nullptr, m_keyChain)
    , m_validator(m_face)
    , m_decryptor(m_keyChain.getPib().getDefaultIdentity().getDefaultKey(), m_validator, m_keyChain, m_face)
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
    Interest interest(Name("/example/testApp/randomData"));
    interest.setInterestLifetime(2_s); // 2 seconds
    interest.setMustBeFresh(true);

    m_face.expressInterest(interest,
                           bind(&Consumer::onData, this,  _1, _2),
                           bind(&Consumer::onNack, this, _1, _2),
                           bind(&Consumer::onTimeout, this, _1));

    std::cout << "Sending " << interest << std::endl;

    // processEvents will block until the requested data received or timeout occurs
    m_face.processEvents();
  }

private:
  void
  onData(const Interest& interest, const Data& data)
  {
    m_validator.validate(data,
      [=] (const Data& data) {
        m_decryptor.decrypt(data.getContent().blockFromValue(),
          [=] (ConstBufferPtr content) {
            std::cout << "Decrypted content: "
                      << std::string(reinterpret_cast<const char*>(content->data()), content->size())
                      << std::endl;
          },
          [=] (const ErrorCode&, const std::string& error) {
            std::cerr << "Cannot decrypt data: " << error << std::endl;
          });
      },
      [=] (const Data& data, const ValidationError& error) {
        std::cerr << "Cannot validate retrieved data: " << error << std::endl;
      });
  }

  void
  onNack(const Interest& interest, const lp::Nack& nack)
  {
    std::cout << "received Nack with reason " << nack.getReason()
              << " for interest " << interest << std::endl;
  }

  void
  onTimeout(const Interest& interest)
  {
    std::cout << "Timeout " << interest << std::endl;
  }

private:
  KeyChain m_keyChain;
  Face m_face;
  ValidatorConfig m_validator;
  Decryptor m_decryptor;
};

} // namespace examples
} // namespace nac
} // namespace ndn

int
main(int argc, char** argv)
{
  ndn::nac::examples::Consumer consumer;
  try {
    consumer.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
