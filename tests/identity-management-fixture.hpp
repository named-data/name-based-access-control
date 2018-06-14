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

#ifndef NAC_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP
#define NAC_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP

#include "boost-test.hpp"

#include <ndn-cxx/security/v2/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <vector>

namespace ndn {
namespace nac {
namespace tests {

/**
 * @brief A test suite level fixture to help with identity management
 *
 * Test cases in the suite can use this fixture to create identities.  Identities,
 * certificates, and saved certificates are automatically removed during test teardown.
 */
class IdentityManagementFixture
{
public:
  IdentityManagementFixture();

  ~IdentityManagementFixture();

  /**
   * @brief Add identity @p identityName
   * @return name of the created self-signed certificate
   */
  security::Identity
  addIdentity(const Name& identityName, const KeyParams& params = security::v2::KeyChain::getDefaultKeyParams());

  /**
   *  @brief Save identity certificate to a file
   *  @param identity identity
   *  @param filename file name, should be writable
   *  @return whether successful
   */
  bool
  saveIdentityCertificate(const security::Identity& identity, const std::string& filename);

  /**
   * @brief Issue a certificate for \p subIdentityName signed by \p issuer
   *
   *  If identity does not exist, it is created.
   *  A new key is generated as the default key for identity.
   *  A default certificate for the key is signed by the issuer using its default certificate.
   *
   *  @return the sub identity
   */
  security::Identity
  addSubCertificate(const Name& subIdentityName, const security::Identity& issuer,
                    const KeyParams& params = security::v2::KeyChain::getDefaultKeyParams());

  /**
   * @brief Add a self-signed certificate to @p key with issuer ID @p issuer
   */
  security::v2::Certificate
  addCertificate(const security::Key& key, const std::string& issuer);

  bool
  saveCertToFile(const Data& obj, const std::string& filename);

protected:
  security::v2::KeyChain m_keyChain;
  std::set<Name> m_identities;
  std::set<std::string> m_certFiles;
};

} // namespace tests
} // namespace nac
} // namespace ndn

#endif // NAC_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP
