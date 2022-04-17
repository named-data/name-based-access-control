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

#ifndef NAC_TESTS_KEY_CHAIN_FIXTURE_HPP
#define NAC_TESTS_KEY_CHAIN_FIXTURE_HPP

#include <ndn-cxx/security/key-chain.hpp>

namespace ndn::nac::tests {

/**
 * @brief A fixture providing an in-memory KeyChain.
 *
 * Test cases can use this fixture to create identities. Identities, certificates, and
 * saved certificates are automatically removed during test teardown.
 */
class KeyChainFixture
{
protected:
  using Certificate = ndn::security::Certificate;
  using Identity    = ndn::security::Identity;
  using Key         = ndn::security::Key;

public:
  /**
   * @brief Saves an NDN certificate to a file
   * @return true if successful, false otherwise
   */
  bool
  saveCert(const Data& cert, const std::string& filename);

  /**
   * @brief Saves the default certificate of @p identity to a file
   * @return true if successful, false otherwise
   */
  bool
  saveIdentityCert(const Identity& identity, const std::string& filename);

  /**
   * @brief Saves the default certificate of the identity named @p identityName to a file
   * @param identityName Name of the identity
   * @param filename File name, must be writable
   * @param allowCreate If true, create the identity if it does not exist
   * @return true if successful, false otherwise
   */
  bool
  saveIdentityCert(const Name& identityName, const std::string& filename,
                   bool allowCreate = false);

protected:
  KeyChainFixture();

  ~KeyChainFixture();

protected:
  ndn::KeyChain m_keyChain;

private:
  std::vector<std::string> m_certFiles;
};

} // namespace ndn::nac::tests

#endif // NAC_TESTS_KEY_CHAIN_FIXTURE_HPP
