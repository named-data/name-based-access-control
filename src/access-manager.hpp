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

#ifndef NDN_NAC_ACCESS_MANAGER_HPP
#define NDN_NAC_ACCESS_MANAGER_HPP

#include "common.hpp"

#include <ndn-cxx/face.hpp>

namespace ndn::nac {

/**
 * @brief Access Manager
 *
 * Access Manager controls decryption policy by publishing granular per-namespace access
 * policies in the form of key encryption (KEK, plaintext public) and key decryption (KDK,
 * encrypted private key) key pair.
 *
 * @todo Rolling KEK
 */
class AccessManager
{
public:
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

public:
  /**
   * @param identity Data owner's namespace identity (will be used to sign KEK and KDK)
   * @param dataset Name of dataset that this manager is controlling
   * @param keyChain KeyChain
   * @param face Face that will be used to publish KEK and KDKs
   *
   * KEK and KDK naming:
   *
   *     [identity]/NAC/[dataset]/KEK            /[key-id]                           (== KEK, public key)
   *
   *     [identity]/NAC/[dataset]/KDK/[key-id]   /ENCRYPTED-BY/[user]/KEY/[key-id]   (== KDK, encrypted private key)
   *
   *     \_____________  ______________/
   *                   \/
   *          registered with NFD
   *
   * AccessManager serves NAC public key for data producers to fetch and encrypted versions of
   * private keys (as safe bags) for authorized consumers to fetch.
   */
  AccessManager(const Identity& identity, const Name& dataset,
                KeyChain& keyChain, Face& face);

  /**
   * @brief Authorize a member identified by its certificate @p memberCert to decrypt data
   *        under the policy
   * @return published KDK
   */
  Data
  addMember(const Certificate& memberCert);

  // void
  // addMemberWithKey(const Name& keyName);

  // void
  // addMemberWithIdentity(const Name& identityName);

  /**
   * @brief Remove member with name @p identity from the group
   */
  void
  removeMember(const Name& identity);

public: // accessor interface for published data packets

  /** @return{ number of packets stored in in-memory storage }
   */
  size_t
  size() const
  {
    return m_ims.size();
  }

  /** @brief Returns begin iterator of the in-memory storage ordered by
   *  name with digest
   *
   *  @return{ const_iterator pointing to the beginning of m_cache }
   */
  InMemoryStorage::const_iterator
  begin() const
  {
    return m_ims.begin();
  }

  /** @brief Returns end iterator of the in-memory storage ordered by
   *  name with digest
   *
   *  @return{ const_iterator pointing to the end of m_cache }
   */
  InMemoryStorage::const_iterator
  end() const
  {
    return m_ims.end();
  }

private:
  Identity m_identity;
  Key m_nacKey;
  KeyChain& m_keyChain;
  Face& m_face;

  InMemoryStoragePersistent m_ims; // for KEK and KDKs
  ScopedRegisteredPrefixHandle m_kekReg;
  ScopedRegisteredPrefixHandle m_kdkReg;
};

} // namespace ndn::nac

#endif // NDN_NAC_ACCESS_MANAGER_HPP
