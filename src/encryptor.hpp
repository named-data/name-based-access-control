/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2019, Regents of the University of California
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

#ifndef NDN_NAC_ENCRYPTOR_HPP
#define NDN_NAC_ENCRYPTOR_HPP

#include "common.hpp"
#include "encrypted-content.hpp"

namespace ndn {
namespace nac {

/**
 * @brief NAC Encryptor
 *
 * Encryptor encrypts the requested content and returns ``EncryptedContent`` element.
 */
class Encryptor
{
public:
  /**
   * @param accessPrefix  NAC prefix to fetch KEK (e.g., /access/prefix/NAC/data/subset)
   * @param ckPrefix      Prefix under which Content Keys will be generated
   *                      (each will have unique version appended)
   * @param ckDataSigningInfo  SigningInfo parameters to sign CK Data
   * @param onFailure     Callback to notify application of a failure to create CK data
   *                      (failed to fetch KEK, failed to encrypt with KEK, etc.).
   *                      Note that Encryptor will continue trying to retrieve KEK until success
   *                      (each attempt separated by `RETRY_DELAY_KEK_RETRIEVAL`) and @p onFailure
   *                      may be called multiple times.
   * @param validator     Validation policy to ensure correctness of KEK
   * @param keyChain      KeyChain
   * @param face          Face that will be used to fetch KEK and publish CK data
   */
  Encryptor(const Name& accessPrefix,
            const Name& ckPrefix, SigningInfo ckDataSigningInfo,
            const ErrorCallback& onFailure,
            Validator& validator, KeyChain& keyChain, Face& face);

  ~Encryptor();

  /**
   * Synchronously encrypt supplied data
   *
   * If KEK has not been fetched already, this method will trigger async fetching of it.
   * After KEK successfully fetched, CK data will be automatically published.
   *
   * @todo For now, CK is being published in InMemoryStorage and can be fetched only while
   *       Encryptor instance is alive.
   *
   * The actual encryption is done synchronously, but the exact KDK name is not known
   * until KEK is fetched.
   *
   * Note that if the KDK name is already known, this method will call onReady right away.
   *
   * @return Encrypted content
   */
  EncryptedContent
  encrypt(const uint8_t* data, size_t size);

  /**
   * @brief Create a new content key and publish the corresponding CK data
   *
   * @todo Ensure that CK data packet for the old CK is published, when CK updated
   *       before KEK fetched
   */
  void
  regenerateCk();

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
  void
  retryFetchingKek();

  void
  fetchKekAndPublishCkData(const std::function<void()>& onReady,
                           const ErrorCallback& onFailure,
                           size_t nTriesLeft);

  bool
  makeAndPublishCkData(const ErrorCallback& onFailure);

NAC_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  Name m_accessPrefix;
  Name m_ckPrefix;
  Name m_ckName;
  Buffer m_ckBits;
  SigningInfo m_ckDataSigningInfo;

  bool m_isKekRetrievalInProgress;
  optional<Data> m_kek;
  ErrorCallback m_onFailure;

  InMemoryStoragePersistent m_ims; // for encrypted CKs
  ScopedRegisteredPrefixHandle m_ckReg;
  PendingInterestHandle m_kekPendingInterest;

  KeyChain& m_keyChain;
  Face& m_face;
  Scheduler m_scheduler;
};

} // namespace nac
} // namespace ndn

#endif // NDN_NAC_ENCRYPTOR_HPP
