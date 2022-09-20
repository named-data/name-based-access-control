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

#ifndef NDN_NAC_DECRYPTOR_HPP
#define NDN_NAC_DECRYPTOR_HPP

#include "common.hpp"
#include "encrypted-content.hpp"

#include <list>
#include <map>

namespace ndn::nac {

/**
 * @brief NAC Decryptor
 *
 * Encryptor decrypts (asynchronous operation, contingent on successful retrieval of CK data,
 * KDK, and decryption of both) the supplied ``EncryptedContent`` element.
 */
class Decryptor
{
public:
  using DecryptSuccessCallback = std::function<void(ConstBufferPtr)>;

  /**
   * @brief Constructor
   * @param credentialsKey Credentials key to be used to retrieve and decrypt KDK
   * @param validator Validation policy to ensure validity of KDK and CK
   * @param keyChain  KeyChain
   * @param face      Face that will be used to fetch CK and KDK
   */
  Decryptor(const Key& credentialsKey, Validator& validator, KeyChain& keyChain, Face& face);

  ~Decryptor();

  /**
   * @brief Asynchronously decrypt @p encryptedContent
   */
  void
  decrypt(const Block& encryptedContent,
          const DecryptSuccessCallback& onSuccess, const ErrorCallback& onFailure);

private:
  struct ContentKey
  {
    bool isRetrieved = false;
    Buffer bits;
    std::optional<PendingInterestHandle> pendingInterest;

    struct PendingDecrypt
    {
      EncryptedContent encryptedContent;
      DecryptSuccessCallback onSuccess;
      ErrorCallback onFailure;
    };
    std::list<PendingDecrypt> pendingDecrypts;
  };

  using ContentKeys = std::map<Name, ContentKey>;

  void
  fetchCk(ContentKeys::iterator ck, const ErrorCallback& onFailure, size_t nTriesLeft);

  void
  fetchKdk(ContentKeys::iterator ck, const Name& kdkPrefix, const Data& ckData,
           const ErrorCallback& onFailure, size_t nTriesLeft);

  bool
  decryptAndImportKdk(const Data& kdkData, const ErrorCallback& onFailure);

  void
  decryptCkAndProcessPendingDecrypts(ContentKeys::iterator ck, const Data& ckData,
                                     const Name& kdkKeyName/* local keyChain name for KDK key*/,
                                     const ErrorCallback& onFailure);

  /**
   * @brief Synchronously decrypt
   */
  static void
  doDecrypt(const EncryptedContent& encryptedContent, const Buffer& ckBits,
            const DecryptSuccessCallback& onSuccess,
            const ErrorCallback& onFailure);

private:
  Key m_credentialsKey;
  // Validator& m_validator;
  Face& m_face;
  KeyChain& m_keyChain; // external keychain with access credentials
  KeyChain m_internalKeyChain; // internal in-memory keychain for temporarily storing KDKs

  // a set of Content Keys
  // TODO: add some expiration, so they are not stored forever
  ContentKeys m_cks;
};

} // namespace ndn::nac

#endif // NDN_NAC_DECRYPTOR_HPP
