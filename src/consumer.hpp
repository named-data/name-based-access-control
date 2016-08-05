/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2015,  Regents of the University of California
 *
 * This file is part of ndn-group-encrypt (Group-based Encryption Protocol for NDN).
 * See AUTHORS.md for complete list of ndn-group-encrypt authors and contributors.
 *
 * ndn-group-encrypt is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * ndn-group-encrypt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndn-group-encrypt, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Zhiyi Zhang <dreamerbarrychang@gmail.com>
 * @author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_GEP_CONSUMER_HPP
#define NDN_GEP_CONSUMER_HPP

#include "algo/rsa.hpp"
#include "algo/aes.hpp"
#include "consumer-db.hpp"
#include "error-code.hpp"

#include <ndn-cxx/security/validator-null.hpp>
#include <ndn-cxx/face.hpp>

namespace ndn {
namespace gep {

typedef function<void (const Data&, const Buffer&)> ConsumptionCallBack;

/**
 * @brief Consumer in group-based encryption protocol
 */
class Consumer
{
private:
  typedef function<void (const Buffer&)> PlainTextCallBack;

public:
  /**
   * @brief Create a consumer instance
   *
   * @param face The face used for key fetching
   * @param groupName The reading group name that the consumer belongs to
   * @param consumerName The identity of the consumer
   * @param dbDir The path to database storing decryption key
   */
  Consumer(Face& face, const Name& groupName, const Name& consumerName, const std::string& dbDir);

  /**
   * @brief Send out the Interest packet to fetch content packet with @p dataName.
   *
   * @param dataName name of the data packet to fetch
   * @param consumptionCallBack The callback when requested data is decrypted
   * @param errorCallBack The callback when error happens in consumption
   */
  void
  consume(const Name& dataName,
          const ConsumptionCallBack& consumptionCallBack,
          const ErrorCallBack& errorCallBack);

  /**
   * @brief Set the group name to @p groupName.
   */
  void
  setGroup(const Name& groupName);

  /**
   * @brief Add new decryption key with @p keyName and @p keyBuf.
   */
  void
  addDecryptionKey(const Name& keyName, const Buffer& keyBuf);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:

  /**
   * @brief Decrypt @p encryptedBlock using @p keyBits
   *
   * Invoke @p plainTextCallBack when block is decrypted, otherwise @p errorCallBack.
   */
  void
  decrypt(const Block& encryptedBlock,
          const Buffer& keyBits,
          const PlainTextCallBack& plainTextCallBack,
          const ErrorCallBack& errorCallBack);

  /**
   * @brief Decrypt @p data.
   *
   * Invoke @p plainTextCallBack when block is decrypted, otherwise @p errorCallBack.
   */
  void
  decryptContent(const Data& data,
                 const PlainTextCallBack& plainTextCallBack,
                 const ErrorCallBack& errorCallBack);

  /**
   * @brief Decrypt @p cKeyData.
   *
   * Invoke @p plainTextCallBack when block is decrypted, otherwise @p errorCallBack.
   */
  void
  decryptCKey(const Data& cKeyData,
              const PlainTextCallBack& plainTextCallBack,
              const ErrorCallBack& errorCallBack);

  /**
   * @brief Decrypt @p dKeyData.
   *
   * Invoke @p plainTextCallBack when block is decrypted, otherwise @p errorCallBack.
   */
  void
  decryptDKey(const Data& dKeyData,
              const PlainTextCallBack& plainTextCallBack,
              const ErrorCallBack& errorCallBack);


  /**
   * @brief Get the buffer of decryption key with @p decryptionKeyName from database.
   *
   * @return Null buffer when there is no decryption key with @p decryptionKeyName.
   */
  const Buffer
  getDecryptionKey(const Name& decryptionKeyName);

private:
  ConsumerDB m_db;
  unique_ptr<Validator> m_validator;
  Face& m_face;
  Name m_groupName;
  Name m_consumerName;

  std::map<Name, Buffer> m_cKeyMap;
  std::map<Name, Buffer> m_dKeyMap;
};

} // namespace gep
} // namespace ndn

#endif // NDN_GEP_CONSUMER_HPP
