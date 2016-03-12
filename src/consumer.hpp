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
   * @param dbPath The path to database storing decryption key
   * @param cKeyLink The link object for C-KEY retrieval
   * @param dKeyLink The link object for D-KEY retrieval
   */
  Consumer(Face& face, const Name& groupName, const Name& consumerName, const std::string& dbPath,
           const Link& cKeyLink = NO_LINK, const Link& dKeyLink = NO_LINK);

  /**
   * @brief Send out the Interest packet to fetch content packet with @p dataName.
   *
   * @param dataName name of the data packet to fetch
   * @param consumptionCallBack The callback when requested data is decrypted
   * @param errorCallback The callback when error happens in consumption
   * @param link The link object for data retrieval
   */
  void
  consume(const Name& dataName,
          const ConsumptionCallBack& consumptionCallBack,
          const ErrorCallBack& errorCallback,
          const Link& link = NO_LINK);

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
   * Invoke @p plainTextCallBack when block is decrypted, otherwise @p errorCallback.
   */
  void
  decrypt(const Block& encryptedBlock,
          const Buffer& keyBits,
          const PlainTextCallBack& plainTextCallBack,
          const ErrorCallBack& errorCallback);

  /**
   * @brief Decrypt @p data.
   *
   * Invoke @p plainTextCallBack when block is decrypted, otherwise @p errorCallback.
   */
  void
  decryptContent(const Data& data,
                 const PlainTextCallBack& plainTextCallBack,
                 const ErrorCallBack& errorCallback);

  /**
   * @brief Decrypt @p cKeyData.
   *
   * Invoke @p plainTextCallBack when block is decrypted, otherwise @p errorCallback.
   */
  void
  decryptCKey(const Data& cKeyData,
              const PlainTextCallBack& plainTextCallBack,
              const ErrorCallBack& errorCallback);

  /**
   * @brief Decrypt @p dKeyData.
   *
   * Invoke @p plainTextCallBack when block is decrypted, otherwise @p errorCallback.
   */
  void
  decryptDKey(const Data& dKeyData,
              const PlainTextCallBack& plainTextCallBack,
              const ErrorCallBack& errorCallback);


  /**
   * @brief Get the buffer of decryption key with @p decryptionKeyName from database.
   *
   * @return Null buffer when there is no decryption key with @p decryptionKeyName.
   */
  const Buffer
  getDecryptionKey(const Name& decryptionKeyName);

  /**
   * @brief Helper method for sending interest
   *
   * This method prepare the three callbacks: DataCallbak, NackCallback, TimeoutCallback
   * for the @p interest.
   *
   * @param interest The interes to send out
   * @param nRetrials The number of retrials left (if timeout)
   * @param link The link object (used when NACK is received)
   * @param validationCallback The callback when data is validated
   * @param errorCallback The callback when error happens
   */
  void
  sendInterest(const Interest& interest, int nRetrials,
               const Link& link,
               const OnDataValidated& validationCallback,
               const ErrorCallBack& errorCallback);

  /**
   * @brief Callback to handle NACK
   *
   * This method will check if there is another delegation to use. Otherwise report error
   *
   * @param interest The interes got NACKed
   * @param nack The nack object
   * @param link The link object (used when NACK is received)
   * @param delegationIndex Current selected delegation
   * @param validationCallback The callback when data is validated
   * @param errorCallback The callback when error happens
   */
  void
  handleNack(const Interest& interest, const lp::Nack& nack,
             const Link& link,
             const OnDataValidated& validationCallback,
             const ErrorCallBack& errorCallback);

  /**
   * @brief Callback to handle timeout
   *
   * This method will check if a retrial is allowed. Otherwise retreat the interest as NACKed
   *
   * @param interest The interes timed out
   * @param nRetrials The number of retrials left
   * @param link The link object (used when NACK is received)
   * @param delegationIndex Current selected delegation
   * @param validationCallback The callback when data is validated
   * @param errorCallback The callback when error happens
   */
  void
  handleTimeout(const Interest& interest, int nRetrials,
                const Link& link,
                const OnDataValidated& validationCallback,
                const ErrorCallBack& errorCallback);

public:
  static const Link NO_LINK;

private:
  ConsumerDB m_db;
  unique_ptr<Validator> m_validator;
  Face& m_face;
  Name m_groupName;
  Name m_consumerName;

  Link m_cKeyLink;
  std::map<Name, Buffer> m_cKeyMap;
  Link m_dKeyLink;
  std::map<Name, Buffer> m_dKeyMap;
};

} // namespace gep
} // namespace ndn

#endif // NDN_GEP_CONSUMER_HPP
