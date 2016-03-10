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
 * @author Prashanth Swaminathan <prashanthsw@gmail.com>
 * @author Yingdi Yu <yuyingdi@gmail.com>
 */

#ifndef NDN_GEP_PRODUCER_HPP
#define NDN_GEP_PRODUCER_HPP

#include "producer-db.hpp"
#include "error-code.hpp"

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/face.hpp>

namespace ndn {
namespace gep {

// @brief Callback returns vector of Data contains content keys encrypted by E-KEYS
typedef function<void(const std::vector<Data>&)> ProducerEKeyCallback;

/**
 * @brief Manage content key and data encryption
 */
class Producer
{
public:
  struct KeyInfo {
    time::system_clock::TimePoint beginTimeslot;
    time::system_clock::TimePoint endTimeslot;
    Buffer keyBits;
  };

  struct KeyRequest {
    KeyRequest(size_t interests)
    : interestCount(interests)
    {}
    size_t interestCount;
    std::unordered_map<Name, size_t> repeatAttempts;
    std::vector<Data> encryptedKeys;
  };

public:
  /**
   * @brief Construct a producer
   *
   * A producer can produce data with a naming convention:
   *   /<@p prefix>/SAMPLES/<@p dataType>/[timestamp]
   *
   * The produced data packet is encrypted with a content key,
   * which is stored in a database at @p dbPath.
   *
   * A producer also need to produce data containing content key
   * encrypted with E-KEYs. A producer can retrieve E-KEYs through
   * @p face, and will re-try for at most @p repeatAttemps times when
   * E-KEY retrieval fails.
   */
  Producer(const Name& prefix, const Name& dataType,
           Face& face, const std::string& dbPath, uint8_t repeatAttempts = 3);

  /**
   * @brief Create content key corresponding to @p timeslot
   *
   * This method will first check if the content key exists. For existing
   * content key, the method will return content key name directly.
   * If the key does not exist, the method will create one and encrypt
   * it using corresponding E-KEY. The encrypted content keys will be
   * passed back through @p callback. In case of any error, @p errorCallBack
   * will be invoked.
   */
  Name
  createContentKey(const time::system_clock::TimePoint& timeslot,
                   const ProducerEKeyCallback& callback,
                   const ErrorCallBack& errorCallBack = Producer::defaultErrorCallBack);

  /**
   * @brief Produce an data packet encrypted using the content key corresponding @p timeslot
   *
   * This method encrypts @p content of @p contentLen with a content key covering
   * @p timeslot, and set @p data with the encrypted content and appropriate data name.
   * In case of any error, @p errorCallBack will be invoked.
   */
  void
  produce(Data& data, const time::system_clock::TimePoint& timeslot,
          const uint8_t* content, size_t contentLen,
          const ErrorCallBack& errorCallBack = Producer::defaultErrorCallBack);

public:
  /**
   * @brief Default error callback
   *
   * @param code The error code.
   * @param msg The error msg.
   */
  static void
  defaultErrorCallBack(const ErrorCode& code, const std::string& msg);

private:

  /**
   * @brief Send interest for E-KEY
   *
   * This method simply construct DataCallback, NackCallback, TiemoutCallback using
   * @p timeslot, @p callback, and @p errorCallBack, and express @p interest with
   * the created callbacks.
   */
  void
  sendKeyInterest(const Interest& interest,
                  const time::system_clock::TimePoint& timeslot,
                  const ProducerEKeyCallback& callback,
                  const ErrorCallBack& errorCallBack = Producer::defaultErrorCallBack);

  /**
   * @brief Handle received E-KEY retrieved using @p interest.
   *
   * This method first checks if the E-key contained in @p data fits @p timeslot.
   * If true, encrypt the C-KEY for @p timeslot using the E-KEY, if the retrieval for
   * all E-KEYs for the C-KEY have been done, invoke @p callback. Otherwise, narrow down
   * the search scope through revising exclude filter and re-express the interest. In case
   * of any error, invoke @p errorCallBack.
   */
  void
  handleCoveringKey(const Interest& interest, const Data& data,
                    const time::system_clock::TimePoint& timeslot,
                    const ProducerEKeyCallback& callback,
                    const ErrorCallBack& errorCallBack = Producer::defaultErrorCallBack);

  /**
   * @brief Handle timeout.
   *
   * Re-express @p interest if the number of retrials is less than max limit.
   * The DataCallback, NackCallback, TiemoutCallback are created using @p timeslot,
   * @p callback, and @p errorCallBack,
   */
  void
  handleTimeout(const Interest& interest,
                const time::system_clock::TimePoint& timeslot,
                const ProducerEKeyCallback& callback,
                const ErrorCallBack& errorCallBack = Producer::defaultErrorCallBack);

  /**
   * @brief Handle @p nack for the E-KEY requested through @p interest.
   *
   * This method will decrease the outstanding E-KEY interest count for the C-Key
   * corresponding to @p timeCount.  When there is no outstanding interest, invoke
   * @p callback.
   */
  void
  handleNack(const Interest& interest,
             const lp::Nack& nack,
             const time::system_clock::TimePoint& timeslot,
             const ProducerEKeyCallback& callback);

  /**
   * @brief Decrease the count of outstanding E-KEY interests for C-KEY for @p timeCount
   *
   * If the count decrease to 0, invoke @p callback.
   */
  void
  updateKeyRequest(KeyRequest& keyRequest, uint64_t timeCount,
                   const ProducerEKeyCallback& callback);

  /**
   * @brief Encrypts C-KEY for @p timeslot using @p encryptionKey of @p eKeyName
   *
   * Invoke @p callback if no more interests to process.
   * invoke @p errorCallback in case of any error.
   *
   * @return true if encryption succeeds, otherwise false.
   */
  bool
  encryptContentKey(const Buffer& encryptionKey, const Name& eKeyName,
                    const time::system_clock::TimePoint& timeslot,
                    const ProducerEKeyCallback& callback,
                    const ErrorCallBack& errorCallback = Producer::defaultErrorCallBack);

private:
  Face& m_face;
  Name m_namespace;
  KeyChain m_keychain;
  std::unordered_map<Name, KeyInfo> m_ekeyInfo;
  std::unordered_map<uint64_t, KeyRequest> m_keyRequests;
  ProducerDB m_db;
  uint8_t m_maxRepeatAttempts;
};

} // namespace gep
} // namespace ndn

#endif // NDN_GEP_PRODUCER_HPP
