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
 */

#ifndef NDN_GEP_PRODUCER_HPP
#define NDN_GEP_PRODUCER_HPP

#include "producer-db.hpp"

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
   * @brief Create content key
   *
   * This method will first check if the content key exists. For existing
   * content key, the method will return content key name directly.
   * If the key does not exist, the method will create one and encrypt
   * it using corresponding E-KEY. The encrypted content keys will be
   * passed back through @p callback.
   */
  Name
  createContentKey(const time::system_clock::TimePoint& timeslot,
                   const ProducerEKeyCallback& callback);

  /**
   * @brief Produce an data packet encrypted using corresponding content key
   *
   * This method encrypts @p content with a content key covering
   * @p timeslot, and set @p data with the encrypted content and
   * appropriate data name.
   */
  void
  produce(Data& data, const time::system_clock::TimePoint& timeslot,
          const uint8_t* content, size_t contentLen);

private:

  /**
   * @brief Sends interest through face with necessary callbacks
   *        Uses @p exclude to limit interest if specified
   */
  void
  sendKeyInterest(const Name& name, const time::system_clock::TimePoint& timeslot,
                  KeyRequest& keyRequest, const ProducerEKeyCallback& callback,
                  const Exclude& timeRange = Exclude());

  /**
   * @brief Updates state in @p keyRequest on timeout
   */
  void
  handleTimeout(const Interest& interest,
                const time::system_clock::TimePoint& timeslot,
                KeyRequest& keyRequest, const ProducerEKeyCallback& callback);

  /**
   * @brief Checks that encryption key contained in @p data fits @p timeslot
   *        Sends refined interest if required
   */
  void
  handleCoveringKey(const Interest& interest, Data& data,
                    const time::system_clock::TimePoint& timeslot,
                    KeyRequest& keyRequest, const ProducerEKeyCallback& callback);

  /**
   * @brief Encrypts content key for @p timeslot with @p encryptionKey
   *        Fires @p callback if no more interests to process
   */
  void
  encryptContentKey(KeyRequest& keyRequest, const Buffer& encryptionKey,
                    const Name& eKeyName,
                    const time::system_clock::TimePoint& timeslot,
                    const ProducerEKeyCallback& callback);

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
