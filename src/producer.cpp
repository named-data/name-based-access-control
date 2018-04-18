/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2018, Regents of the University of California
 *
 * This file is part of NAC (Name-Based Access Control for NDN).
 * See AUTHORS.md for complete list of NAC authors and contributors.
 *
 * NAC is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NAC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NAC, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Prashanth Swaminathan <prashanthsw@gmail.com>
 * @author Yingdi Yu <yuyingdi@gmail.com>
 * @author Zhiyi Zhang <zhiyi@cs.ucla.edu>
 */

#include "producer.hpp"
#include "algo/aes.hpp"
#include "algo/encryptor.hpp"
#include "algo/error.hpp"
#include <iostream>

namespace ndn {
namespace nac {

using time::system_clock;

static const int START_TS_INDEX = -2;
static const int END_TS_INDEX = -1;

const Link Producer::NO_LINK = Link();

/**
  @brief Method to round the provided @p timeslot to the nearest whole
  hour, so that we can store content keys uniformly (by start of the hour).
*/
static const system_clock::TimePoint
getRoundedTimeslot(const system_clock::TimePoint& timeslot)
{
  return time::fromUnixTimestamp((time::toUnixTimestamp(timeslot) / 3600000) * 3600000);
}

Producer::Producer(const Name& prefix,
                   const Name& dataType,
                   Face& face,
                   const std::string& dbPath,
                   uint8_t repeatAttempts,
                   const Link& keyRetrievalLink)
  : m_face(face)
  , m_db(dbPath)
  , m_maxRepeatAttempts(repeatAttempts)
  , m_keyRetrievalLink(keyRetrievalLink)
{
  Name fixedPrefix = prefix;
  Name fixedDataType = dataType;
  KeyInfo keyInfo;
  /**
    Fill m_ekeyInfo vector with all permutations of dataType, including the 'E-KEY'
    component of the name. This will be used in DataProducer::createContentKey to
    send interests without reconstructing names every time.
  */
  fixedPrefix.append(NAME_COMPONENT_READ);
  while (!fixedDataType.empty()) {
    Name nodeName = fixedPrefix;
    nodeName.append(fixedDataType);
    nodeName.append(NAME_COMPONENT_E_KEY);

    m_ekeyInfo[nodeName] = keyInfo;
    fixedDataType = fixedDataType.getPrefix(-1);
  }
  fixedPrefix.append(dataType);
  m_namespace = prefix;
  m_namespace.append(NAME_COMPONENT_SAMPLE);
  m_namespace.append(dataType);
}

Name
Producer::createContentKey(const system_clock::TimePoint& timeslot,
                           const ProducerEKeyCallback& callback,
                           const ErrorCallBack& errorCallback)
{
  const system_clock::TimePoint hourSlot = getRoundedTimeslot(timeslot);

  // Create content key name.
  Name contentKeyName = m_namespace;
  contentKeyName.append(NAME_COMPONENT_C_KEY);
  contentKeyName.append(time::toIsoString(hourSlot));

  Buffer contentKeyBits;

  // Check if we have created the content key before.
  if (m_db.hasContentKey(timeslot)) {
    // We have created the content key, return its name directly.
    return contentKeyName;
  }

  // We haven't created the content key, create one and add it into the database.
  AesKeyParams aesParams(128);
  contentKeyBits = algo::Aes::generateKey(aesParams).getKeyBits();
  m_db.addContentKey(timeslot, contentKeyBits);

  // Now we need to retrieve the E-KEYs for content key encryption.
  uint64_t timeCount = toUnixTimestamp(timeslot).count();
  m_keyRequests.insert({timeCount, KeyRequest(m_ekeyInfo.size())});
  KeyRequest& keyRequest = m_keyRequests.at(timeCount);

  // Check if current E-KEYs can cover the content key.
  Exclude timeRange;
  timeRange.excludeAfter(name::Component(time::toIsoString(timeslot)));
  std::unordered_map<Name, KeyInfo>::iterator it;
  for (it = m_ekeyInfo.begin(); it != m_ekeyInfo.end(); ++it) {
    // for each current E-KEY
    if (timeslot < it->second.beginTimeslot || timeslot >= it->second.endTimeslot) {
      // current E-KEY cannot cover the content key, retrieve one.
      keyRequest.repeatAttempts[it->first] = 0;
      sendKeyInterest(Interest(it->first).setExclude(timeRange).setChildSelector(1),
                      timeslot,
                      callback,
                      errorCallback);
    }
    else {
      // current E-KEY can cover the content key, encrypt the content key directly.
      Name eKeyName(it->first);
      eKeyName.append(time::toIsoString(it->second.beginTimeslot));
      eKeyName.append(time::toIsoString(it->second.endTimeslot));
      encryptContentKey(it->second.keyBits, eKeyName, timeslot, callback, errorCallback);
    }
  }

  return contentKeyName;
}

void
Producer::defaultErrorCallBack(const ErrorCode& code, const std::string& msg)
{
  // do nothing.
}

void
Producer::produce(Data& data,
                  const system_clock::TimePoint& timeslot,
                  const uint8_t* content,
                  size_t contentLen,
                  const ErrorCallBack& errorCallBack)
{
  // Get a content key
  Name contentKeyName = createContentKey(timeslot, nullptr, errorCallBack);
  Buffer contentKey = m_db.getContentKey(timeslot);

  // Produce data
  Name dataName = m_namespace;
  dataName.append(time::toIsoString(timeslot));
  data.setName(dataName);
  algo::EncryptParams params(tlv::AlgorithmAesCbc, 16);
  algo::encryptData(data, content, contentLen, contentKeyName,
                    contentKey.data(), contentKey.size(), params);
  m_keychain.sign(data);
}

void
Producer::sendKeyInterest(const Interest& interest,
                          const system_clock::TimePoint& timeslot,
                          const ProducerEKeyCallback& callback,
                          const ErrorCallBack& errorCallback)
{
  Interest request(interest);
  if (m_keyRetrievalLink.getDelegationList().size() > 0) {
    request.setForwardingHint(m_keyRetrievalLink.getDelegationList());
  }
  m_face.expressInterest(request,
                         std::bind(&Producer::handleCoveringKey, this, _1, _2,
                                   timeslot, callback, errorCallback),
                         std::bind(&Producer::handleNack, this, _1, _2,
                                   timeslot, callback, errorCallback),
                         std::bind(&Producer::handleTimeout, this, _1,
                                   timeslot, callback, errorCallback));
}

void
Producer::handleCoveringKey(const Interest& interest,
                            const Data& data,
                            const system_clock::TimePoint& timeslot,
                            const ProducerEKeyCallback& callback,
                            const ErrorCallBack& errorCallback)
{
  uint64_t timeCount = toUnixTimestamp(timeslot).count();
  KeyRequest& keyRequest = m_keyRequests.at(timeCount);

  Name interestName = interest.getName();
  Name keyName = data.getName();

  system_clock::TimePoint begin = time::fromIsoString(keyName.get(START_TS_INDEX).toUri());
  system_clock::TimePoint end = time::fromIsoString(keyName.get(END_TS_INDEX).toUri());

  if (timeslot >= end) {
    // if received E-KEY covers some earlier period, try to retrieve an E-KEY covering later one.
    keyRequest.repeatAttempts[interestName] = 0;

    Exclude timeRange = interest.getSelectors().getExclude();
    timeRange.excludeBefore(keyName.get(START_TS_INDEX));

    sendKeyInterest(Interest(interestName).setExclude(timeRange).setChildSelector(1),
                    timeslot,
                    callback,
                    errorCallback);
  }
  else {
    // if received E-KEY covers the content key, encrypt the content
    Buffer encryptionKey(data.getContent().value(), data.getContent().value_size());
    // if everything is correct, save the E-KEY as the current key
    if (encryptContentKey(encryptionKey, keyName, timeslot, callback, errorCallback)) {
      m_ekeyInfo[interestName].beginTimeslot = begin;
      m_ekeyInfo[interestName].endTimeslot = end;
      m_ekeyInfo[interestName].keyBits = encryptionKey;
    }
  }
}

void
Producer::handleTimeout(const Interest& interest,
                        const system_clock::TimePoint& timeslot,
                        const ProducerEKeyCallback& callback,
                        const ErrorCallBack& errorCallback)
{
  uint64_t timeCount = toUnixTimestamp(timeslot).count();
  if (m_keyRequests.find(timeCount) == m_keyRequests.end()) {
    return;
  }
  KeyRequest& keyRequest = m_keyRequests.at(timeCount);

  Name interestName = interest.getName();
  if (keyRequest.repeatAttempts[interestName] < m_maxRepeatAttempts) {
    // increase retrial count
    keyRequest.repeatAttempts[interestName]++;
    sendKeyInterest(interest, timeslot, callback, errorCallback);
  }
  else {
    // treat eventual timeout as a NACK
    handleNack(interest, lp::Nack(), timeslot, callback, errorCallback);
  }
}

void
Producer::handleNack(const Interest& interest,
                     const lp::Nack& nack,
                     const system_clock::TimePoint& timeslot,
                     const ProducerEKeyCallback& callback,
                     const ErrorCallBack& errorCallback)
{
  // we run out of options...
  uint64_t timeCount = toUnixTimestamp(timeslot).count();

  if (m_keyRequests.find(timeCount) != m_keyRequests.end()) {
    updateKeyRequest(m_keyRequests.at(timeCount), timeCount, callback);
  }
}

void
Producer::updateKeyRequest(KeyRequest& keyRequest,
                           uint64_t timeCount,
                           const ProducerEKeyCallback& callback)
{
  keyRequest.interestCount--;
  if (keyRequest.interestCount == 0 && callback) {
    callback(keyRequest.encryptedKeys);
    m_keyRequests.erase(timeCount);
  }
}

bool
Producer::encryptContentKey(const Buffer& encryptionKey,
                            const Name& eKeyName,
                            const system_clock::TimePoint& timeslot,
                            const ProducerEKeyCallback& callback,
                            const ErrorCallBack& errorCallBack)
{
  uint64_t timeCount = toUnixTimestamp(timeslot).count();
  if (m_keyRequests.find(timeCount) == m_keyRequests.end()) {
    return false;
  }
  KeyRequest& keyRequest = m_keyRequests.at(timeCount);

  Name keyName = m_namespace;
  keyName.append(NAME_COMPONENT_C_KEY);
  keyName.append(time::toIsoString(getRoundedTimeslot(timeslot)));

  Buffer contentKey = m_db.getContentKey(timeslot);
  Data cKeyData;
  cKeyData.setName(keyName);
  algo::EncryptParams params(tlv::AlgorithmRsaOaep);
  try {
    algo::encryptData(cKeyData,
                      contentKey.data(),
                      contentKey.size(),
                      eKeyName,
                      encryptionKey.data(),
                      encryptionKey.size(),
                      params);
  }
  catch (const algo::Error& e) {
    errorCallBack(ErrorCode::EncryptionFailure, e.what());
    return false;
  }
  m_keychain.sign(cKeyData);
  keyRequest.encryptedKeys.push_back(cKeyData);
  updateKeyRequest(keyRequest, timeCount, callback);
  return true;
}

} // namespace nac
} // namespace ndn
