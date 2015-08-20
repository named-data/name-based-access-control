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

#include "producer.hpp"
#include "random-number-generator.hpp"
#include "algo/encryptor.hpp"
#include "algo/aes.hpp"

namespace ndn {
namespace gep {

using time::system_clock;

static const int startTs = -2;
static const int endTs = -1;

/**
  @brief Method to round the provided @p timeslot to the nearest whole
  hour, so that we can store content keys uniformly (by start of the hour).
*/
static const system_clock::TimePoint
getRoundedTimeslot(const system_clock::TimePoint& timeslot) {
  return time::fromUnixTimestamp(
    (time::toUnixTimestamp(timeslot) / 3600000) * 3600000);
}

Producer::Producer(const Name& prefix, const Name& dataType,
                   Face& face, const std::string& dbPath, uint8_t repeatAttempts)
  : m_face(face),
    m_db(dbPath),
    m_maxRepeatAttempts(repeatAttempts)
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
                           const ProducerEKeyCallback& callback)
{
  const system_clock::TimePoint hourSlot = getRoundedTimeslot(timeslot);

  // Create content key name.
  Name contentKeyName = m_namespace;
  contentKeyName.append(NAME_COMPONENT_C_KEY);
  contentKeyName.append(time::toIsoString(hourSlot));

  Buffer contentKeyBits;
  if (m_db.hasContentKey(timeslot)) {
    contentKeyBits = m_db.getContentKey(timeslot);
    return contentKeyName;
  }

  RandomNumberGenerator rng;
  AesKeyParams aesParams(128);
  contentKeyBits = algo::Aes::generateKey(rng, aesParams).getKeyBits();
  m_db.addContentKey(timeslot, contentKeyBits);

  uint64_t timeCount = toUnixTimestamp(timeslot).count();
  m_keyRequests.insert({timeCount, KeyRequest(m_ekeyInfo.size())});
  KeyRequest& keyRequest = m_keyRequests.at(timeCount);

  Exclude timeRange;
  timeRange.excludeAfter(name::Component(time::toIsoString(timeslot)));
  // Send interests for all nodes in tree.
  std::unordered_map<Name, KeyInfo>::iterator it;
  for (it = m_ekeyInfo.begin(); it != m_ekeyInfo.end(); ++it) {
    const KeyInfo& keyInfo = it->second;
    keyRequest.repeatAttempts.insert({it->first, 0});
    if (timeslot < keyInfo.beginTimeslot || timeslot >= keyInfo.endTimeslot) {
      sendKeyInterest(it->first, timeslot, keyRequest, callback, timeRange);
    }
    else {
      Name eKeyName(it->first);
      eKeyName.append(time::toIsoString(keyInfo.beginTimeslot));
      eKeyName.append(time::toIsoString(keyInfo.endTimeslot));
      encryptContentKey(keyRequest, keyInfo.keyBits, eKeyName, timeslot, callback);
    }
  }

  return contentKeyName;
}

void
Producer::produce(Data& data, const system_clock::TimePoint& timeslot,
                  const uint8_t* content, size_t contentLen)
{
  Buffer contentKey;

  Name contentKeyName = createContentKey(timeslot, nullptr);
  contentKey = m_db.getContentKey(timeslot);

  Name dataName = m_namespace;
  dataName.append(time::toIsoString(getRoundedTimeslot(timeslot)));

  data.setName(dataName);
  algo::EncryptParams params(tlv::AlgorithmAesCbc, 16);
  algo::encryptData(data, content, contentLen, contentKeyName,
                    contentKey.buf(), contentKey.size(), params);
  m_keychain.sign(data);
}

void
Producer::sendKeyInterest(const Name& name, const system_clock::TimePoint& timeslot,
                          KeyRequest& keyRequest,
                          const ProducerEKeyCallback& callback,
                          const Exclude& timeRange)
{
  auto onkey = std::bind(&Producer::handleCoveringKey, this, _1, _2,
                         std::cref(timeslot), std::ref(keyRequest), callback);
  auto timeout = std::bind(&Producer::handleTimeout, this, _1,
                           std::cref(timeslot), std::ref(keyRequest), callback);

  Selectors selector;
  selector.setExclude(timeRange);
  selector.setChildSelector(1);

  Interest keyInterest(name);
  keyInterest.setSelectors(selector);

  m_face.expressInterest(keyInterest, onkey, timeout);
}

void
Producer::encryptContentKey(KeyRequest& keyRequest, const Buffer& encryptionKey,
                            const Name& eKeyName,
                            const system_clock::TimePoint& timeslot,
                            const ProducerEKeyCallback& callback)
{
  Name keyName = m_namespace;
  keyName.append(NAME_COMPONENT_C_KEY);
  keyName.append(time::toIsoString(getRoundedTimeslot(timeslot)));

  Buffer contentKey = m_db.getContentKey(timeslot);

  Data cKeyData;
  cKeyData.setName(keyName);
  algo::EncryptParams params(tlv::AlgorithmRsaOaep);
  algo::encryptData(cKeyData, contentKey.buf(), contentKey.size(), eKeyName,
                    encryptionKey.buf(), encryptionKey.size(), params);
  m_keychain.sign(cKeyData);
  keyRequest.encryptedKeys.push_back(cKeyData);

  keyRequest.interestCount--;
  if (keyRequest.interestCount == 0 && callback) {
    callback(keyRequest.encryptedKeys);
    m_keyRequests.erase(toUnixTimestamp(timeslot).count());
  }
}

void
Producer::handleCoveringKey(const Interest& interest, Data& data,
                            const system_clock::TimePoint& timeslot,
                            KeyRequest& keyRequest,
                            const ProducerEKeyCallback& callback)
{
  Name interestName = interest.getName();
  Name keyName = data.getName();

  system_clock::TimePoint begin = time::fromIsoString(keyName.get(startTs).toUri());
  system_clock::TimePoint end = time::fromIsoString(keyName.get(endTs).toUri());

  if (timeslot >= end) {
    Exclude timeRange = interest.getSelectors().getExclude();
    timeRange.excludeBefore(keyName.get(startTs));
    keyRequest.repeatAttempts[interestName] = 0;
    sendKeyInterest(interestName, timeslot, keyRequest, callback, timeRange);
    return;
  }

  const Block keyBlock = data.getContent();
  Buffer encryptionKey(keyBlock.value(), keyBlock.value_size());
  m_ekeyInfo[interestName].beginTimeslot = begin;
  m_ekeyInfo[interestName].endTimeslot = end;
  m_ekeyInfo[interestName].keyBits = encryptionKey;

  encryptContentKey(keyRequest, encryptionKey, keyName, timeslot, callback);
}

void
Producer::handleTimeout(const Interest& interest,
                        const system_clock::TimePoint& timeslot,
                        KeyRequest& keyRequest,
                        const ProducerEKeyCallback& callback)
{
  Name interestName = interest.getName();

  if (keyRequest.repeatAttempts[interestName] < m_maxRepeatAttempts) {
    keyRequest.repeatAttempts[interestName]++;
    sendKeyInterest(interestName, timeslot, keyRequest, callback,
                    interest.getSelectors().getExclude());
  }
  else {
    keyRequest.interestCount--;
  }

  if (keyRequest.interestCount == 0 && callback) {
    callback(keyRequest.encryptedKeys);
    m_keyRequests.erase(toUnixTimestamp(timeslot).count());
  }
}

} // namespace gep
} // namespace ndn