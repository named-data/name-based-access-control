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
 */

#include "group-manager.hpp"
#include "algo/encryptor.hpp"
#include "encrypted-content.hpp"

#include <map>

namespace ndn {
namespace gep {

GroupManager::GroupManager(const Name& prefix, const Name& dataType, const std::string& dbPath,
                           const int paramLength, const int freshPeriod)
  : m_namespace(prefix)
  , m_db(dbPath)
  , m_paramLength(paramLength)
  , m_freshPeriod(freshPeriod)
{
  m_namespace.append(NAME_COMPONENT_READ).append(dataType);
}

std::list<Data>
GroupManager::getGroupKey(const TimeStamp& timeslot)
{
  std::map<Name, Buffer> memberKeys;
  std::list<Data> result;

  // get time interval
  Interval finalInterval = calculateInterval(timeslot, memberKeys);
  if (finalInterval.isValid() == false)
    return result;

  std::string startTs = boost::posix_time::to_iso_string(finalInterval.getStartTime());
  std::string endTs = boost::posix_time::to_iso_string(finalInterval.getEndTime());

  // generate the pri key and pub key
  Buffer priKeyBuf, pubKeyBuf;
  generateKeyPairs(priKeyBuf, pubKeyBuf);

  // add the first element to the result
  // E-KEY (public key) data packet name convention:
  // /<data_type>/E-KEY/[start-ts]/[end-ts]
  Data data = createEKeyData(startTs, endTs, pubKeyBuf);
  result.push_back(data);

  // encrypt pri key with pub key from certificate
  for (const auto& entry : memberKeys) {
    const Name& keyName = entry.first;
    const Buffer& certKey = entry.second;

    // generate the name of the packet
    // D-KEY (private key) data packet name convention:
    // /<data_type>/D-KEY/[start-ts]/[end-ts]/[member-name]
    data = createDKeyData(startTs, endTs, keyName, priKeyBuf, certKey);
    result.push_back(data);
  }
  return result;
}

void
GroupManager::addSchedule(const std::string& scheduleName, const Schedule& schedule)
{
  m_db.addSchedule(scheduleName, schedule);
}

void
GroupManager::deleteSchedule(const std::string& scheduleName)
{
  m_db.deleteSchedule(scheduleName);
}

void
GroupManager::updateSchedule(const std::string& scheduleName, const Schedule& schedule)
{
  m_db.updateSchedule(scheduleName, schedule);
}

void
GroupManager::addMember(const std::string& scheduleName, const Data& memCert)
{
  IdentityCertificate cert(memCert);
  m_db.addMember(scheduleName, cert.getPublicKeyName(), cert.getPublicKeyInfo().get());
}

void
GroupManager::removeMember(const Name& identity)
{
  m_db.deleteMember(identity);
}

void
GroupManager::updateMemberSchedule(const Name& identity, const std::string& scheduleName)
{
  m_db.updateMemberSchedule(identity, scheduleName);
}

Interval
GroupManager::calculateInterval(const TimeStamp& timeslot, std::map<Name, Buffer>& memberKeys)
{
  // prepare
  Interval positiveResult;
  Interval negativeResult;
  Interval tempInterval;
  Interval finalInterval;
  bool isPositive;
  memberKeys.clear();

  // get the all intervals from schedules
  for (const std::string& scheduleName : m_db.listAllScheduleNames()) {

    const Schedule& schedule = m_db.getSchedule(scheduleName);
    std::tie(isPositive, tempInterval) = schedule.getCoveringInterval(timeslot);

    if (isPositive) {
      if (!positiveResult.isValid())
        positiveResult = tempInterval;
      positiveResult && tempInterval;

      std::map<Name, Buffer> m = m_db.getScheduleMembers(scheduleName);
      memberKeys.insert(m.begin(), m.end());
    }
    else {
      if (!negativeResult.isValid())
        negativeResult = tempInterval;
      negativeResult && tempInterval;
    }
  }
  if (!positiveResult.isValid()) {
    // return invalid interval when there is no member has interval covering the time slot
    return Interval(false);
  }

  // get the final interval result
  if (negativeResult.isValid())
    finalInterval = positiveResult && negativeResult;
  else
    finalInterval = positiveResult;

  return finalInterval;
}

void
GroupManager::generateKeyPairs(Buffer& priKeyBuf, Buffer& pubKeyBuf) const
{
  RandomNumberGenerator rng;
  RsaKeyParams params(m_paramLength);
  DecryptKey<algo::Rsa> privateKey = algo::Rsa::generateKey(rng, params);
  priKeyBuf = privateKey.getKeyBits();
  EncryptKey<algo::Rsa> publicKey = algo::Rsa::deriveEncryptKey(priKeyBuf);
  pubKeyBuf = publicKey.getKeyBits();
}


Data
GroupManager::createEKeyData(const std::string& startTs, const std::string& endTs,
                             const Buffer& pubKeyBuf)
{
  Name name(m_namespace);
  name.append(NAME_COMPONENT_E_KEY).append(startTs).append(endTs);
  Data data(name);
  data.setFreshnessPeriod(time::hours(m_freshPeriod));
  data.setContent(pubKeyBuf.get(), pubKeyBuf.size());
  m_keyChain.sign(data);
  return data;
}

Data
GroupManager::createDKeyData(const std::string& startTs, const std::string& endTs,
                             const Name& keyName, const Buffer& priKeyBuf,
                             const Buffer& certKey)
{
  Name name(m_namespace);
  name.append(NAME_COMPONENT_D_KEY);
  name.append(startTs).append(endTs);
  Data data = Data(name);
  data.setFreshnessPeriod(time::hours(m_freshPeriod));
  algo::EncryptParams eparams(tlv::AlgorithmRsaOaep);
  algo::encryptData(data, priKeyBuf.buf(), priKeyBuf.size(), keyName,
                    certKey.buf(), certKey.size(), eparams);
  m_keyChain.sign(data);
  return data;
}

} // namespace ndn
} // namespace ndn
