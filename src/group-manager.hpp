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

#ifndef NDN_GEP_GROUP_MANAGER_HPP
#define NDN_GEP_GROUP_MANAGER_HPP

#include "group-manager-db.hpp"
#include "algo/rsa.hpp"

#include <ndn-cxx/security/key-chain.hpp>

namespace ndn {
namespace gep {

class GroupManager
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

public:
  /**
   * @brief Create group manager
   *
   * The namespace of group manager is /<prefix>/read/<dataType>/
   * The group management information (including user cert, schedule) is stored in a database
   * at @p dbPath.
   * The group key will be an RSA key with @p paramLength bits.
   * The FreshnessPeriod of data packet carrying the keys will be set to @p freshPeriod hours.
   */
  GroupManager(const Name& prefix, const Name& dataType, const std::string& dbPath,
               const int paramLength, const int freshPeriod);

  /**
   * @brief Create a group key for interval which
   *        @p timeslot falls into
   *
   * This method creates a group key if it does not
   * exist, and encrypts the key using public key of
   * all eligible members
   *
   * @returns The group key (the first one is the
   *          public key, and the rest are encrypted
   *          private key.
   */
  std::list<Data>
  getGroupKey(const TimeStamp& timeslot);

  /// @brief Add @p schedule with @p scheduleName
  void
  addSchedule(const std::string& scheduleName, const Schedule& schedule);

  /// @brief Delete schedule with name @p scheduleName
  void
  deleteSchedule(const std::string& scheduleName);

  /// @brief Update a schedule by name @p scheduleName with a new @p schedule
  void
  updateSchedule(const std::string& scheduleName, const Schedule& schedule);

  /// @brief Add @p memCert with @p scheduleName
  void
  addMember(const std::string& scheduleName, const Data& memCert);

  /// @brief Remove member with name @p identity from the group.
  void
  removeMember(const Name& identity);

  /// @brief Update @p member with a schedule of @p schedule Name.
  void
  updateMemberSchedule(const Name& identity, const std::string& scheduleName);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  /**
   * @brief Calculate interval that covers @p timeslot
   * and fill @p memberKeys with the info of members who is allowed to access the interval.
   */
  Interval
  calculateInterval(const TimeStamp& timeslot, std::map<Name, Buffer>& certMap);

  /**
   * @brief Generate rsa key pairs according to the member variable m_paramLength.
   * @p priKeyBuf The generated private key buffer
   * @p pubKeyBuf The generated public key buffer
   */
  void
  generateKeyPairs(Buffer& priKeyBuf, Buffer& pubKeyBuf) const;

  /// @brief Create E-KEY data.
  Data
  createEKeyData(const std::string& startTs, const std::string& endTs,
                 const Buffer& pubKeyBuf);

  /// @brief Create D-KEY data.
  Data
  createDKeyData(const std::string& startTs, const std::string& endTs, const Name& keyName,
                 const Buffer& priKeyBuf, const Buffer& certKey);

private:
  Name m_namespace;
  GroupManagerDB m_db;
  int m_paramLength;
  int m_freshPeriod;

  KeyChain m_keyChain;
};

} // namespace gep
} // namespace ndn

#endif // NDN_GEP_GROUP_MANAGER_HPP
