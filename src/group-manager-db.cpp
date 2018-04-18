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
 * @author Zhiyi Zhang <zhiyi@cs.ucla.edu>
 */

#include "group-manager-db.hpp"
#include "algo/rsa.hpp"
#include <ndn-cxx/util/sqlite3-statement.hpp>
#include <boost/filesystem.hpp>
#include <sqlite3.h>
#include <ndn-cxx/util/string-helper.hpp>

namespace ndn {
namespace nac {

using util::Sqlite3Statement;

static const std::string INITIALIZATION = R"_DBTEXT_(
CREATE TABLE IF NOT EXISTS
  schedules(
    schedule_id         INTEGER PRIMARY KEY,
    schedule_name       TEXT NOT NULL,
    schedule            BLOB NOT NULL
  );
CREATE UNIQUE INDEX IF NOT EXISTS
   scheduleNameIndex ON schedules(schedule_name);

CREATE TABLE IF NOT EXISTS
  members(
    member_id           INTEGER PRIMARY KEY,
    schedule_id         INTEGER NOT NULL,
    member_name         BLOB NOT NULL,
    key_name            BLOB NOT NULL,
    pubkey              BLOB NOT NULL,
    FOREIGN KEY(schedule_id)
      REFERENCES schedules(schedule_id)
      ON DELETE CASCADE
      ON UPDATE CASCADE
  );
CREATE UNIQUE INDEX IF NOT EXISTS
   memNameIndex ON members(member_name);

CREATE TABLE IF NOT EXISTS
  ekeys(
    ekey_id             INTEGER PRIMARY KEY,
    ekey_name           BLOB NOT NULL,
    pub_key             BLOB NOT NULL
  );
CREATE UNIQUE INDEX IF NOT EXISTS
   ekeyNameIndex ON ekeys(ekey_name);)_DBTEXT_";

class GroupManagerDB::Impl
{
public:
  Impl(const std::string& dbPath)
  {
    // open Database

    int result = sqlite3_open_v2(dbPath.c_str(),
                                 &m_database,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                                 nullptr);

    if (result != SQLITE_OK)
      BOOST_THROW_EXCEPTION(Error("GroupManager DB cannot be opened/created: " + dbPath));

    // enable foreign key
    sqlite3_exec(m_database, "PRAGMA foreign_keys = ON", nullptr, nullptr, nullptr);

    // initialize database specific tables
    char* errorMessage = nullptr;
    result = sqlite3_exec(m_database, INITIALIZATION.c_str(), nullptr, nullptr, &errorMessage);
    if (result != SQLITE_OK && errorMessage != nullptr) {
      sqlite3_free(errorMessage);
      BOOST_THROW_EXCEPTION(Error("GroupManager DB cannot be initialized"));
    }
  }

  ~Impl()
  {
    sqlite3_close(m_database);
  }

  int
  getScheduleId(const std::string& name) const
  {
    Sqlite3Statement statement(m_database,
                               R"_DBTEXT_(SELECT schedule_id FROM schedules
                               WHERE schedule_name=?)_DBTEXT_");
    statement.bind(1, name, SQLITE_TRANSIENT);

    int result = -1;
    if (statement.step() == SQLITE_ROW)
      result = statement.getInt(0);
    return result;
  }

public:
  sqlite3* m_database;
  std::map<Name, Buffer> m_priKeyBase;
};

GroupManagerDB::GroupManagerDB(const std::string& dbPath)
  : m_impl(new Impl(dbPath))
{
}

GroupManagerDB::~GroupManagerDB() = default;

bool
GroupManagerDB::hasSchedule(const std::string& name) const
{
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(SELECT schedule_id FROM schedules
                             WHERE schedule_name=?)_DBTEXT_");
  statement.bind(1, name, SQLITE_TRANSIENT);
  return (statement.step() == SQLITE_ROW);
}

std::list<std::string>
GroupManagerDB::listAllScheduleNames() const
{
  std::list<std::string> result;
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(SELECT schedule_name FROM schedules)_DBTEXT_");

  result.clear();
  while (statement.step() == SQLITE_ROW) {
    result.push_back(statement.getString(0));
  }
  return result;
}

Schedule
GroupManagerDB::getSchedule(const std::string& name) const
{
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(SELECT schedule FROM schedules where schedule_name=?)_DBTEXT_");
  statement.bind(1, name, SQLITE_TRANSIENT);

  Schedule result;
  if (statement.step() == SQLITE_ROW) {
    result.wireDecode(statement.getBlock(0));
  }
  else {
    BOOST_THROW_EXCEPTION(Error("Cannot get the result from database"));
  }
  return result;
}

std::map<Name, Buffer>
GroupManagerDB::getScheduleMembers(const std::string& name) const
{
  std::map<Name, Buffer> result;
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(SELECT key_name, pubkey
                             FROM members JOIN schedules
                             ON members.schedule_id=schedules.schedule_id
                             WHERE schedule_name=?)_DBTEXT_");
  statement.bind(1, name, SQLITE_TRANSIENT);
  result.clear();

  const uint8_t* keyBytes = nullptr;
  while (statement.step() == SQLITE_ROW) {
    keyBytes = statement.getBlob(1);
    const int& keyBytesSize = statement.getSize(1);
    result.insert(std::pair<Name, Buffer>(Name(statement.getBlock(0)),
                                          Buffer(keyBytes, keyBytesSize)));
  }
  return result;
}

void
GroupManagerDB::addSchedule(const std::string& name, const Schedule& schedule)
{
  BOOST_ASSERT(name.length() != 0);

  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(INSERT INTO schedules (schedule_name, schedule)
                             values (?, ?))_DBTEXT_");
  statement.bind(1, name, SQLITE_TRANSIENT);
  statement.bind(2, schedule.wireEncode(), SQLITE_TRANSIENT);
  if (statement.step() != SQLITE_DONE)
    BOOST_THROW_EXCEPTION(Error("Cannot add the schedule to database"));
}

void
GroupManagerDB::deleteSchedule(const std::string& name)
{
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(DELETE FROM schedules WHERE schedule_name=?)_DBTEXT_");
  statement.bind(1, name, SQLITE_TRANSIENT);
  statement.step();
}

void
GroupManagerDB::renameSchedule(const std::string& oldName, const std::string& newName)
{
  BOOST_ASSERT(newName.length() != 0);

  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(UPDATE schedules SET schedule_name=?
                             WHERE schedule_name=?)_DBTEXT_");
  statement.bind(1, newName, SQLITE_TRANSIENT);
  statement.bind(2, oldName, SQLITE_TRANSIENT);
  if (statement.step() != SQLITE_DONE)
    BOOST_THROW_EXCEPTION(Error("Cannot rename the schedule from database"));
}

void
GroupManagerDB::updateSchedule(const std::string& name, const Schedule& schedule)
{
  if (!hasSchedule(name)) {
    addSchedule(name, schedule);
    return;
  }

  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(UPDATE schedules SET schedule=?
                             WHERE schedule_name=?)_DBTEXT_");
  statement.bind(1, schedule.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(2, name, SQLITE_TRANSIENT);
  statement.step();
}

bool
GroupManagerDB::hasMember(const Name& identity) const
{
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(SELECT member_id FROM members WHERE member_name=?)_DBTEXT_");
  statement.bind(1, identity.wireEncode(), SQLITE_TRANSIENT);
  return (statement.step() == SQLITE_ROW);
}

std::list<Name>
GroupManagerDB::listAllMembers() const
{
  std::list<Name> result;
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(SELECT member_name FROM members)_DBTEXT_");

  result.clear();
  while (statement.step() == SQLITE_ROW) {
    result.push_back(Name(statement.getBlock(0)));
  }
  return result;
}

std::string
GroupManagerDB::getMemberSchedule(const Name& identity) const
{
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(SELECT schedule_name
                             FROM schedules JOIN members
                             ON schedules.schedule_id = members.schedule_id
                             WHERE member_name=?)_DBTEXT_");
  statement.bind(1, identity.wireEncode(), SQLITE_TRANSIENT);

  std::string result = "";
  if (statement.step() == SQLITE_ROW) {
    result = statement.getString(0);
  }
  else {
    BOOST_THROW_EXCEPTION(Error("Cannot get the result from database"));
  }
  return result;
}

void
GroupManagerDB::addMember(const std::string& scheduleName, const Name& keyName, const Buffer& key)
{
  int scheduleId = m_impl->getScheduleId(scheduleName);
  if (scheduleId == -1)
    BOOST_THROW_EXCEPTION(Error("The schedule dose not exist"));

  // need to be changed in the future
  Name memberName = keyName.getPrefix(-1);

  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(INSERT INTO members(schedule_id, member_name, key_name, pubkey)
                             values (?, ?, ?, ?))_DBTEXT_");
  statement.bind(1, scheduleId);
  statement.bind(2, memberName.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(3, keyName.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(4, key.data(), key.size(), SQLITE_TRANSIENT);

  if (statement.step() != SQLITE_DONE)
    BOOST_THROW_EXCEPTION(Error("Cannot add the member to database"));
}

void
GroupManagerDB::updateMemberSchedule(const Name& identity, const std::string& scheduleName)
{
  int scheduleId = m_impl->getScheduleId(scheduleName);
  if (scheduleId == -1)
    BOOST_THROW_EXCEPTION(Error("The schedule dose not exist"));

  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(UPDATE members SET schedule_id=?
                             WHERE member_name=?)_DBTEXT_");
  statement.bind(1, scheduleId);
  statement.bind(2, identity.wireEncode(), SQLITE_TRANSIENT);
  statement.step();
}

void
GroupManagerDB::deleteMember(const Name& identity)
{
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(DELETE FROM members WHERE member_name=?)_DBTEXT_");
  statement.bind(1, identity.wireEncode(), SQLITE_TRANSIENT);
  statement.step();
}

bool
GroupManagerDB::hasEKey(const Name& eKeyName)
{
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(SELECT ekey_id FROM ekeys where ekey_name=?)_DBTEXT_");
  statement.bind(1, eKeyName.wireEncode(), SQLITE_TRANSIENT);
  return (statement.step() == SQLITE_ROW);
}

void
GroupManagerDB::addEKey(const Name& eKeyName, const Buffer& pubKey, const Buffer& priKey)
{
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(INSERT INTO ekeys(ekey_name, pub_key)
                             values (?, ?))_DBTEXT_");
  statement.bind(1, eKeyName.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(2, pubKey.data(), pubKey.size(), SQLITE_TRANSIENT);
  if (statement.step() != SQLITE_DONE)
    BOOST_THROW_EXCEPTION(Error("Cannot add the EKey to database"));

  m_impl->m_priKeyBase[eKeyName] = priKey;
}

std::tuple<Buffer, Buffer>
GroupManagerDB::getEKey(const Name& eKeyName)
{
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(SELECT * FROM ekeys where ekey_name=?)_DBTEXT_");
  statement.bind(1, eKeyName.wireEncode(), SQLITE_TRANSIENT);

  Buffer pubKey, priKey;
  if (statement.step() == SQLITE_ROW) {
    pubKey = Buffer(statement.getBlob(2), statement.getSize(2));
  }
  else {
    BOOST_THROW_EXCEPTION(Error("Cannot get the result from database"));
  }
  return std::make_tuple(pubKey, m_impl->m_priKeyBase[eKeyName]);
}

void
GroupManagerDB::cleanEKeys()
{
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(DELETE FROM ekeys)_DBTEXT_");
  statement.step();
  m_impl->m_priKeyBase.clear();
}

void
GroupManagerDB::deleteEKey(const Name& eKeyName)
{
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(DELETE FROM ekeys WHERE ekey_name=?)_DBTEXT_");
  statement.bind(1, eKeyName.wireEncode(), SQLITE_TRANSIENT);
  statement.step();

  auto search = m_impl->m_priKeyBase.find(eKeyName);
  if (search != m_impl->m_priKeyBase.end()) {
    m_impl->m_priKeyBase.erase(search);
  }
}

} // namespace nac
} // namespace ndn
