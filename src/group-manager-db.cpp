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

#include "group-manager-db.hpp"
#include "algo/rsa.hpp"

#include <sqlite3.h>
#include <boost/filesystem.hpp>
#include <ndn-cxx/util/sqlite3-statement.hpp>
#include <ndn-cxx/security/identity-certificate.hpp>

namespace ndn {
namespace gep {

using util::Sqlite3Statement;

static const std::string INITIALIZATION =
  "CREATE TABLE IF NOT EXISTS                         \n"
  "  schedules(                                       \n"
  "    schedule_id         INTEGER PRIMARY KEY,       \n"
  "    schedule_name       TEXT NOT NULL,             \n"
  "    schedule            BLOB NOT NULL              \n"
  "  );                                               \n"
  "CREATE UNIQUE INDEX IF NOT EXISTS                  \n"
  "   scheduleNameIndex ON schedules(schedule_name);  \n"
  "                                                   \n"
  "CREATE TABLE IF NOT EXISTS                         \n"
  "  members(                                         \n"
  "    member_id           INTEGER PRIMARY KEY,       \n"
  "    schedule_id         INTEGER NOT NULL,          \n"
  "    member_name         BLOB NOT NULL,             \n"
  "    key_name            BLOB NOT NULL,             \n"
  "    pubkey              BLOB NOT NULL,             \n"
  "    FOREIGN KEY(schedule_id)                       \n"
  "      REFERENCES schedules(schedule_id)            \n"
  "      ON DELETE CASCADE                            \n"
  "      ON UPDATE CASCADE                            \n"
  "  );                                               \n"
  "CREATE UNIQUE INDEX IF NOT EXISTS                  \n"
  "   memNameIndex ON members(member_name);           \n";

class GroupManagerDB::Impl
{
public:
  Impl(const std::string& dbPath)
  {
    // open Database

    int result = sqlite3_open_v2(dbPath.c_str(), &m_database,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
#ifdef NDN_CXX_DISABLE_SQLITE3_FS_LOCKING
                                 "unix-dotfile"
#else
                                 nullptr
#endif
                                 );

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
                               "SELECT schedule_id FROM schedules WHERE schedule_name=?");
    statement.bind(1, name, SQLITE_TRANSIENT);

    int result = -1;
    if (statement.step() == SQLITE_ROW)
      result = statement.getInt(0);
    return result;
  }

public:
  sqlite3* m_database;
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
                             "SELECT schedule_id FROM schedules where schedule_name=?");
  statement.bind(1, name, SQLITE_TRANSIENT);
  return (statement.step() == SQLITE_ROW);
}

std::list<std::string>
GroupManagerDB::listAllScheduleNames() const
{
  std::list<std::string> result;
  Sqlite3Statement statement(m_impl->m_database,
                             "SELECT schedule_name FROM schedules");

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
                             "SELECT schedule FROM schedules where schedule_name=?");
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
                             "SELECT key_name, pubkey\
                              FROM members JOIN schedules\
                              ON members.schedule_id=schedules.schedule_id\
                              WHERE schedule_name=?");
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
                             "INSERT INTO schedules (schedule_name, schedule)\
                              values (?, ?)");
  statement.bind(1, name, SQLITE_TRANSIENT);
  statement.bind(2, schedule.wireEncode(), SQLITE_TRANSIENT);
  if (statement.step() != SQLITE_DONE)
    BOOST_THROW_EXCEPTION(Error("Cannot add the schedule to database"));
}

void
GroupManagerDB::deleteSchedule(const std::string& name)
{
  Sqlite3Statement statement(m_impl->m_database,
                             "DELETE FROM schedules WHERE schedule_name=?");
  statement.bind(1, name, SQLITE_TRANSIENT);
  statement.step();
}

void
GroupManagerDB::renameSchedule(const std::string& oldName, const std::string& newName)
{
  BOOST_ASSERT(newName.length() != 0);

  Sqlite3Statement statement(m_impl->m_database,
                             "UPDATE schedules SET schedule_name=? WHERE schedule_name=?");
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
                             "UPDATE schedules SET schedule=? WHERE schedule_name=?");
  statement.bind(1, schedule.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(2, name, SQLITE_TRANSIENT);
  statement.step();
}

bool
GroupManagerDB::hasMember(const Name& identity) const
{
  Sqlite3Statement statement(m_impl->m_database,
                             "SELECT member_id FROM members WHERE member_name=?");
  statement.bind(1, identity.wireEncode(), SQLITE_TRANSIENT);
  return (statement.step() == SQLITE_ROW);
}

std::list<Name>
GroupManagerDB::listAllMembers() const
{
  std::list<Name> result;
  Sqlite3Statement statement(m_impl->m_database,
                             "SELECT member_name FROM members");

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
                             "SELECT schedule_name\
                              FROM schedules JOIN members\
                              ON schedules.schedule_id = members.schedule_id\
                              WHERE member_name=?");
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
GroupManagerDB::addMember(const std::string& scheduleName, const Name& keyName,
                          const Buffer& key)
{
  int scheduleId = m_impl->getScheduleId(scheduleName);
  if (scheduleId == -1)
    BOOST_THROW_EXCEPTION(Error("The schedule dose not exist"));

  // need to be changed in the future
  Name memberName = keyName.getPrefix(-1);

  Sqlite3Statement statement(m_impl->m_database,
                             "INSERT INTO members(schedule_id, member_name, key_name, pubkey)\
                              values (?, ?, ?, ?)");
  statement.bind(1, scheduleId);
  statement.bind(2, memberName.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(3, keyName.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(4, key.buf(), key.size(), SQLITE_TRANSIENT);

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
                             "UPDATE members SET schedule_id=? WHERE member_name=?");
  statement.bind(1, scheduleId);
  statement.bind(2, identity.wireEncode(), SQLITE_TRANSIENT);
  statement.step();
}

void
GroupManagerDB::deleteMember(const Name& identity)
{
  Sqlite3Statement statement(m_impl->m_database,
                             "DELETE FROM members WHERE member_name=?");
  statement.bind(1, identity.wireEncode(), SQLITE_TRANSIENT);
  statement.step();
}

} // namespace gep
} // namespace ndn
