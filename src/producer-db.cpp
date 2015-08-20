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

#include "producer-db.hpp"

#include <sqlite3.h>
#include <boost/filesystem.hpp>
#include <ndn-cxx/util/sqlite3-statement.hpp>
#include <ndn-cxx/security/identity-certificate.hpp>

namespace ndn {
namespace gep {

using util::Sqlite3Statement;
using time::system_clock;

static const std::string INITIALIZATION =
  "CREATE TABLE IF NOT EXISTS                         \n"
  "  contentkeys(                                     \n"
  "    rowId            INTEGER PRIMARY KEY,          \n"
  "    timeslot         INTEGER,                      \n"
  "    key              BLOB NOT NULL                 \n"
  "  );                                               \n"
  "CREATE UNIQUE INDEX IF NOT EXISTS                  \n"
  "   timeslotIndex ON contentkeys(timeslot);         \n";

class ProducerDB::Impl
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
      BOOST_THROW_EXCEPTION(Error("Producer DB cannot be opened/created: " + dbPath));

    // enable foreign key
    sqlite3_exec(m_database, "PRAGMA foreign_keys = ON", nullptr, nullptr, nullptr);

    // initialize database specific tables
    char* errorMessage = nullptr;
    result = sqlite3_exec(m_database, INITIALIZATION.c_str(), nullptr, nullptr, &errorMessage);
    if (result != SQLITE_OK && errorMessage != nullptr) {
      sqlite3_free(errorMessage);
      BOOST_THROW_EXCEPTION(Error("Producer DB cannot be initialized"));
    }
  }

  ~Impl()
  {
    sqlite3_close(m_database);
  }

public:
  sqlite3* m_database;
};

ProducerDB::ProducerDB(const std::string& dbPath)
  : m_impl(new Impl(dbPath))
{
}

ProducerDB::~ProducerDB() = default;

static int32_t
getFixedTimeslot(const system_clock::TimePoint& timeslot) {
  return (time::toUnixTimestamp(timeslot)).count() / 3600000;
}

bool
ProducerDB::hasContentKey(const system_clock::TimePoint& timeslot) const
{
  int32_t fixedTimeslot = getFixedTimeslot(timeslot);
  Sqlite3Statement statement(m_impl->m_database,
                             "SELECT key FROM contentkeys where timeslot=?");
  statement.bind(1, fixedTimeslot);
  return (statement.step() == SQLITE_ROW);
}


Buffer
ProducerDB::getContentKey(const system_clock::TimePoint& timeslot) const
{
  int32_t fixedTimeslot = getFixedTimeslot(timeslot);
  Sqlite3Statement statement(m_impl->m_database,
                             "SELECT key FROM contentkeys where timeslot=?");
  statement.bind(1, fixedTimeslot);

  Buffer result;
  if (statement.step() == SQLITE_ROW) {
    result = Buffer(statement.getBlob(0), statement.getSize(0));
  }
  else {
    BOOST_THROW_EXCEPTION(Error("Cannot get the key from database"));
  }
  return result;
}

void
ProducerDB::addContentKey(const system_clock::TimePoint& timeslot, const Buffer& key)
{
  // BOOST_ASSERT(key.length() != 0);
  int32_t fixedTimeslot = getFixedTimeslot(timeslot);
  Sqlite3Statement statement(m_impl->m_database,
                             "INSERT INTO contentkeys (timeslot, key)\
                              values (?, ?)");
  statement.bind(1, fixedTimeslot);
  statement.bind(2, key.buf(), key.size(), SQLITE_TRANSIENT);
  if (statement.step() != SQLITE_DONE)
    BOOST_THROW_EXCEPTION(Error("Cannot add the key to database"));
}

void
ProducerDB::deleteContentKey(const system_clock::TimePoint& timeslot)
{
  int32_t fixedTimeslot = getFixedTimeslot(timeslot);
  Sqlite3Statement statement(m_impl->m_database,
                             "DELETE FROM contentkeys WHERE timeslot=?");
  statement.bind(1, fixedTimeslot);
  statement.step();
}

} // namespace gep
} // namespace ndn
