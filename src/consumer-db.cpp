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

#include "consumer-db.hpp"

#include <sqlite3.h>
#include <boost/filesystem.hpp>
#include <ndn-cxx/util/sqlite3-statement.hpp>

namespace ndn {
namespace gep {

using util::Sqlite3Statement;

static const std::string INITIALIZATION =
  "CREATE TABLE IF NOT EXISTS                         \n"
  "  decryptionkeys(                                  \n"
  "    key_id              INTEGER PRIMARY KEY,       \n"
  "    key_name            BLOB NOT NULL,             \n"
  "    key_buf             BLOB NOT NULL              \n"
  "  );                                               \n"
  "CREATE UNIQUE INDEX IF NOT EXISTS                  \n"
  "   KeyNameIndex ON decryptionkeys(key_name);       \n"
  "CREATE TABLE IF NOT EXISTS                         \n"
  "  consumer(                                        \n"
  "    prefix              BLOB PRIMARY KEY           \n"
  "  );                                               \n";

class ConsumerDB::Impl
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

public:
  sqlite3* m_database;
};


ConsumerDB::ConsumerDB(const std::string& dbPath)
  : m_impl(new Impl(dbPath))
{
}

ConsumerDB::~ConsumerDB() = default;

const Buffer
ConsumerDB::getKey(const Name& keyName) const
{
  Sqlite3Statement statement(m_impl->m_database,
                             "SELECT key_buf FROM decryptionkeys\
                              WHERE key_name=?");
  statement.bind(1, keyName.wireEncode(), SQLITE_TRANSIENT);

  Buffer result;
  if (statement.step() == SQLITE_ROW) {
    result = Buffer(statement.getBlob(0), statement.getSize(0));
  }
  return result;
}

void
ConsumerDB::addKey(const Name& keyName, const Buffer& keyBuf)
{
  Sqlite3Statement statement(m_impl->m_database,
                             "INSERT INTO decryptionkeys(key_name, key_buf)\
                              values (?, ?)");
  statement.bind(1, keyName.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(2, keyBuf.buf(), keyBuf.size(), SQLITE_TRANSIENT);

  if (statement.step() != SQLITE_DONE)
    BOOST_THROW_EXCEPTION(Error("Cannot add the key to database"));
}

void
ConsumerDB::deleteKey(const Name& keyName)
{
  Sqlite3Statement statement(m_impl->m_database,
                             "DELETE FROM decryptionkeys WHERE key_name=?");
  statement.bind(1, keyName.wireEncode(), SQLITE_TRANSIENT);
  statement.step();
}

} // namespace gep
} // namespace ndn
