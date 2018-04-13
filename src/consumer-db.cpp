/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2018, Regents of the University of California
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
 * @author Zhiyi Zhang <zhiyi@cs.ucla.edu>
 */

#include "consumer-db.hpp"
#include <ndn-cxx/util/sqlite3-statement.hpp>
#include <boost/filesystem.hpp>
#include <sqlite3.h>

namespace ndn {
namespace gep {

using util::Sqlite3Statement;

static const std::string INITIALIZATION = R"_DBTEXT_(
CREATE TABLE IF NOT EXISTS
  decryptionkeys(
    key_id              INTEGER PRIMARY KEY,
    key_name            BLOB NOT NULL,
    key_buf             BLOB NOT NULL
  );
CREATE UNIQUE INDEX IF NOT EXISTS
   KeyNameIndex ON decryptionkeys(key_name);
)_DBTEXT_";

class ConsumerDB::Impl
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
                             R"_DBTEXT_(SELECT key_buf FROM decryptionkeys
                             WHERE key_name=?)_DBTEXT_");
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
                             R"_DBTEXT_(INSERT INTO decryptionkeys(key_name, key_buf)
                             values (?, ?))_DBTEXT_");
  statement.bind(1, keyName.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(2, keyBuf.data(), keyBuf.size(), SQLITE_TRANSIENT);

  if (statement.step() != SQLITE_DONE)
    BOOST_THROW_EXCEPTION(Error("Cannot add the key to database"));
}

void
ConsumerDB::deleteKey(const Name& keyName)
{
  Sqlite3Statement statement(m_impl->m_database,
                             R"_DBTEXT_(DELETE FROM decryptionkeys WHERE key_name=?)_DBTEXT_");
  statement.bind(1, keyName.wireEncode(), SQLITE_TRANSIENT);
  statement.step();
}

} // namespace gep
} // namespace ndn
