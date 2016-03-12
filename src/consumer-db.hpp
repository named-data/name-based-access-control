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

#ifndef NDN_GEP_CONSUMER_DB_HPP
#define NDN_GEP_CONSUMER_DB_HPP

#include "common.hpp"

namespace ndn {
namespace gep {

/**
 * @brief ConsumerDB is a class to manage decryption keys for consumer.
 */
class ConsumerDB
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
  /** @brief Create a consumer database at @p dbPath
   */
  explicit
  ConsumerDB(const std::string& dbPath);

  ~ConsumerDB();

public:
  /**
   * @brief Get the key with @p keyName from database.
   *
   * @return Empty buffer when there is no key with @p keyName in database
   */
  const Buffer
  getKey(const Name& keyName) const;

  /**
   * @brief Add the key with @p keyName and @p keyBuf to database.
   *
   * @throw Error when a key with the same name already exists in database.
   */
  void
  addKey(const Name& keyName, const Buffer& keyBuf);

  /**
   * @brief Remove the key with @p keyName from the database.
   */
  void
  deleteKey(const Name& keyName);

private:
  class Impl;
  unique_ptr<Impl> m_impl;
};

} // namespace gep
} // namespace ndn

#endif // NDN_GEP_CONSUMER_DB_HPP
