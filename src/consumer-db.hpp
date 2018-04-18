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
 * @author Zhiyi Zhang <dreamerbarrychang@gmail.com>
 */

#ifndef NDN_NAC_CONSUMER_DB_HPP
#define NDN_NAC_CONSUMER_DB_HPP

#include "common.hpp"

namespace ndn {
namespace nac {

/**
 * @brief ConsumerDB is a class to manage decryption keys for consumer.
 */
class ConsumerDB
{
public:
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
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

} // namespace nac
} // namespace ndn

#endif // NDN_NAC_CONSUMER_DB_HPP
