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

#ifndef NDN_GEP_PRODUCER_DB_HPP
#define NDN_GEP_PRODUCER_DB_HPP

#include "common.hpp"

namespace ndn {
namespace gep {

/**
 * @brief ProducerDB is a class to manage the database of data producer.
 * It contains one table that maps timeslots (to the nearest hour) to the
 * content key created for that timeslot.
 */
class ProducerDB
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
  explicit
  ProducerDB(const std::string& dbPath);

  ~ProducerDB();

public:
  /**
   * @brief Check if content key exists for the hour covering @p timeslot
   */
  bool
  hasContentKey(const time::system_clock::TimePoint& timeslot) const;

  /**
   * @brief Get content key for the hour covering @p timeslot
   * @throws Error if the key does not exist
   */
  Buffer
  getContentKey(const time::system_clock::TimePoint& timeslot) const;

  /**
   * @brief Add @p key as the content key for the hour covering @p timeslot
   * @throws Error if a key for the same hour already exists
   */
  void
  addContentKey(const time::system_clock::TimePoint& timeslot, const Buffer& key);

  /**
   * @brief Delete content key for the hour covering @p timeslot
   */
  void
  deleteContentKey(const time::system_clock::TimePoint& timeslot);

private:
  class Impl;
  unique_ptr<Impl> m_impl;
};

} // namespace gep
} // namespace ndn

#endif // NDN_GEP_PRODUCER_DB_HPP
