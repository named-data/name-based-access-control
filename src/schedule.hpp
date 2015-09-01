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

#ifndef NDN_GEP_SECHEDULE_HPP
#define NDN_GEP_SECHEDULE_HPP

#include "common.hpp"
#include "repetitive-interval.hpp"

namespace ndn {
namespace gep {

/**
 * @brief Schedule is used to manage the time, which contains two sets of RepetitiveIntervals
 *
 * whiteIntervalList is used to define the time allowing member's access to data
 * blackIntervalList is used to define the time not allowing member's access to data
 */
class Schedule
{
public:
  Schedule();

  explicit
  Schedule(const Block& block);

public:
  template<encoding::Tag TAG>
  size_t
  wireEncode(EncodingImpl<TAG>& encoder) const;

  const Block&
  wireEncode() const;

  void
  wireDecode(const Block& wire);

  ///@brief Add an RepetitiveInterval @p repetitiveInterval into white list
  Schedule&
  addWhiteInterval(const RepetitiveInterval& repetitiveInterval);

  ///@brief Add the RepetitiveInterval into black list
  Schedule&
  addBlackInterval(const RepetitiveInterval& repetitiveInterval);

  /**
   * @brief Get the Interval that covers the @p ts
   *
   * Function iterates two repetitive interval sets and find out
   * the shortest interval that allows group member to have the access to the data
   * if there's no interval covering the @p ts, function will return false and
   * return a negative interval
   */
  std::tuple<bool, Interval>
  getCoveringInterval(const TimeStamp& ts) const;

private:
  std::set<RepetitiveInterval> m_whiteIntervalList;
  std::set<RepetitiveInterval> m_blackIntervalList;

  mutable Block m_wire;
};

} // namespace gep
} // namespace ndn

#endif // NDN_GROUP_ENCRYPT_SECHEDULE_HPP
