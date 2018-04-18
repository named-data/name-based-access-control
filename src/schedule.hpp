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

#ifndef NDN_NAC_SCHEDULE_HPP
#define NDN_NAC_SCHEDULE_HPP

#include "common.hpp"
#include "repetitive-interval.hpp"

namespace ndn {
namespace nac {

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

} // namespace nac
} // namespace ndn

#endif // NDN_NAC_SCHEDULE_HPP
