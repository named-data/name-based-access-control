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

#ifndef NDN_NAC_REPETITIVE_INTERVAL_HPP
#define NDN_NAC_REPETITIVE_INTERVAL_HPP

#include "common.hpp"
#include "interval.hpp"

namespace ndn {
namespace nac {

///@brief An advanced interval which can have a repeat pattern and repeat unit
class RepetitiveInterval
{
public:
  enum class
  RepeatUnit {
    NONE = 0,
    DAY = 1,
    MONTH = 2,
    YEAR = 3
  };

public:
  RepetitiveInterval();

  explicit
  RepetitiveInterval(const Block& block);

  /**
   * @brief Construction to create an object
   * @pre @p startDate <= @p endDate
   * @pre @p intervalStartHour and @p intervalEndHour can be [0, 24]
   * @pre @p intervalStartHour < @p intervalEndHour
   * @pre when @p unit = NONE, then @p startDate == @p endDate
   */
  RepetitiveInterval(const TimeStamp& startDate,
                     const TimeStamp& endDate,
                     size_t intervalStartHour,
                     size_t intervalEndHour,
                     size_t nRepeats = 0,
                     RepeatUnit unit = RepeatUnit::NONE);

  template<encoding::Tag TAG>
  size_t
  wireEncode(EncodingImpl<TAG>& encoder) const;

  const Block&
  wireEncode() const;

  void
  wireDecode(const Block& wire);

  /**
   * @brief Get get an interval that @p tp falls in
   *
   * @param tp A timestamp
   *
   * @return bool If the repetitive interval covers the @p tp, return true, otherwise false
   * @return Interval Return the interval which @p tp falls in
   */
  std::tuple<bool, Interval>
  getInterval(const TimeStamp& tp) const;

  /**
   * @brief To store in std::set, class have to implement operator <
   *
   * @param interval Interval which will be compared with
   */
  bool
  operator<(const RepetitiveInterval& interval) const;

  const TimeStamp&
  getStartDate() const
  {
    return m_startDate;
  }

  const TimeStamp&
  getEndDate() const
  {
    return m_endDate;
  }

  size_t
  getIntervalStartHour() const
  {
    return m_intervalStartHour;
  }

  size_t
  getIntervalEndHour() const
  {
    return m_intervalEndHour;
  }

  size_t
  getNRepeats() const
  {
    return m_nRepeats;
  }

  RepeatUnit
  getRepeatUnit() const
  {
    return m_unit;
  }

private:
  ///@brief Check if there is any interval in the date of timestamp
  bool
  hasIntervalOnDate(const TimeStamp& tp) const;

  TimeStamp m_startDate;
  TimeStamp m_endDate;
  size_t m_intervalStartHour;
  size_t m_intervalEndHour;
  size_t m_nRepeats;
  RepeatUnit m_unit;

  mutable Block m_wire;
};

} // namespace nac
} // namespace ndn

#endif // NDN_NAC_REPETITIVE_INTERVAL_HPP
