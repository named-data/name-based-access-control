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

#ifndef NDN_NAC_INTERVAL_HPP
#define NDN_NAC_INTERVAL_HPP

#include "common.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>

namespace ndn {
namespace nac {

typedef boost::posix_time::ptime TimeStamp;

///@brief Interval define a time duration which contains a start timestamp and an end timestamp
class Interval
{
public:
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

public:
  /**
   * @brief Construction to create an object
   *
   * @param isValid If isValid is true, the created interval is an empty interval
   */
  explicit
  Interval(bool isValid = false);

  Interval(const TimeStamp& startTime, const TimeStamp& endTime);

  /**
   * @brief Check if the timestamp tp is in the interval
   * @pre this->isValid() == true
   *
   * @param tp A timestamp
   */
  bool
  covers(const TimeStamp& tp) const;

  /**
   * @brief Get the intersection interval of two intervals
   * @pre this->isValid() == true && interval.isValid() == true
   *
   * Two intervals should all be valid but they can be empty
   */
  Interval&
  operator&&(const Interval& interval);

  /**
   * @brief Get the union set interval of two intervals
   * @pre this->isValid() == true && interval.isValid() == true
   *
   * Two intervals should all be valid but they can be empty
   */
  Interval&
  operator||(const Interval& interval);

  const TimeStamp&
  getStartTime() const
  {
    BOOST_ASSERT(isValid());
    return m_startTime;
  }

  const TimeStamp&
  getEndTime() const
  {
    BOOST_ASSERT(isValid());
    return m_endTime;
  }

  bool
  isValid() const
  {
    return m_isValid;
  }

  bool
  isEmpty() const
  {
    BOOST_ASSERT(isValid());
    return m_startTime == m_endTime;
  }

private:
  TimeStamp m_startTime;
  TimeStamp m_endTime;

  bool m_isValid;
};

} // namespace nac
} // namespace ndn

#endif // NDN_NAC_INTERVAL_HPP
