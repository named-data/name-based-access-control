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

#ifndef NDN_GEP_INTERVAL_HPP
#define NDN_GEP_INTERVAL_HPP

#include "common.hpp"

#include <boost/date_time/posix_time/posix_time.hpp>

namespace ndn {
namespace gep {

typedef boost::posix_time::ptime TimeStamp;

///@brief Interval define a time duration which contains a start timestamp and an end timestamp
class Interval
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
  /**
   * @brief Construction to create an object
   *
   * @parameter isValid If isValid is true, the created interval is an empty interval
   */
  explicit
  Interval(bool isValid = false);

  Interval(const TimeStamp& startTime,
           const TimeStamp& endTime);

  /**
   * @brief Check if the timestamp tp is in the interval
   * @pre this->isValid() == true
   *
   * @parameter tp A timestamp
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
  operator &&(const Interval& interval);

  /**
   * @brief Get the union set interval of two intervals
   * @pre this->isValid() == true && interval.isValid() == true
   *
   * Two intervals should all be valid but they can be empty
   */
  Interval&
  operator ||(const Interval& interval);

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

} // namespace gep
} // namespace ndn

#endif // NDN_GEP_INTERVAL_HPP
