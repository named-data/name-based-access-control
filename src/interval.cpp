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

#include "interval.hpp"

namespace ndn {
namespace gep {

static const TimeStamp DEFAULT_TIME = boost::posix_time::from_iso_string("14000101T000000");

Interval::Interval(bool isValid)
  : m_startTime(DEFAULT_TIME)
  , m_endTime(DEFAULT_TIME)
  , m_isValid(isValid)
{
}

Interval::Interval(const TimeStamp& startTime,
                   const TimeStamp& endTime)
  : m_startTime(startTime)
  , m_endTime(endTime)
  , m_isValid(true)
{
  BOOST_ASSERT(startTime < endTime);
}

bool
Interval::covers(const TimeStamp& tp) const
{
  BOOST_ASSERT(isValid());

  if (isEmpty())
    return false;
  return (m_startTime <= tp && tp < m_endTime);
}

Interval&
Interval::operator &&(const Interval& interval)
{
  BOOST_ASSERT(isValid() && interval.isValid());

  // if one is empty, result is empty
  if (isEmpty() || interval.isEmpty()) {
    m_startTime = m_endTime;
    return *this;
  }
  // two intervals do not have intersection
  if (m_startTime >= interval.getEndTime() || m_endTime <= interval.getStartTime()) {
    m_startTime = m_endTime;
    return *this;
  }

  // get the start time
  if (m_startTime <= interval.getStartTime())
    m_startTime = interval.getStartTime();

  // get the end time
  if (m_endTime > interval.getEndTime())
    m_endTime = interval.getEndTime();

  return *this;
}

Interval&
Interval::operator ||(const Interval& interval)
{
  BOOST_ASSERT(this->isValid() && interval.isValid());

  if (isEmpty()) {
    // left interval is empty, return left one
    m_startTime = interval.getStartTime();
    m_endTime = interval.getEndTime();
    return *this;
  }
  if (interval.isEmpty()) {
    // right interval is empty, return right one
    return *this;
  }
  if (m_startTime >= interval.getEndTime() || m_endTime <= interval.getStartTime()) {
    // two intervals do not have intersection
    BOOST_THROW_EXCEPTION(Error("cannot generate a union interval when there's no intersection"));
  }

  // get the start time
  if (m_startTime > interval.getStartTime())
    m_startTime = interval.getStartTime();

  // get the end time
  if (m_endTime <= interval.getEndTime())
    m_endTime = interval.getEndTime();

  return *this;
}

} // namespace gep
} // namespace ndn
