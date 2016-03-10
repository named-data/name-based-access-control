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

#include "repetitive-interval.hpp"
#include "tlv.hpp"

#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/util/concepts.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace ndn {
namespace gep {

static const TimeStamp DEFAULT_TIME = boost::posix_time::from_iso_string("14000101T000000");

BOOST_CONCEPT_ASSERT((WireEncodable<RepetitiveInterval>));
BOOST_CONCEPT_ASSERT((WireDecodable<RepetitiveInterval>));

RepetitiveInterval::RepetitiveInterval()
  : m_startDate(DEFAULT_TIME)
  , m_endDate(DEFAULT_TIME)
  , m_intervalStartHour(0)
  , m_intervalEndHour(24)
  , m_nRepeats(0)
  , m_unit(RepeatUnit::NONE)
{
}

RepetitiveInterval::RepetitiveInterval(const Block& block)
{
  wireDecode(block);
}

RepetitiveInterval::RepetitiveInterval(const TimeStamp& startDate,
                                       const TimeStamp& endDate,
                                       size_t intervalStartHour,
                                       size_t intervalEndHour,
                                       size_t nRepeats,
                                       RepeatUnit unit)
  : m_startDate(startDate)
  , m_endDate(endDate)
  , m_intervalStartHour(intervalStartHour)
  , m_intervalEndHour(intervalEndHour)
  , m_nRepeats(nRepeats)
  , m_unit(unit)
{
  BOOST_ASSERT(m_intervalStartHour < m_intervalEndHour);
  BOOST_ASSERT(m_startDate.date() <= m_endDate.date());
  BOOST_ASSERT(m_intervalEndHour <= 24);
  if (unit == RepeatUnit::NONE)
    BOOST_ASSERT(m_startDate.date() == m_endDate.date());
}

template<encoding::Tag TAG>
size_t
RepetitiveInterval::wireEncode(EncodingImpl<TAG>& encoder) const
{
  using namespace boost::posix_time;

  size_t totalLength = 0;

  // RepeatUnit
  totalLength += prependNonNegativeIntegerBlock(encoder, tlv::RepeatUnit,
                                                  static_cast<size_t>(m_unit));
  // NRepeat
  totalLength += prependNonNegativeIntegerBlock(encoder, tlv::NRepeats, m_nRepeats);
  // IntervalEndHour
  totalLength += prependNonNegativeIntegerBlock(encoder, tlv::IntervalEndHour, m_intervalEndHour);
  // IntervalStartHour
  totalLength += prependNonNegativeIntegerBlock(encoder, tlv::IntervalStartHour,
                                                m_intervalStartHour);
  // EndDate
  totalLength += prependStringBlock(encoder, tlv::EndDate, to_iso_string(m_endDate));
  // StartDate
  totalLength += prependStringBlock(encoder, tlv::StartDate, to_iso_string(m_startDate));

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::RepetitiveInterval);

  return totalLength;
}

const Block&
RepetitiveInterval::wireEncode() const
{
  if (m_wire.hasWire())
    return m_wire;

  EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  this->m_wire = buffer.block();
  return m_wire;
}

void
RepetitiveInterval::wireDecode(const Block& wire)
{
  using namespace boost::posix_time;

  if (wire.type() != tlv::RepetitiveInterval)
    BOOST_THROW_EXCEPTION(tlv::Error("Unexpected TLV type when decoding RepetitiveInterval"));

  m_wire = wire;
  m_wire.parse();

  if (m_wire.elements_size() != 6)
    BOOST_THROW_EXCEPTION(tlv::Error("RepetitiveInterval tlv does not have six sub-TLVs"));

  Block::element_const_iterator it = m_wire.elements_begin();
  // StartDate
  if (it->type() == tlv::StartDate) {
    m_startDate = ptime(from_iso_string(readString(*it)));
    it++;
  }
  else
    BOOST_THROW_EXCEPTION(tlv::Error("First element must be StartDate"));

  // EndDate
  if (it->type() == tlv::EndDate) {
    m_endDate = ptime(from_iso_string(readString(*it)));
    it++;
  }
  else
    BOOST_THROW_EXCEPTION(tlv::Error("Second element must be EndDate"));

  // IntervalStartHour
  if (it->type() == tlv::IntervalStartHour) {
    m_intervalStartHour = readNonNegativeInteger(*it);
    it++;
  }
  else
    BOOST_THROW_EXCEPTION(tlv::Error("Third element must be IntervalStartHour"));

  // IntervalEndHour
  if (it->type() == tlv::IntervalEndHour) {
    m_intervalEndHour = readNonNegativeInteger(*it);
    it++;
  }
  else
    BOOST_THROW_EXCEPTION(tlv::Error("Fourth element must be IntervalEndHour"));

  // NRepeats
  if (it->type() == tlv::NRepeats) {
    m_nRepeats = readNonNegativeInteger(*it);
    it++;
  }
  else
    BOOST_THROW_EXCEPTION(tlv::Error("Fifth element must be NRepeats"));

  // RepeatUnit
  if (it->type() == tlv::RepeatUnit) {
    m_unit = static_cast<RepeatUnit>(readNonNegativeInteger(*it));
    it++;
  }
  else
    BOOST_THROW_EXCEPTION(tlv::Error("The last element must be RepeatUnit"));
}

std::tuple<bool, Interval>
RepetitiveInterval::getInterval(const TimeStamp& tp) const
{
  TimeStamp startTime;
  TimeStamp endTime;
  bool isPositive;

  if (!this->hasIntervalOnDate(tp)) {
    // there is no interval on the date of tp
    startTime = TimeStamp(tp.date(), boost::posix_time::hours(0));
    endTime = TimeStamp(tp.date(), boost::posix_time::hours(24));
    isPositive = false;
  }
  else {
    // there is an interval on the date of tp
    startTime = TimeStamp(tp.date(), boost::posix_time::hours(m_intervalStartHour));
    endTime = TimeStamp(tp.date(), boost::posix_time::hours(m_intervalEndHour));

    // check if in the time duration
    if (tp < startTime) {
      endTime = startTime;
      startTime = TimeStamp(tp.date(), boost::posix_time::hours(0));
      isPositive = false;
    }
    else if (tp > endTime) {
      startTime = endTime;
      endTime = TimeStamp(tp.date(), boost::posix_time::hours(24));
      isPositive = false;
    }
    else {
      isPositive = true;
    }
  }
  return std::make_tuple(isPositive, Interval(startTime, endTime));
}

bool
RepetitiveInterval::hasIntervalOnDate(const TimeStamp& tp) const
{
  namespace bg = boost::gregorian;

  // check if in the bound of the interval
  if (tp.date() < m_startDate.date() || tp.date() > m_endDate.date()) {
    return false;
  }

  if (m_unit == RepeatUnit::NONE) {
    return true;
  }

  // check if in the matching date
  bg::date dateA = tp.date();
  bg::date dateB = m_startDate.date();
  if (m_unit == RepeatUnit::DAY) {
    bg::date_duration duration = dateA - dateB;
    if (static_cast<size_t>(duration.days()) % m_nRepeats == 0)
      return true;
  }
  else if (m_unit == RepeatUnit::MONTH && dateA.day() == dateB.day()) {
    size_t yearDiff = static_cast<size_t>(dateA.year() - dateB.year());
    size_t monthDiff = 12 * yearDiff + dateA.month().as_number() - dateB.month().as_number();
    if (monthDiff % m_nRepeats == 0)
      return true;
  }
  else if (m_unit == RepeatUnit::YEAR &&
           dateA.day().as_number() == dateB.day().as_number() &&
           dateA.month().as_number() == dateB.month().as_number()) {
    size_t diff = static_cast<size_t>(dateA.year() - dateB.year());
    if (diff % m_nRepeats == 0)
      return true;
  }

  return false;
}

bool
RepetitiveInterval::operator<(const RepetitiveInterval& interval) const
{
  if (m_startDate < interval.getStartDate())
    return true;
  else if (m_startDate > interval.getStartDate())
    return false;

  if (m_endDate < interval.getEndDate())
    return true;
  else if (m_endDate > interval.getEndDate())
    return false;

  if (m_intervalStartHour < interval.getIntervalStartHour())
    return true;
  else if (m_intervalStartHour > interval.getIntervalStartHour())
    return false;

  if (m_intervalEndHour < interval.getIntervalEndHour())
    return true;
  else if (m_intervalEndHour > interval.getIntervalEndHour())
    return false;

  if (m_nRepeats < interval.getNRepeats())
    return true;
  else if (m_nRepeats > interval.getNRepeats())
    return false;

  return (static_cast<size_t>(m_unit) < static_cast<size_t>(interval.getRepeatUnit()));
}

} // namespace gep
} // namespace ndn
