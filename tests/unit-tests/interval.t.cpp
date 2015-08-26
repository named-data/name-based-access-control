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
#include "boost-test.hpp"

namespace ndn {
namespace gep {
namespace tests {

using namespace boost::posix_time;

BOOST_AUTO_TEST_SUITE(TestInterval)

BOOST_AUTO_TEST_CASE(Construction)
{
  // construct with the right parameters
  Interval interval1(from_iso_string("20150825T120000"),
                     from_iso_string("20150825T160000"));
  BOOST_CHECK_EQUAL(to_iso_string(interval1.getStartTime()), "20150825T120000");
  BOOST_CHECK_EQUAL(to_iso_string(interval1.getEndTime()), "20150825T160000");
  BOOST_CHECK_EQUAL(interval1.isValid(), true);

  // construct with the invalid interval
  Interval interval2;
  BOOST_CHECK_EQUAL(interval2.isValid(), false);

  // construct with the empty interval
  Interval interval3(true);
  BOOST_CHECK_EQUAL(interval3.isValid(), true);
  BOOST_CHECK_EQUAL(interval3.isEmpty(), true);
}

BOOST_AUTO_TEST_CASE(CoverTimePoint)
{
  Interval interval(from_iso_string("20150825T120000"),
                    from_iso_string("20150825T160000"));

  TimeStamp tp1 = from_iso_string("20150825T120000");
  TimeStamp tp2 = from_iso_string("20150825T130000");
  TimeStamp tp3 = from_iso_string("20150825T170000");
  TimeStamp tp4 = from_iso_string("20150825T110000");

  BOOST_CHECK_EQUAL(interval.covers(tp1), true);
  BOOST_CHECK_EQUAL(interval.covers(tp2), true);
  BOOST_CHECK_EQUAL(interval.covers(tp3), false);
  BOOST_CHECK_EQUAL(interval.covers(tp4), false);
}

BOOST_AUTO_TEST_CASE(IntersectionAndUnion)
{
  Interval interval1(from_iso_string("20150825T030000"),
                     from_iso_string("20150825T050000"));
  // no intersection
  Interval interval2(from_iso_string("20150825T050000"),
                     from_iso_string("20150825T070000"));
  // no intersection
  Interval interval3(from_iso_string("20150825T060000"),
                     from_iso_string("20150825T070000"));
  // there's an intersection
  Interval interval4(from_iso_string("20150825T010000"),
                     from_iso_string("20150825T040000"));
  // right in the interval1, there's an intersection
  Interval interval5(from_iso_string("20150825T030000"),
                     from_iso_string("20150825T040000"));
  // wrap the interval1, there's an intersection
  Interval interval6(from_iso_string("20150825T010000"),
                     from_iso_string("20150825T050000"));
  // empty interval
  Interval interval7(true);

  Interval tempInterval = interval1;
  tempInterval && interval2;
  BOOST_CHECK_EQUAL(tempInterval.isEmpty(), true);

  tempInterval = interval1;
  BOOST_CHECK_THROW(tempInterval || interval2, Interval::Error);

  tempInterval = interval1;
  tempInterval && interval3;
  BOOST_CHECK_EQUAL(tempInterval.isEmpty(), true);

  tempInterval = interval1;
  BOOST_CHECK_THROW(tempInterval || interval3, Interval::Error);

  tempInterval = interval1;
  tempInterval && interval4;
  BOOST_CHECK_EQUAL(tempInterval.isEmpty(), false);
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getStartTime()), "20150825T030000");
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getEndTime()), "20150825T040000");

  tempInterval = interval1;
  tempInterval || interval4;
  BOOST_CHECK_EQUAL(tempInterval.isEmpty(), false);
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getStartTime()), "20150825T010000");
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getEndTime()), "20150825T050000");

  tempInterval = interval1;
  tempInterval && interval5;
  BOOST_CHECK_EQUAL(tempInterval.isEmpty(), false);
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getStartTime()), "20150825T030000");
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getEndTime()), "20150825T040000");

  tempInterval = interval1;
  tempInterval || interval5;
  BOOST_CHECK_EQUAL(tempInterval.isEmpty(), false);
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getStartTime()), "20150825T030000");
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getEndTime()), "20150825T050000");

  tempInterval = interval1;
  tempInterval && interval6;
  BOOST_CHECK_EQUAL(tempInterval.isEmpty(), false);
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getStartTime()), "20150825T030000");
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getEndTime()), "20150825T050000");

  tempInterval = interval1;
  tempInterval || interval6;
  BOOST_CHECK_EQUAL(tempInterval.isEmpty(), false);
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getStartTime()), "20150825T010000");
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getEndTime()), "20150825T050000");

  tempInterval = interval1;
  tempInterval && interval7;
  BOOST_CHECK_EQUAL(tempInterval.isEmpty(), true);

  tempInterval = interval1;
  tempInterval || interval7;
  BOOST_CHECK_EQUAL(tempInterval.isEmpty(), false);
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getStartTime()), "20150825T030000");
  BOOST_CHECK_EQUAL(to_iso_string(tempInterval.getEndTime()), "20150825T050000");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace gep
} // namespace ndn
