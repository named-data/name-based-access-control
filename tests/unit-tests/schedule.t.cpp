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

#include "schedule.hpp"
#include "boost-test.hpp"

namespace ndn {
namespace gep {
namespace tests {

using namespace boost::posix_time;

BOOST_AUTO_TEST_SUITE(TestSchedule)

BOOST_AUTO_TEST_CASE(CalIntervalWithBlackAndWhite)
{
  Schedule schedule;
  RepetitiveInterval interval1(from_iso_string("20150825T000000"),
                               from_iso_string("20150827T000000"),
                               5, 10, 2, RepetitiveInterval::RepeatUnit::DAY);
  RepetitiveInterval interval2(from_iso_string("20150825T000000"),
                               from_iso_string("20150827T000000"),
                               6, 8, 1, RepetitiveInterval::RepeatUnit::DAY);
  RepetitiveInterval interval3(from_iso_string("20150827T000000"),
                               from_iso_string("20150827T000000"),
                               7, 8);
  RepetitiveInterval interval4(from_iso_string("20150825T000000"),
                               from_iso_string("20150825T000000"),
                               4, 7);

  schedule.addWhiteInterval(interval1);
  schedule.addWhiteInterval(interval2);
  schedule.addWhiteInterval(interval4);
  schedule.addBlackInterval(interval3);

  Interval resultInterval;
  bool isPositive;

  // tp1 --> positive 8.25 4-10
  TimeStamp tp1 = from_iso_string("20150825T063000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp1);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150825T040000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150825T100000");

  // tp2 --> positive 8.26 6-8
  TimeStamp tp2 = from_iso_string("20150826T073000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp2);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150826T060000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150826T080000");

  // tp3 --> positive 8.27 5-7
  TimeStamp tp3 = from_iso_string("20150827T053000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp3);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150827T050000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150827T070000");

  // tp4 --> positive 8.27 5-7
  TimeStamp tp4 = from_iso_string("20150827T063000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp4);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150827T050000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150827T070000");

  // tp5 --> negative 8.27 7-8
  TimeStamp tp5 = from_iso_string("20150827T073000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp5);
  BOOST_CHECK_EQUAL(isPositive, false);
  BOOST_CHECK_EQUAL(resultInterval.isEmpty(), false);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150827T070000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150827T080000");

  // tp6 --> negative 8.25 10-24
  TimeStamp tp6 = from_iso_string("20150825T113000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp6);
  BOOST_CHECK_EQUAL(isPositive, false);
  BOOST_CHECK_EQUAL(resultInterval.isEmpty(), false);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150825T100000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150826T000000");
}

BOOST_AUTO_TEST_CASE(CalIntervalWithoutBlack)
{
  Schedule schedule;
  RepetitiveInterval interval1(from_iso_string("20150825T000000"),
                               from_iso_string("20150827T000000"),
                               5, 10, 2, RepetitiveInterval::RepeatUnit::DAY);
  RepetitiveInterval interval2(from_iso_string("20150825T000000"),
                               from_iso_string("20150827T000000"),
                               6, 8, 1, RepetitiveInterval::RepeatUnit::DAY);
  RepetitiveInterval interval3(from_iso_string("20150825T000000"),
                               from_iso_string("20150825T000000"),
                               4, 7);

  schedule.addWhiteInterval(interval1);
  schedule.addWhiteInterval(interval2);
  schedule.addWhiteInterval(interval3);

  Interval resultInterval;
  bool isPositive;

  // tp1 --> positive 8.25 4-10
  TimeStamp tp1 = from_iso_string("20150825T063000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp1);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150825T040000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150825T100000");

  // tp2 --> positive 8.26 6-8
  TimeStamp tp2 = from_iso_string("20150826T073000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp2);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150826T060000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150826T080000");

  // tp3 --> positive 8.27 5-10
  TimeStamp tp3 = from_iso_string("20150827T053000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp3);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150827T050000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150827T100000");

  // tp4 --> negative 8.25 10-24
  TimeStamp tp4 = from_iso_string("20150825T113000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp4);
  BOOST_CHECK_EQUAL(isPositive, false);
  BOOST_CHECK_EQUAL(resultInterval.isEmpty(), false);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150825T100000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150826T000000");

  // tp5 --> negative 8.25 0-4
  TimeStamp tp5 = from_iso_string("20150825T013000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp5);
  BOOST_CHECK_EQUAL(isPositive, false);
  BOOST_CHECK_EQUAL(resultInterval.isEmpty(), false);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150825T000000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150825T040000");
}

BOOST_AUTO_TEST_CASE(CalIntervalWithoutWhite)
{
  Schedule schedule;
  RepetitiveInterval interval1(from_iso_string("20150825T000000"),
                               from_iso_string("20150827T000000"),
                               5, 10, 2, RepetitiveInterval::RepeatUnit::DAY);
  RepetitiveInterval interval2(from_iso_string("20150825T000000"),
                               from_iso_string("20150827T000000"),
                               6, 8, 1, RepetitiveInterval::RepeatUnit::DAY);

  schedule.addBlackInterval(interval1);
  schedule.addBlackInterval(interval2);

  Interval resultInterval;
  bool isPositive;

  // tp1 --> negative 8.25 4-10
  TimeStamp tp1 = from_iso_string("20150825T063000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp1);
  BOOST_CHECK_EQUAL(isPositive, false);
  BOOST_CHECK_EQUAL(resultInterval.isEmpty(), false);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150825T050000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150825T100000");

  // tp2 --> negative 8.25 0-4
  TimeStamp tp2 = from_iso_string("20150825T013000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp2);
  BOOST_CHECK_EQUAL(isPositive, false);
  BOOST_CHECK_EQUAL(resultInterval.isEmpty(), false);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150825T000000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150826T000000");
}

const uint8_t SCHEDULE[] = {
  0x8f, 0xc4,// Schedule
  0x8d, 0x90,// WhiteIntervalList
  /////
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x04,
    0x89, 0x01,
      0x07,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00,
  /////
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x05,
    0x89, 0x01,
      0x0a,
    0x8a, 0x01,
      0x02,
    0x8b, 0x01,
      0x01,
  /////
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x06,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x01,
    0x8b, 0x01,
      0x01,
  /////
  0x8e, 0x30, // BlackIntervalList
  /////
  0x8c, 0x2e, // RepetitiveInterval
     0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x07,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00
};

BOOST_AUTO_TEST_CASE(EncodeAndDecode)
{
  Schedule schedule;

  RepetitiveInterval interval1(from_iso_string("20150825T000000"),
                               from_iso_string("20150828T000000"),
                               5, 10, 2, RepetitiveInterval::RepeatUnit::DAY);
  RepetitiveInterval interval2(from_iso_string("20150825T000000"),
                               from_iso_string("20150828T000000"),
                               6, 8, 1, RepetitiveInterval::RepeatUnit::DAY);
  RepetitiveInterval interval3(from_iso_string("20150827T000000"),
                               from_iso_string("20150827T000000"),
                               7, 8);
  RepetitiveInterval interval4(from_iso_string("20150825T000000"),
                               from_iso_string("20150825T000000"),
                               4, 7);

  schedule.addWhiteInterval(interval1);
  schedule.addWhiteInterval(interval2);
  schedule.addWhiteInterval(interval4);
  schedule.addBlackInterval(interval3);

  Block block = schedule.wireEncode();
  Block block2(SCHEDULE, sizeof(SCHEDULE));
  BOOST_CHECK(block == block2);

  Schedule schedule2(block);
  Interval resultInterval;
  bool isPositive;

  // tp1 --> positive 8.25 4-10
  TimeStamp tp1 = from_iso_string("20150825T063000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp1);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150825T040000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150825T100000");

  // tp2 --> positive 8.26 6-8
  TimeStamp tp2 = from_iso_string("20150826T073000");
  std::tie(isPositive, resultInterval) = schedule.getCoveringInterval(tp2);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150826T060000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150826T080000");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace gep
} // namespace ndn
