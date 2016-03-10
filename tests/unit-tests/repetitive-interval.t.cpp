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
#include "boost-test.hpp"

namespace ndn {
namespace gep {
namespace tests {

using namespace boost::posix_time;

BOOST_AUTO_TEST_SUITE(TestRepetitiveInterval)

BOOST_AUTO_TEST_CASE(Construction)
{
  RepetitiveInterval repetitiveInterval1(from_iso_string("20150825T000000"),
                                         from_iso_string("20150825T000000"),
                                         5, 10);

  BOOST_CHECK_EQUAL(to_iso_string(repetitiveInterval1.getStartDate()), "20150825T000000");
  BOOST_CHECK_EQUAL(to_iso_string(repetitiveInterval1.getEndDate()), "20150825T000000");
  BOOST_CHECK_EQUAL(repetitiveInterval1.getIntervalStartHour(), 5);
  BOOST_CHECK_EQUAL(repetitiveInterval1.getIntervalEndHour(), 10);

  RepetitiveInterval repetitiveInterval2(from_iso_string("20150825T000000"),
                                         from_iso_string("20150827T000000"),
                                         5, 10, 1, RepetitiveInterval::RepeatUnit::DAY);

  BOOST_CHECK_EQUAL(repetitiveInterval2.getNRepeats(), 1);
  BOOST_CHECK(repetitiveInterval2.getRepeatUnit() == RepetitiveInterval::RepeatUnit::DAY);

  RepetitiveInterval repetitiveInterval3(from_iso_string("20150825T000000"),
                                         from_iso_string("20151227T000000"),
                                         5, 10, 2, RepetitiveInterval::RepeatUnit::MONTH);

  BOOST_CHECK_EQUAL(repetitiveInterval3.getNRepeats(), 2);
  BOOST_CHECK(repetitiveInterval3.getRepeatUnit() == RepetitiveInterval::RepeatUnit::MONTH);

  RepetitiveInterval repetitiveInterval4(from_iso_string("20150825T000000"),
                                         from_iso_string("20301227T000000"),
                                         5, 10, 5, RepetitiveInterval::RepeatUnit::YEAR);

  BOOST_CHECK_EQUAL(repetitiveInterval4.getNRepeats(), 5);
  BOOST_CHECK(repetitiveInterval4.getRepeatUnit() == RepetitiveInterval::RepeatUnit::YEAR);

  RepetitiveInterval repetitiveInterval5;

  BOOST_CHECK_EQUAL(repetitiveInterval5.getNRepeats(), 0);
  BOOST_CHECK(repetitiveInterval5.getRepeatUnit() == RepetitiveInterval::RepeatUnit::NONE);
}

BOOST_AUTO_TEST_CASE(CheckCoverTimePoint)
{
  ///////////////////////////////////////////// with the repeat unit DAY

  RepetitiveInterval repetitiveInterval1(from_iso_string("20150825T000000"),
                                         from_iso_string("20150925T000000"),
                                         5, 10, 2, RepetitiveInterval::RepeatUnit::DAY);
  Interval resultInterval;
  bool isPositive = false;

  TimeStamp tp1 = from_iso_string("20150825T050000");

  std::tie(isPositive,resultInterval) = repetitiveInterval1.getInterval(tp1);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150825T050000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150825T100000");

  TimeStamp tp2 = from_iso_string("20150902T060000");

  std::tie(isPositive,resultInterval) = repetitiveInterval1.getInterval(tp2);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150902T050000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150902T100000");

  TimeStamp tp3 = from_iso_string("20150929T040000");

  BOOST_CHECK(std::get<0>(repetitiveInterval1.getInterval(tp3)) == false);

  ///////////////////////////////////////////// with the repeat unit MONTH

  RepetitiveInterval repetitiveInterval2(from_iso_string("20150825T000000"),
                                         from_iso_string("20160825T000000"),
                                         5, 10, 2, RepetitiveInterval::RepeatUnit::MONTH);

  TimeStamp tp4 = from_iso_string("20150825T050000");

  std::tie(isPositive,resultInterval) = repetitiveInterval2.getInterval(tp4);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150825T050000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150825T100000");

  TimeStamp tp5 = from_iso_string("20151025T060000");

  std::tie(isPositive,resultInterval) = repetitiveInterval2.getInterval(tp5);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20151025T050000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()),  "20151025T100000");

  TimeStamp tp6 = from_iso_string("20151226T050000");

  BOOST_CHECK(std::get<0>(repetitiveInterval2.getInterval(tp6)) == false);

  TimeStamp tp7 = from_iso_string("20151225T040000");

  BOOST_CHECK(std::get<0>(repetitiveInterval2.getInterval(tp7)) == false);

  ///////////////////////////////////////////// with the repeat unit YEAR

  RepetitiveInterval repetitiveInterval3(from_iso_string("20150825T000000"),
                                         from_iso_string("20300825T000000"),
                                         5, 10, 3, RepetitiveInterval::RepeatUnit::YEAR);

  TimeStamp tp8 = from_iso_string("20150825T050000");

  std::tie(isPositive,resultInterval) = repetitiveInterval3.getInterval(tp8);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20150825T050000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20150825T100000");

  TimeStamp tp9 = from_iso_string("20180825T060000");

  std::tie(isPositive,resultInterval) = repetitiveInterval3.getInterval(tp9);
  BOOST_CHECK_EQUAL(isPositive, true);
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getStartTime()), "20180825T050000");
  BOOST_CHECK_EQUAL(to_iso_string(resultInterval.getEndTime()), "20180825T100000");

  TimeStamp tp10 = from_iso_string("20180826T050000");
  BOOST_CHECK(std::get<0>(repetitiveInterval3.getInterval(tp10)) == false);

  TimeStamp tp11 = from_iso_string("20210825T040000");
  BOOST_CHECK(std::get<0>(repetitiveInterval3.getInterval(tp11)) == false);

  TimeStamp tp12 = from_iso_string("20300825T040000");
  BOOST_CHECK(std::get<0>(repetitiveInterval3.getInterval(tp12)) == false);
}

const uint8_t REPETITIVE_INTERVAL[] = {
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x39, 0x32, 0x31, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x05,
    0x89, 0x01,
      0x0a,
    0x8a, 0x01,
      0x04,
    0x8b, 0x01,
      0x01
};

BOOST_AUTO_TEST_CASE(EncodeAndDecode)
{
  RepetitiveInterval repetitiveInterval1(from_iso_string("20150825T000000"),
                                         from_iso_string("20150921T000000"),
                                         5, 10, 4, RepetitiveInterval::RepeatUnit::DAY);

  Block block1 = repetitiveInterval1.wireEncode();
  Block block2(REPETITIVE_INTERVAL, sizeof(REPETITIVE_INTERVAL));

  BOOST_CHECK(block1 == block2);

  RepetitiveInterval RepetitiveInterval2(block1);

  BOOST_CHECK_EQUAL(to_iso_string(RepetitiveInterval2.getStartDate()), "20150825T000000");
  BOOST_CHECK_EQUAL(to_iso_string(RepetitiveInterval2.getEndDate()), "20150921T000000");
  BOOST_CHECK_EQUAL(RepetitiveInterval2.getIntervalStartHour(), 5);
  BOOST_CHECK_EQUAL(RepetitiveInterval2.getIntervalEndHour(), 10);
  BOOST_CHECK_EQUAL(RepetitiveInterval2.getNRepeats(), 4);
  BOOST_CHECK(RepetitiveInterval2.getRepeatUnit() == RepetitiveInterval::RepeatUnit::DAY);

  RepetitiveInterval repetitiveInterval3(block2);

  BOOST_CHECK_EQUAL(to_iso_string(repetitiveInterval3.getStartDate()), "20150825T000000");
  BOOST_CHECK_EQUAL(to_iso_string(repetitiveInterval3.getEndDate()), "20150921T000000");
  BOOST_CHECK_EQUAL(repetitiveInterval3.getIntervalStartHour(), 5);
  BOOST_CHECK_EQUAL(repetitiveInterval3.getIntervalEndHour(), 10);
  BOOST_CHECK_EQUAL(repetitiveInterval3.getNRepeats(), 4);
  BOOST_CHECK(repetitiveInterval3.getRepeatUnit() == RepetitiveInterval::RepeatUnit::DAY);
}

static bool
check(const RepetitiveInterval& small, const RepetitiveInterval& big)
{
  return  (small < big && !(big < small));
}

BOOST_AUTO_TEST_CASE(Comparison)
{
  BOOST_CHECK(check(RepetitiveInterval(from_iso_string("20150825T000000"),
                                       from_iso_string("20150828T000000"),
                                       5, 10, 2, RepetitiveInterval::RepeatUnit::DAY),
                    RepetitiveInterval(from_iso_string("20150826T000000"),
                                       from_iso_string("20150828T000000"),
                                       5, 10, 2, RepetitiveInterval::RepeatUnit::DAY)));

  BOOST_CHECK(check(RepetitiveInterval(from_iso_string("20150825T000000"),
                                       from_iso_string("20150828T000000"),
                                       5, 10, 2, RepetitiveInterval::RepeatUnit::DAY),
                    RepetitiveInterval(from_iso_string("20150825T000000"),
                                       from_iso_string("20150828T000000"),
                                       6, 10, 2, RepetitiveInterval::RepeatUnit::DAY)));

  BOOST_CHECK(check(RepetitiveInterval(from_iso_string("20150825T000000"),
                                       from_iso_string("20150828T000000"),
                                       5, 10, 2, RepetitiveInterval::RepeatUnit::DAY),
                    RepetitiveInterval(from_iso_string("20150825T000000"),
                                       from_iso_string("20150828T000000"),
                                       5, 11, 2, RepetitiveInterval::RepeatUnit::DAY)));

  BOOST_CHECK(check(RepetitiveInterval(from_iso_string("20150825T000000"),
                                       from_iso_string("20150828T000000"),
                                       5, 10, 2, RepetitiveInterval::RepeatUnit::DAY),
                    RepetitiveInterval(from_iso_string("20150825T000000"),
                                       from_iso_string("20150828T000000"),
                                       5, 10, 3, RepetitiveInterval::RepeatUnit::DAY)));

  BOOST_CHECK(check(RepetitiveInterval(from_iso_string("20150825T000000"),
                                       from_iso_string("20150828T000000"),
                                       5, 10, 2, RepetitiveInterval::RepeatUnit::DAY),
                    RepetitiveInterval(from_iso_string("20150825T000000"),
                                       from_iso_string("20150828T000000"),
                                       5, 10, 2, RepetitiveInterval::RepeatUnit::MONTH)));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace gep
} // namespace ndn
