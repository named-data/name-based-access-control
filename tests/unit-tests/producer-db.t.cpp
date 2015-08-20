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
 * @author Prashanth Swaminathan <prashanthsw@gmail.com>
 */

#include "producer-db.hpp"
#include "algo/aes.hpp"
#include "boost-test.hpp"

#include <boost/filesystem.hpp>

namespace ndn {
namespace gep {
namespace tests {

using time::system_clock;

class ProducerDBFixture
{
public:
  ProducerDBFixture()
    : tmpPath(boost::filesystem::path(TMP_TESTS_PATH))
  {
    boost::filesystem::create_directories(tmpPath);
  }

  ~ProducerDBFixture()
  {
    boost::filesystem::remove_all(tmpPath);
  }

public:
  boost::filesystem::path tmpPath;
};

BOOST_FIXTURE_TEST_SUITE(TestProducerDB, ProducerDBFixture)

BOOST_AUTO_TEST_CASE(DatabaseFunctions)
{
  // construction
  std::string dbDir = tmpPath.c_str();
  dbDir += "/test.db";
  ProducerDB db(dbDir);

  // create member
  RandomNumberGenerator rng;
  AesKeyParams params(128);
  Buffer keyBuf1 = algo::Aes::generateKey(rng, params).getKeyBits();
  Buffer keyBuf2 = algo::Aes::generateKey(rng, params).getKeyBits();

  system_clock::TimePoint point1(time::fromIsoString("20150101T100000"));
  system_clock::TimePoint point2(time::fromIsoString("20150102T100000"));
  system_clock::TimePoint point3(time::fromIsoString("20150103T100000"));
  system_clock::TimePoint point4(time::fromIsoString("20150104T100000"));

  // add keys into the database
  BOOST_CHECK_NO_THROW(db.addContentKey(point1, keyBuf1));
  BOOST_CHECK_NO_THROW(db.addContentKey(point2, keyBuf1));
  BOOST_CHECK_NO_THROW(db.addContentKey(point3, keyBuf2));

  // throw exception when adding a key to an existing timeslot
  BOOST_CHECK_THROW(db.addContentKey(point1, keyBuf1), ProducerDB::Error);

  // has function
  BOOST_CHECK_EQUAL(db.hasContentKey(point1), true);
  BOOST_CHECK_EQUAL(db.hasContentKey(point2), true);
  BOOST_CHECK_EQUAL(db.hasContentKey(point3), true);
  BOOST_CHECK_EQUAL(db.hasContentKey(point4), false);

  // get content key
  Buffer keyResult = db.getContentKey(point1);
  BOOST_CHECK_EQUAL_COLLECTIONS(keyResult.begin(),
                                keyResult.end(),
                                keyBuf1.begin(),
                                keyBuf1.end());

  keyResult = db.getContentKey(point3);
  BOOST_CHECK_EQUAL_COLLECTIONS(keyResult.begin(),
                                keyResult.end(),
                                keyBuf2.begin(),
                                keyBuf2.end());

  // throw exception when there is no such timeslot in database
  BOOST_CHECK_THROW(db.getContentKey(point4), ProducerDB::Error);

  // delete content key
  BOOST_CHECK_EQUAL(db.hasContentKey(point1), true);
  db.deleteContentKey(point1);
  BOOST_CHECK_EQUAL(db.hasContentKey(point1), false);

  // delete at a non-existing timeslot
  BOOST_CHECK_NO_THROW(db.deleteContentKey(point4));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace gep
} // namespace ndn
