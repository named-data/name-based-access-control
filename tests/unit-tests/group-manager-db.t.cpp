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

#include "group-manager-db.hpp"
#include "algo/rsa.hpp"
#include "boost-test.hpp"

#include <boost/filesystem.hpp>

namespace ndn {
namespace gep {
namespace tests {

const uint8_t SCHEDULE[] = {
  0x8f, 0xc4,// Schedule
  0x8d, 0x90,// WhiteIntervalList
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
  0x8e, 0x30, // BlackIntervalList
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

const uint8_t REPETITIVE_INTERVAL[] = {
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x39, 0x32, 0x31, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x02,
    0x89, 0x01,
      0x0a,
    0x8a, 0x01,
      0x05,
    0x8b, 0x01,
      0x01
};

class GroupManagerDBFixture
{
public:
  GroupManagerDBFixture()
    : tmpPath(boost::filesystem::path(TMP_TESTS_PATH))
  {
    boost::filesystem::create_directories(tmpPath);
  }

  ~GroupManagerDBFixture()
  {
    boost::filesystem::remove_all(tmpPath);
  }

public:
  boost::filesystem::path tmpPath;
};

BOOST_FIXTURE_TEST_SUITE(TestGroupManagerDB, GroupManagerDBFixture)

BOOST_AUTO_TEST_CASE(DatabaseFunctions)
{
  // construction
  std::string dbDir = tmpPath.c_str();
  dbDir += "/test.db";
  GroupManagerDB db(dbDir);

  Block scheduleBlock(SCHEDULE, sizeof(SCHEDULE));

  // create schedule
  Schedule schedule(scheduleBlock);

  // create member
  RandomNumberGenerator rng;
  RsaKeyParams params;
  DecryptKey<algo::Rsa> decryptKey = algo::Rsa::generateKey(rng, params);
  EncryptKey<algo::Rsa> encryptKey = algo::Rsa::deriveEncryptKey(decryptKey.getKeyBits());
  Buffer keyBuf = encryptKey.getKeyBits();

  Name name1("/ndn/BoyA/ksk-123");
  Name name2("/ndn/BoyB/ksk-1233");
  Name name3("/ndn/GirlC/ksk-123");
  Name name4("/ndn/GirlD/ksk-123");
  Name name5("/ndn/Hello/ksk-123");

  // add schedules into the database
  BOOST_CHECK_NO_THROW(db.addSchedule("work-time", schedule));
  BOOST_CHECK_NO_THROW(db.addSchedule("rest-time", schedule));
  BOOST_CHECK_NO_THROW(db.addSchedule("play-time", schedule));
  BOOST_CHECK_NO_THROW(db.addSchedule("boelter-time", schedule));

  // throw exception when adding a schedule called an existing name
  BOOST_CHECK_THROW(db.addSchedule("boelter-time", schedule), GroupManagerDB::Error);

  // add members into the database
  BOOST_CHECK_NO_THROW(db.addMember("work-time", name1, keyBuf));
  BOOST_CHECK_NO_THROW(db.addMember("rest-time", name2, keyBuf));
  BOOST_CHECK_NO_THROW(db.addMember("play-time", name3, keyBuf));
  BOOST_CHECK_NO_THROW(db.addMember("play-time", name4, keyBuf));

  // throw exception when adding a member having a not existing schedule name
  BOOST_CHECK_THROW(db.addMember("false-time", name5, keyBuf), GroupManagerDB::Error);

  BOOST_CHECK_NO_THROW(db.addMember("boelter-time", name5, keyBuf));

  // throw exception when adding a member having an existing identity
  BOOST_CHECK_THROW(db.addMember("work-time", name5, keyBuf), GroupManagerDB::Error);

  // has function
  BOOST_CHECK_EQUAL(db.hasSchedule("work-time"), true);
  BOOST_CHECK_EQUAL(db.hasSchedule("rest-time"), true);
  BOOST_CHECK_EQUAL(db.hasSchedule("play-time"), true);
  BOOST_CHECK_EQUAL(db.hasSchedule("sleep-time"), false);
  BOOST_CHECK_EQUAL(db.hasSchedule(""), false);

  BOOST_CHECK_EQUAL(db.hasMember(Name("/ndn/BoyA")), true);
  BOOST_CHECK_EQUAL(db.hasMember(Name("/ndn/BoyB")), true);
  BOOST_CHECK_EQUAL(db.hasMember(Name("/ndn/BoyC")), false);

  // get schedule
  Schedule scheduleResult = db.getSchedule("work-time");
  BOOST_CHECK(scheduleResult.wireEncode() == scheduleBlock);

  scheduleResult = db.getSchedule("play-time");
  BOOST_CHECK(scheduleResult.wireEncode() == scheduleBlock);

  // throw exception when there is no such schedule in database
  BOOST_CHECK_THROW(db.getSchedule("work-time-11"), GroupManagerDB::Error);

  // list all schedule names
  std::list<std::string> names = db.listAllScheduleNames();
  BOOST_CHECK(std::find(names.begin(), names.end(), "work-time") != names.end());
  BOOST_CHECK(std::find(names.begin(), names.end(), "play-time") != names.end());
  BOOST_CHECK(std::find(names.begin(), names.end(), "rest-time") != names.end());
  BOOST_CHECK(std::find(names.begin(), names.end(), "sleep-time") == names.end());

  // list members of a schedule
  std::map<Name, Buffer> memberMap = db.getScheduleMembers("play-time");
  BOOST_CHECK(memberMap.size() != 0);

  // when there's no such schedule, the return list's size is 0
  BOOST_CHECK_EQUAL(db.getScheduleMembers("sleep-time").size(), 0);

  // list all members
  std::list<Name> members = db.listAllMembers();
  BOOST_CHECK(std::find(members.begin(), members.end(), Name("/ndn/GirlC")) != members.end());
  BOOST_CHECK(std::find(members.begin(), members.end(), Name("/ndn/GirlD")) != members.end());
  BOOST_CHECK(std::find(members.begin(), members.end(), Name("/ndn/BoyA")) != members.end());
  BOOST_CHECK(std::find(members.begin(), members.end(), Name("/ndn/BoyB")) != members.end());

  // rename schedule
  BOOST_CHECK_EQUAL(db.hasSchedule("boelter-time"), true);
  db.renameSchedule("boelter-time", "rieber-time");
  BOOST_CHECK_EQUAL(db.hasSchedule("boelter-time"), false);
  BOOST_CHECK_EQUAL(db.hasSchedule("rieber-time"), true);
  BOOST_CHECK_EQUAL(db.getMemberSchedule("/ndn/Hello"), "rieber-time");

  // update schedule
  Schedule newSchedule(scheduleBlock);
  Block repIntervalBlock(REPETITIVE_INTERVAL, sizeof(REPETITIVE_INTERVAL));
  newSchedule.addWhiteInterval(RepetitiveInterval(repIntervalBlock));
  db.updateSchedule("rieber-time", newSchedule);
  scheduleResult = db.getSchedule("rieber-time");
  BOOST_CHECK(scheduleResult.wireEncode() != scheduleBlock);
  BOOST_CHECK(scheduleResult.wireEncode() == newSchedule.wireEncode());

  // add a new schedule when update a not existing schedule
  BOOST_CHECK_EQUAL(db.hasSchedule("ralphs-time"), false);
  db.updateSchedule("ralphs-time", newSchedule);
  BOOST_CHECK_EQUAL(db.hasSchedule("ralphs-time"), true);

  // update schedule of member
  db.updateMemberSchedule(Name("/ndn/Hello"), "play-time");
  BOOST_CHECK_EQUAL(db.getMemberSchedule(Name("/ndn/Hello")), "play-time");

  // delete member
  BOOST_CHECK_EQUAL(db.hasMember(Name("/ndn/Hello")), true);
  db.deleteMember(Name("/ndn/Hello"));
  BOOST_CHECK_EQUAL(db.hasMember(Name("/ndn/Hello")), false);

  // delete a not existing member
  BOOST_CHECK_NO_THROW(db.deleteMember(Name("/ndn/notExisting")));

  // delete the schedule and all the members using this schedule should be deleted
  db.deleteSchedule("play-time");
  BOOST_CHECK_EQUAL(db.hasSchedule("play-time"), false);
  BOOST_CHECK_EQUAL(db.hasMember(Name("/ndn/GirlC")), false);
  BOOST_CHECK_EQUAL(db.hasMember(Name("/ndn/GirlD")), false);

  // delete a not existing schedule
  BOOST_CHECK_NO_THROW(db.deleteSchedule("not-existing-time"));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace gep
} // namespace ndn
