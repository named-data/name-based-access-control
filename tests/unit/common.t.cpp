/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2020, Regents of the University of California
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
 */

#include "common.hpp"

#include "tests/boost-test.hpp"

namespace ndn {
namespace nac {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestCommon)

BOOST_AUTO_TEST_CASE(Helpers)
{
  bool hasFailed = false;
  auto onFailed = [&] (auto...) { hasFailed = true; };

  auto kdkPrefix = convertKekNameToKdkPrefix(Name("/access/prefix/NAC/dataset/KEK/id"), onFailed);

  BOOST_CHECK(!hasFailed);
  BOOST_CHECK(kdkPrefix == Name("/access/prefix/NAC/dataset/KDK/id"));

  hasFailed = false;
  kdkPrefix = convertKekNameToKdkPrefix(Name("/invalid/name"), onFailed);
  BOOST_CHECK(hasFailed);
  BOOST_CHECK(kdkPrefix.empty());

  hasFailed = false;
  Name kdkIdentity, kdkKeyName;
  std::tie(kdkPrefix, kdkIdentity, kdkKeyName) =
    extractKdkInfoFromCkName(Name("/ck/prefix/stuff/ENCRYPTED-BY/access/prefix/NAC/dataset/KEK/id"),
                             Name("/ck/prefix/stuff"), onFailed);
  BOOST_CHECK(!hasFailed);
  BOOST_CHECK_EQUAL(kdkPrefix, Name("/access/prefix/NAC/dataset/KDK/id"));
  BOOST_CHECK_EQUAL(kdkIdentity, Name("/access/prefix/NAC/dataset"));
  BOOST_CHECK_EQUAL(kdkKeyName, Name("/access/prefix/NAC/dataset/KEY/id"));

  hasFailed = false;
  std::tie(kdkPrefix, kdkIdentity, kdkKeyName) =
    extractKdkInfoFromCkName(Name("/ck/prefix/ENCRYPTED-BY/access/prefix/NAC/dataset/KEK/id"),
                             Name("/ck/prefix/stuff"), onFailed);
  BOOST_CHECK(hasFailed);
  BOOST_CHECK(kdkPrefix.empty());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nac
} // namespace ndn
