/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2020, Regents of the University of California
 *
 * NAC library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * NAC library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of NAC library authors and contributors.
 */

#ifndef NDN_NAC_TESTS_BOOST_TEST_HPP
#define NDN_NAC_TESTS_BOOST_TEST_HPP

// suppress warnings from Boost.Test
#pragma GCC system_header
#pragma clang system_header

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

namespace ut = boost::unit_test;

#endif // NDN_NAC_TESTS_BOOST_TEST_HPP
