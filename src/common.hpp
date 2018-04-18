/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2018, Regents of the University of California
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

#ifndef NDN_NAC_COMMON_HPP
#define NDN_NAC_COMMON_HPP

#include "config.hpp"

#ifdef NDN_NAC_HAVE_TESTS
#define VIRTUAL_WITH_TESTS virtual
#define PUBLIC_WITH_TESTS_ELSE_PROTECTED public
#define PUBLIC_WITH_TESTS_ELSE_PRIVATE public
#define PROTECTED_WITH_TESTS_ELSE_PRIVATE protected
#else
#define VIRTUAL_WITH_TESTS
#define PUBLIC_WITH_TESTS_ELSE_PROTECTED protected
#define PUBLIC_WITH_TESTS_ELSE_PRIVATE private
#define PROTECTED_WITH_TESTS_ELSE_PRIVATE private
#endif

#include <cstddef>
#include <list>
#include <map>
#include <queue>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <ndn-cxx/common.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/util/signal.hpp>
#include <ndn-cxx/link.hpp>

#include <ndn-cxx/security/v2/validation-callback.hpp>
#include <ndn-cxx/security/v2/validation-error.hpp>
#include <ndn-cxx/security/v2/validator.hpp>
#include <ndn-cxx/security/validator-null.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/assert.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/noncopyable.hpp>
#include <boost/property_tree/ptree.hpp>

namespace ndn {
namespace nac {

using security::v2::Certificate;
using security::v2::Validator;
using security::ValidatorNull;
using security::v2::DataValidationSuccessCallback;
using security::v2::DataValidationFailureCallback;
using security::v2::ValidationError;

namespace tlv {
using namespace ndn::tlv;
} // namespace tlv

const name::Component NAME_COMPONENT_FOR("FOR");
const name::Component NAME_COMPONENT_READ("READ");
const name::Component NAME_COMPONENT_SAMPLE("SAMPLE");
const name::Component NAME_COMPONENT_ACCESS("ACCESS");
const name::Component NAME_COMPONENT_E_KEY("E-KEY");
const name::Component NAME_COMPONENT_D_KEY("D-KEY");
const name::Component NAME_COMPONENT_C_KEY("C-KEY");

} // namespace nac
} // namespace ndn

#endif // NDN_NAC_COMMON_HPP
