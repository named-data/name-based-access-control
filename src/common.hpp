/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2018, Regents of the University of California
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

#include <ndn-cxx/data.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/ims/in-memory-storage-persistent.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/link.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/transform/block-cipher.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/security/v2/key-chain.hpp>
#include <ndn-cxx/security/v2/validation-callback.hpp>
#include <ndn-cxx/security/v2/validation-error.hpp>
#include <ndn-cxx/security/v2/validator.hpp>
#include <ndn-cxx/security/validator-null.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/util/signal.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/assert.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/noncopyable.hpp>

namespace ndn {
namespace nac {

using security::Identity;
using security::Key;
using security::SigningInfo;
using security::SafeBag;
using security::ValidatorNull;
using security::transform::PublicKey;
using security::v2::Certificate;
using security::v2::DataValidationFailureCallback;
using security::v2::DataValidationSuccessCallback;
using security::v2::ValidationError;
using security::v2::Validator;
using security::v2::extractKeyNameFromCertName;

namespace tlv {
using namespace ndn::tlv;

enum {
  EncryptedContent = 130,
  EncryptedPayload = 132,
  InitializationVector = 133,
  EncryptedPayloadKey = 134,
};

} // namespace tlv

const name::Component ENCRYPTED_BY("ENCRYPTED-BY");
const name::Component NAC("NAC");
const name::Component KEK("KEK");
const name::Component KDK("KDK");
const name::Component CK("CK");

const size_t AES_KEY_SIZE = 32;
const size_t AES_IV_SIZE = 16;

const time::seconds DEFAULT_KEK_FRESHNESS_PERIOD = 1_h;
const time::seconds DEFAULT_KDK_FRESHNESS_PERIOD = 1_h;
const time::seconds DEFAULT_CK_FRESHNESS_PERIOD = 1_h;

enum class ErrorCode {
  KekRetrievalFailure = 1,
  KekRetrievalTimeout = 2,
  KekInvalidName = 3,

  KdkRetrievalFailure = 11,
  KdkRetrievalTimeout = 12,
  KdkInvalidName = 13,
  KdkDecryptionFailure = 14,

  CkRetrievalFailure = 21,
  CkRetrievalTimeout = 22,
  CkInvalidName = 23,

  MissingRequiredKeyLocator = 101,
  TpmKeyNotFound = 102,
  EncryptionFailure = 103
};

using ErrorCallback = std::function<void (const ErrorCode&, const std::string&)>;


class Error : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};

/**
 * @brief Convert KEK name to KDK prefix:
 *
 * `<identity>/NAC/KEK/<key-id>`  =>>  `<identity>/NAC/KDK/<key-id>`
 */
Name
convertKekNameToKdkPrefix(const Name& kekName, const ErrorCallback& onFailure);

/**
 * @brief Extract KDK information from name of CK data packet name
 *
 * @return tuple of (KDK prefix, KDK identity, and KDK key id).  The last two identify
 *         KDK private/key pair in KeyChain
 */
std::tuple<Name, Name, Name>
extractKdkInfoFromCkName(const Name& ckDataName, const Name& ckName, const ErrorCallback& onFailure);

} // namespace nac
} // namespace ndn

#endif // NDN_NAC_COMMON_HPP
