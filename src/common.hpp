/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2023, Regents of the University of California
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

#include "detail/config.hpp"

#ifdef NAC_WITH_TESTS
#define NAC_VIRTUAL_WITH_TESTS virtual
#define NAC_PUBLIC_WITH_TESTS_ELSE_PROTECTED public
#define NAC_PUBLIC_WITH_TESTS_ELSE_PRIVATE public
#define NAC_PROTECTED_WITH_TESTS_ELSE_PRIVATE protected
#else
#define NAC_VIRTUAL_WITH_TESTS
#define NAC_PUBLIC_WITH_TESTS_ELSE_PROTECTED protected
#define NAC_PUBLIC_WITH_TESTS_ELSE_PRIVATE private
#define NAC_PROTECTED_WITH_TESTS_ELSE_PRIVATE private
#endif

#include <functional>
#include <stdexcept>

#include <ndn-cxx/data.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/ims/in-memory-storage-persistent.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/security/certificate.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-info.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/security/validation-callback.hpp>
#include <ndn-cxx/security/validation-error.hpp>
#include <ndn-cxx/security/validator.hpp>

#include <boost/assert.hpp>

namespace ndn::nac {

using security::Certificate;
using security::DataValidationFailureCallback;
using security::DataValidationSuccessCallback;
using security::Identity;
using security::Key;
using security::SafeBag;
using security::SigningInfo;
using security::ValidationError;
using security::Validator;
using security::extractKeyNameFromCertName;
using security::transform::PublicKey;

namespace tlv {

using namespace ndn::tlv;

enum {
  EncryptedContent = 130,
  EncryptedPayload = 132,
  InitializationVector = 133,
  EncryptedPayloadKey = 134,
};

} // namespace tlv

inline const name::Component ENCRYPTED_BY{"ENCRYPTED-BY"};
inline const name::Component NAC{"NAC"};
inline const name::Component KEK{"KEK"};
inline const name::Component KDK{"KDK"};
inline const name::Component CK{"CK"};

inline constexpr size_t AES_KEY_SIZE = 32;
inline constexpr size_t AES_IV_SIZE = 16;

inline constexpr time::seconds DEFAULT_KEK_FRESHNESS_PERIOD = 1_h;
inline constexpr time::seconds DEFAULT_KDK_FRESHNESS_PERIOD = 1_h;
inline constexpr time::seconds DEFAULT_CK_FRESHNESS_PERIOD = 1_h;

inline constexpr time::seconds RETRY_DELAY_AFTER_NACK = 1_s;
inline constexpr time::seconds RETRY_DELAY_KEK_RETRIEVAL = 60_s;

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

using ErrorCallback = std::function<void(const ErrorCode&, const std::string&)>;

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

} // namespace ndn::nac

#endif // NDN_NAC_COMMON_HPP
