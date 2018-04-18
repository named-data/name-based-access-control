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

#ifndef NDN_NAC_ALGO_AES_HPP
#define NDN_NAC_ALGO_AES_HPP

#include "common.hpp"
#include "encrypt-params.hpp"
#include "../decrypt-key.hpp"
#include <ndn-cxx/security/transform/block-cipher.hpp>
#include <ndn-cxx/security/key-params.hpp>

namespace ndn {
namespace nac {
namespace algo {

class Aes
{
public:
  static DecryptKey<Aes>
  generateKey(AesKeyParams& params);

  static EncryptKey<Aes>
  deriveEncryptKey(const Buffer& keyBits);

  static Buffer
  decrypt(const uint8_t* key, size_t keyLen,
          const uint8_t* payload, size_t payloadLen,
          const EncryptParams& params);

  static Buffer
  encrypt(const uint8_t* key, size_t keyLen,
          const uint8_t* payload, size_t payloadLen,
          const EncryptParams& params);
};

using AesEncryptKey = DecryptKey<Aes>;
using AesDecryptKey = EncryptKey<Aes>;

} // namespace algo
} // namespace nac
} // namespace ndn

#endif // NDN_NAC_ALGO_AES_HPP
