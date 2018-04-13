/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2018,  Regents of the University of California
 *
 * This file is part of gep (Group-based Encryption Protocol for NDN).
 * See AUTHORS.md for complete list of gep authors and contributors.
 *
 * gep is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * gep is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * gep, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "rsa.hpp"
#include "error.hpp"
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/private-key.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>

namespace ndn {
namespace gep {
namespace algo {

DecryptKey<Rsa>
Rsa::generateKey(RsaKeyParams& params)
{
  auto privateKey = security::transform::generatePrivateKey(params);

  OBufferStream os;
  privateKey->savePkcs1(os);

  DecryptKey<Rsa> decryptKey(std::move(*os.buf()));
  return decryptKey;
}

EncryptKey<Rsa>
Rsa::deriveEncryptKey(const Buffer& keyBits)
{
  security::transform::PrivateKey sKey;
  sKey.loadPkcs1(keyBits.get<uint8_t>(), keyBits.size());

  ConstBufferPtr pKeyBits = sKey.derivePublicKey();
  security::transform::PublicKey pKey;
  pKey.loadPkcs8(pKeyBits->data(), pKeyBits->size());

  OBufferStream os;
  pKey.savePkcs8(os);

  EncryptKey<Rsa> encryptKey(std::move(*os.buf()));
  return encryptKey;
}

Buffer
Rsa::decrypt(const uint8_t* key, size_t keyLen,
             const uint8_t* payload, size_t payloadLen)
{

  security::transform::PrivateKey sKey;
  sKey.loadPkcs1(key, keyLen);

  auto decrypted = sKey.decrypt(payload, payloadLen);
  return *decrypted;
}

Buffer
Rsa::encrypt(const uint8_t* key, size_t keyLen,
             const uint8_t* payload, size_t payloadLen)
{
  security::transform::PublicKey pKey;
  pKey.loadPkcs8(key, keyLen);

  auto cipherText = pKey.encrypt(payload, payloadLen);
  return *cipherText;
}

} // namespace algo
} // namespace gep
} // namespace ndn
