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

#include "aes.hpp"
#include "error.hpp"
#include <openssl/rand.h>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>

namespace ndn {
namespace gep {
namespace algo {

DecryptKey<Aes>
Aes::generateKey(AesKeyParams& params)
{
  uint8_t key[32];

  int result = RAND_bytes(key, sizeof(key));
  if (result != 1) {
    BOOST_THROW_EXCEPTION(Error("Cannot generate 32 bytes random AES key"));
  }
  DecryptKey<Aes> decryptKey(Buffer(key, sizeof(key)));
  return decryptKey;
}

EncryptKey<Aes>
Aes::deriveEncryptKey(const Buffer& keyBits)
{
  Buffer copy = keyBits;
  EncryptKey<Aes> encryptKey(std::move(copy));
  return encryptKey;
}

Buffer
Aes::decrypt(const uint8_t* key, size_t keyLen,
             const uint8_t* payload, size_t payloadLen,
             const EncryptParams& params)
{
  if (params.getAlgorithmType() != tlv::AlgorithmAesCbc) {
    BOOST_THROW_EXCEPTION(Error("unsupported AES decryption mode"));
  }

  const Buffer& initVector = params.getIV();
  OBufferStream os;
  security::transform::bufferSource(payload, payloadLen)
    >> security::transform::blockCipher(BlockCipherAlgorithm::AES_CBC, CipherOperator::DECRYPT,
                                        key, keyLen, initVector.data(), initVector.size())
    >> security::transform::streamSink(os);

  auto result = os.buf();
  return *result;
}

Buffer
Aes::encrypt(const uint8_t* key, size_t keyLen,
             const uint8_t* payload, size_t payloadLen,
             const EncryptParams& params)
{
  if (params.getAlgorithmType() != tlv::AlgorithmAesCbc) {
    BOOST_THROW_EXCEPTION(Error("unsupported AES decryption mode"));
  }

  const Buffer& initVector = params.getIV();
  OBufferStream os;
  security::transform::bufferSource(payload, payloadLen)
    >> security::transform::blockCipher(BlockCipherAlgorithm::AES_CBC,
                                        CipherOperator::ENCRYPT,
                                        key, keyLen, initVector.data(), initVector.size())
    >> security::transform::streamSink(os);

  auto result = os.buf();
  return *result;
}

} // namespace algo
} // namespace gep
} // namespace ndn
