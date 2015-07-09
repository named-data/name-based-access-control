/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2015,  Regents of the University of California
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

#include <ndn-cxx/encoding/buffer-stream.hpp>
#include "aes.hpp"
#include "error.hpp"

namespace ndn {
namespace gep {
namespace algo {

using namespace CryptoPP;

static Buffer
transform(CipherModeBase* cipher, const uint8_t* data, size_t dataLen)
{
  OBufferStream obuf;
  StringSource pipe(data, dataLen, true,
                    new StreamTransformationFilter(*cipher, new FileSink(obuf)));
  return *(obuf.buf());
}

DecryptKey<Aes>
Aes::generateKey(RandomNumberGenerator& rng, AesKeyParams& params)
{
  SecByteBlock key(0x00, params.getKeySize() >> 3);  // Converting key bit-size to byte-size.
  rng.GenerateBlock(key.data(), key.size());

  DecryptKey<Aes> decryptKey(std::move(Buffer(key.data(), key.size())));
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
  switch (params.getAlgorithmType()) {
    case tlv::AlgorithmAesEcb: {
      ECB_Mode<AES>::Decryption ecbDecryption(key, keyLen);
      return transform(&ecbDecryption, payload, payloadLen);
    }
    case tlv::AlgorithmAesCbc: {
      const Buffer& initVector = params.getIV();
      if (initVector.size() != static_cast<size_t>(AES::BLOCKSIZE))
        throw Error("incorrect initial vector size");

      CBC_Mode<AES>::Decryption cbcDecryption(key, keyLen, initVector.get());
      return transform(&cbcDecryption, payload, payloadLen);
    }
    default:
      throw Error("unsupported encryption mode");
  }
}

Buffer
Aes::encrypt(const uint8_t* key, size_t keyLen,
             const uint8_t* payload, size_t payloadLen,
             const EncryptParams& params)
{
  switch (params.getAlgorithmType()) {
    case tlv::AlgorithmAesEcb: {
      ECB_Mode<AES>::Encryption ecbEncryption(key, keyLen);
      return transform(&ecbEncryption, payload, payloadLen);
    }
    case tlv::AlgorithmAesCbc: {
      const Buffer& initVector = params.getIV();
      if (initVector.size() != static_cast<size_t>(AES::BLOCKSIZE))
        throw Error("incorrect initial vector size");

      CBC_Mode<AES>::Encryption cbcEncryption(key, keyLen, initVector.get());
      return transform(&cbcEncryption, payload, payloadLen);
    }
    default:
      throw Error("unsupported encryption mode");
  }
}

} // namespace algo
} // namespace gep
} // namespace ndn
