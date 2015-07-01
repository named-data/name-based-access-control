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

namespace ndn {
namespace gep {
namespace algo {

using namespace CryptoPP;

Buffer
crypt(CipherModeBase* cipher, const Buffer& data);

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
Aes::decrypt(const Buffer& keyBits, const Buffer& encryptedData, const EncryptParams& params)
{
  switch (params.getEncryptMode()) {
  case ENCRYPT_MODE_ECB_AES:
    {
      ECB_Mode<AES>::Decryption ecbDecryption(keyBits.get(), keyBits.size());
      return crypt(&ecbDecryption, encryptedData);
    }

  case ENCRYPT_MODE_CBC_AES:
    {
      Buffer initVector = params.getIV();
      if (initVector.size() != static_cast<size_t>(AES::BLOCKSIZE))
        throw Error("incorrect initial vector size");

      CBC_Mode<AES>::Decryption cbcDecryption(keyBits.get(), keyBits.size(), initVector.get());
      return crypt(&cbcDecryption, encryptedData);
    }

  default:
    throw Error("unsupported encryption mode");
  }
}

Buffer
Aes::encrypt(const Buffer& keyBits, const Buffer& plainData, const EncryptParams& params)
{
  switch (params.getEncryptMode()) {
  case ENCRYPT_MODE_ECB_AES:
    {
      ECB_Mode<AES>::Encryption ecbEncryption(keyBits.get(), keyBits.size());
      return crypt(&ecbEncryption, plainData);
    }

  case ENCRYPT_MODE_CBC_AES:
    {
      Buffer initVector = params.getIV();
      if (initVector.size() != static_cast<size_t>(AES::BLOCKSIZE))
        throw Error("incorrect initial vector size");

      CBC_Mode<AES>::Encryption cbcEncryption(keyBits.get(), keyBits.size(), initVector.get());
      return crypt(&cbcEncryption, plainData);
    }

  default:
    throw Error("unsupported encryption mode");
  }
}

Buffer
crypt(CipherModeBase* cipher, const Buffer& data)
{
  OBufferStream obuf;
  StringSource pipe(data.get(), data.size(), true,
                    new StreamTransformationFilter(*cipher, new FileSink(obuf)));
  return *(obuf.buf());
}

} // namespace algo
} // namespace gep
} // namespace ndn
