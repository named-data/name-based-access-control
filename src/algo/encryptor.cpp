/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2015,  Regents of the University of California
 *
 * This file is part of ndn-group-encrypt (Group-based Encryption Protocol for NDN).
 * See AUTHORS.md for complete list of ndn-group-encrypt authors and contributors.
 *
 * ndn-group-encrypt is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-group-encrypt is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndn-group-encrypt, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "encryptor.hpp"
#include "../random-number-generator.hpp"
#include "../encrypted-content.hpp"
#include "aes.hpp"
#include "rsa.hpp"

#include "error.hpp"

namespace ndn {
namespace gep {
namespace algo {

using namespace CryptoPP;

/**
 * @brief Helper method for symmetric encryption
 *
 * Encrypt @p payload using @p key according to @p params.
 *
 * @return An EncryptedContent
 */
static EncryptedContent
encryptSymmetric(const uint8_t* payload, size_t payloadLen,
                 const uint8_t* key, size_t keyLen,
                 const Name& keyName, const EncryptParams& params)
{
  tlv::AlgorithmTypeValue algType = params.getAlgorithmType();
  const Buffer& iv = params.getIV();
  KeyLocator keyLocator(keyName);

  switch (algType) {
    case tlv::AlgorithmAesEcb: {
      const Buffer& encryptedPayload = Aes::encrypt(key, keyLen, payload, payloadLen, params);
      return EncryptedContent(algType, keyLocator, encryptedPayload.buf(), encryptedPayload.size(), iv.buf(), iv.size());
    }
    case tlv::AlgorithmAesCbc: {
      BOOST_ASSERT(iv.size() == static_cast<size_t>(AES::BLOCKSIZE));
      const Buffer& encryptedPayload = Aes::encrypt(key, keyLen, payload, payloadLen, params);
      return EncryptedContent(algType, keyLocator, encryptedPayload.buf(), encryptedPayload.size(), iv.buf(), iv.size());
    }
    default: {
      BOOST_ASSERT(false);
      throw algo::Error("Unsupported encryption method");
    }
  }
}

/**
 * @brief Helper method for asymmetric encryption
 *
 * Encrypt @p payload using @p key according to @p params.
 *
 * @pre @p payloadLen should be within the range of the key.
 * @return An EncryptedContent
 */
static EncryptedContent
encryptAsymmetric(const uint8_t* payload, size_t payloadLen,
                  const uint8_t* key, size_t keyLen,
                  const Name& keyName, const EncryptParams& params)
{
  tlv::AlgorithmTypeValue algType = params.getAlgorithmType();
  KeyLocator keyLocator(keyName);

  switch (algType) {
    case tlv::AlgorithmRsaPkcs:
    case tlv::AlgorithmRsaOaep: {
      Buffer encryptedPayload = Rsa::encrypt(key, keyLen, payload, payloadLen, params);
      return EncryptedContent(algType, keyLocator, encryptedPayload.buf(), encryptedPayload.size());
    }
    default: {
      BOOST_ASSERT(false);
      throw algo::Error("Unsupported encryption method");
    }
  }
}

void
encryptData(Data& data, const uint8_t* payload, size_t payloadLen,
            const Name& keyName, const uint8_t* key, size_t keyLen,
            const EncryptParams& params)
{
  Name dataName = data.getName();
  dataName.append(NAME_COMPONENT_FOR).append(keyName);
  data.setName(dataName);
  switch(params.getAlgorithmType()) {
    case tlv::AlgorithmAesCbc:
    case tlv::AlgorithmAesEcb: {
      const EncryptedContent& content = encryptSymmetric(payload, payloadLen, key, keyLen, keyName, params);
      data.setContent(content.wireEncode());
      break;
    }
    case tlv::AlgorithmRsaPkcs:
    case tlv::AlgorithmRsaOaep: {
      size_t maxPlaintextLength = 0;
      RSA::PublicKey publicKey;
      ByteQueue keyQueue;

      keyQueue.LazyPut(key, keyLen);
      publicKey.Load(keyQueue);
      RSAES_PKCS1v15_Encryptor enc(publicKey);
      maxPlaintextLength = enc.FixedMaxPlaintextLength();

      if (maxPlaintextLength < payloadLen) {
        RandomNumberGenerator rng;
        SecByteBlock nonceKey(0x00, 16);  // 128 bits key.
        rng.GenerateBlock(nonceKey.data(), nonceKey.size());

        Name nonceKeyName(keyName);
        nonceKeyName.append("nonce");

        EncryptParams symParams(tlv::AlgorithmAesCbc, AES::BLOCKSIZE);

        const EncryptedContent& nonceContent =
          encryptSymmetric(payload, payloadLen, nonceKey.data(), nonceKey.size(), nonceKeyName, symParams);

        const EncryptedContent& payloadContent =
          encryptAsymmetric(nonceKey.data(), nonceKey.size(), key, keyLen, keyName, params);

        Block content(tlv::Content);
        content.push_back(payloadContent.wireEncode());
        content.push_back(nonceContent.wireEncode());

        data.setContent(content);
        return;
      }
      else {
        const EncryptedContent& content = encryptAsymmetric(payload, payloadLen, key, keyLen, keyName, params);
        data.setContent(content.wireEncode());
        return;
      }
    }
    default:
      throw algo::Error("Unsupported encryption method");
  }
}

} // namespace algo
} // namespace gep
} // namespace ndn
