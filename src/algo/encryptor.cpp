/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2018, Regents of the University of California
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
#include "aes.hpp"
#include "rsa.hpp"
#include "../encrypted-content.hpp"
#include "error.hpp"
#include <openssl/rand.h>

namespace ndn {
namespace gep {
namespace algo {

/**
 * @brief Helper method for symmetric encryption
 *
 * Encrypt @p payload using @p key according to @p params.
 *
 * @return An EncryptedContent
 */
static EncryptedContent
encryptSymmetric(const uint8_t* payload,
                 size_t payloadLen,
                 const uint8_t* key,
                 size_t keyLen,
                 const Name& keyName,
                 const EncryptParams& params)
{
  tlv::AlgorithmTypeValue algType = params.getAlgorithmType();
  const Buffer& iv = params.getIV();
  KeyLocator keyLocator(keyName);

  switch (algType) {
    case tlv::AlgorithmAesCbc: {
      const Buffer& encryptedPayload = Aes::encrypt(key, keyLen, payload, payloadLen, params);
      return EncryptedContent(algType, keyLocator,
                              encryptedPayload.data(),
                              encryptedPayload.size(),
                              iv.data(), iv.size());
    }
    default: {
      BOOST_ASSERT(false);
      BOOST_THROW_EXCEPTION(algo::Error("Unsupported encryption method"));
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
                  const Name& keyName,
                  const EncryptParams& params)
{
  tlv::AlgorithmTypeValue algType = params.getAlgorithmType();
  KeyLocator keyLocator(keyName);

  switch (algType) {
    case tlv::AlgorithmRsaPkcs:
    case tlv::AlgorithmRsaOaep: {
      Buffer encryptedPayload = Rsa::encrypt(key, keyLen, payload, payloadLen);
      return EncryptedContent(algType, keyLocator, encryptedPayload.data(), encryptedPayload.size());
    }
    default: {
      BOOST_ASSERT(false);
      BOOST_THROW_EXCEPTION(algo::Error("Unsupported encryption method"));
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
  switch (params.getAlgorithmType()) {
    case tlv::AlgorithmAesCbc:
    case tlv::AlgorithmAesEcb: {
      const EncryptedContent& content =
        encryptSymmetric(payload, payloadLen, key, keyLen, keyName, params);
      data.setContent(content.wireEncode());
      break;
    }
    case tlv::AlgorithmRsaPkcs:
    case tlv::AlgorithmRsaOaep: {
      if (payloadLen > keyLen - 11) {
        uint8_t nonceKey[16];
        int result = RAND_bytes(nonceKey, sizeof(nonceKey));
        if (result != 1) {
          BOOST_THROW_EXCEPTION(Error("Cannot generate 32 bytes random AES key"));
        }

        Name nonceKeyName(keyName);
        nonceKeyName.append("nonce");

        EncryptParams symParams(tlv::AlgorithmAesCbc, 16);

        const EncryptedContent& nonceContent =
          encryptSymmetric(payload, payloadLen, nonceKey, sizeof(nonceKey), nonceKeyName, symParams);

        const EncryptedContent& payloadContent =
          encryptAsymmetric(nonceKey, sizeof(nonceKey), key, keyLen, keyName, params);

        Block content(tlv::Content);
        content.push_back(payloadContent.wireEncode());
        content.push_back(nonceContent.wireEncode());

        data.setContent(content);
        return;
      }
      else {
        const EncryptedContent& content =
          encryptAsymmetric(payload, payloadLen, key, keyLen, keyName, params);
        data.setContent(content.wireEncode());
        return;
      }
    }
    default:
      BOOST_THROW_EXCEPTION(algo::Error("Unsupported encryption method"));
  }
}

} // namespace algo
} // namespace gep
} // namespace ndn
