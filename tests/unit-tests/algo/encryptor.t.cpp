/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2015,  Regents of the University of California
 *
 * This file is part of ndn-group-encrypt (Group-based Encryption Protocol for NDN).
 * See AUTHORS.md for complete list of ndn-group-encrypt authors and contributors.
 *
 * ndn-group-encrypt is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * ndn-group-encrypt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndn-group-encrypt, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "random-number-generator.hpp"
#include "encrypted-content.hpp"
#include "algo/encryptor.hpp"
#include "algo/rsa.hpp"
#include "algo/aes.hpp"

#include <boost/mpl/list.hpp>
#include "boost-test.hpp"
#include <algorithm>

namespace ndn {
namespace gep {
namespace algo {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestEncryptor)

class TestDataAesEcb
{
public:
  TestDataAesEcb()
    : keyName("/test")
    , encryptParams(tlv::AlgorithmAesEcb)
  {
    const uint8_t raw_content[] = {
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
      0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73
    };
    plainText = Buffer(raw_content, sizeof(raw_content));

    const uint8_t aes_key[] = {
      0xdd, 0x60, 0x77, 0xec, 0xa9, 0x6b, 0x23, 0x1b,
      0x40, 0x6b, 0x5a, 0xf8, 0x7d, 0x3d, 0x55, 0x32
    };
    key = Buffer(aes_key, sizeof(aes_key));

    const uint8_t encrypted_content[] = {
      0x15, 0x31,
        0x82, 0x2f,
          0x1c, 0x08,
            0x07, 0x06,
              0x08, 0x04, 0x74, 0x65, 0x73, 0x74,
        0x83, 0x01,
          0x00,
        0x84, 0x20,
          0x13, 0x80, 0x1a, 0xc0, 0x4c, 0x75, 0xa7, 0x7f,
          0x43, 0x5e, 0xd7, 0xa6, 0x3f, 0xd3, 0x68, 0x94,
          0xe2, 0xcf, 0x54, 0xb1, 0xc2, 0xce, 0xad, 0x9b,
          0x56, 0x6e, 0x1c, 0xe6, 0x55, 0x1d, 0x79, 0x04
    };
    encryptedContent = Buffer(encrypted_content, sizeof(encrypted_content));
  }

public:
  Buffer plainText;
  Buffer key;
  Name keyName;
  EncryptParams encryptParams;
  Buffer encryptedContent;
};

class TestDataAesCbc
{
public:
  TestDataAesCbc()
    : keyName("/test")
    , encryptParams(tlv::AlgorithmAesCbc)
  {
    const uint8_t raw_content[] = {
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
      0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73
    };
    plainText = Buffer(raw_content, sizeof(raw_content));

    const uint8_t aes_key[] = {
      0xdd, 0x60, 0x77, 0xec, 0xa9, 0x6b, 0x23, 0x1b,
      0x40, 0x6b, 0x5a, 0xf8, 0x7d, 0x3d, 0x55, 0x32
    };
    key = Buffer(aes_key, sizeof(aes_key));

    const uint8_t iv[] = {
      0x73, 0x6f, 0x6d, 0x65, 0x72, 0x61, 0x6e, 0x64,
      0x6f, 0x6d, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72
    };

    encryptParams.setIV(iv, sizeof(iv));

    const uint8_t encrypted_content[] = {
      0x15, 0x43, // Content
        0x82, 0x41, // EncryptedContent
          0x1c, 0x08, // KeyLocator /test
            0x07, 0x06,
              0x08, 0x04, 0x74, 0x65, 0x73, 0x74,
        0x83, 0x01, // EncryptedAlgorithm
          0x01, // AlgorithmAesCbc
        0x85, 0x10,
          0x73, 0x6f, 0x6d, 0x65, 0x72, 0x61, 0x6e, 0x64,
          0x6f, 0x6d, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72,
        0x84, 0x20, // EncryptedPayLoad
          0x6a, 0x6b, 0x58, 0x9c, 0x30, 0x3b, 0xd9, 0xa6,
          0xed, 0xd2, 0x12, 0xef, 0x29, 0xad, 0xc3, 0x60,
          0x1f, 0x1b, 0x6b, 0xc7, 0x03, 0xff, 0x53, 0x52,
          0x82, 0x6d, 0x82, 0x73, 0x05, 0xf9, 0x03, 0xdc
    };
    encryptedContent = Buffer(encrypted_content, sizeof(encrypted_content));
  }

public:
  Buffer plainText;
  Buffer key;
  Name keyName;
  EncryptParams encryptParams;
  Buffer encryptedContent;
};

typedef boost::mpl::list<TestDataAesCbc,
                         TestDataAesEcb> EncryptorAesTestInputs;

BOOST_AUTO_TEST_CASE_TEMPLATE(ContentSymmetricEncrypt, T, EncryptorAesTestInputs)
{
  T input;

  Data data;
  encryptData(data, input.plainText.buf(), input.plainText.size(),
              input.keyName, input.key.buf(), input.key.size(), input.encryptParams);

  BOOST_CHECK_EQUAL(data.getName(), Name("/FOR").append(input.keyName));

  BOOST_CHECK_EQUAL_COLLECTIONS(input.encryptedContent.begin(), input.encryptedContent.end(),
                                data.getContent().wire(), data.getContent().wire() + data.getContent().size());

  EncryptedContent content(data.getContent().blockFromValue());
  const Buffer& decryptedOutput = Aes::decrypt(input.key.buf(), input.key.size(),
                                               content.getPayload().buf(), content.getPayload().size(),
                                               input.encryptParams);

  BOOST_CHECK_EQUAL_COLLECTIONS(input.plainText.begin(), input.plainText.end(),
                                decryptedOutput.begin(), decryptedOutput.end());
}

class TestDataRsaOaep
{
public:
  TestDataRsaOaep()
    : type(tlv::AlgorithmRsaOaep)
  {
  }
public:
  tlv::AlgorithmTypeValue type;
};

class TestDataRsaPkcs
{
public:
  TestDataRsaPkcs()
    : type(tlv::AlgorithmRsaPkcs)
  {
  }
public:
  tlv::AlgorithmTypeValue type;
};

typedef boost::mpl::list<TestDataRsaOaep,
                         TestDataRsaPkcs> EncryptorRsaTestInputs;

BOOST_AUTO_TEST_CASE_TEMPLATE(ContentAsymmetricEncryptSmall, T, EncryptorRsaTestInputs)
{
  T type;

  const uint8_t raw_content[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73
  };

  Data data;
  RandomNumberGenerator rng;
  RsaKeyParams rsaParams(1024);

  Name keyName("test");

  DecryptKey<Rsa> decryptKey = Rsa::generateKey(rng, rsaParams);
  EncryptKey<Rsa> encryptKey = Rsa::deriveEncryptKey(decryptKey.getKeyBits());

  Buffer eKey = encryptKey.getKeyBits();
  Buffer dKey = decryptKey.getKeyBits();

  EncryptParams encryptParams(type.type);

  encryptData(data, raw_content, sizeof(raw_content),
              keyName, eKey.buf(), eKey.size(), encryptParams);

  BOOST_CHECK_EQUAL(data.getName(), Name("/FOR").append(keyName));

  Block dataContent = data.getContent();
  dataContent.parse();
  BOOST_CHECK_EQUAL(dataContent.elements_size(), 1);

  EncryptedContent extractContent(data.getContent().blockFromValue());
  BOOST_CHECK_EQUAL(extractContent.getKeyLocator().getName(), keyName);
  BOOST_CHECK_EQUAL(extractContent.getInitialVector().size(), 0);
  BOOST_CHECK_EQUAL(extractContent.getAlgorithmType(), type.type);

  const Buffer& recovered = extractContent.getPayload();
  Buffer decrypted = Rsa::decrypt(dKey.buf(), dKey.size(), recovered.buf(), recovered.size(), encryptParams);
  BOOST_CHECK_EQUAL_COLLECTIONS(raw_content, raw_content + sizeof(raw_content),
                                decrypted.begin(), decrypted.end());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(ContentAsymmetricEncryptLarge, T, EncryptorRsaTestInputs)
{
  T type;

  const uint8_t large_content[] = {
    0x73, 0x5a, 0xbd, 0x47, 0x0c, 0xfe, 0xf8, 0x7d,
    0x2e, 0x17, 0xaa, 0x11, 0x6f, 0x23, 0xc5, 0x10,
    0x23, 0x36, 0x88, 0xc4, 0x2a, 0x0f, 0x9a, 0x72,
    0x54, 0x31, 0xa8, 0xb3, 0x51, 0x18, 0x9f, 0x0e,
    0x1b, 0x93, 0x62, 0xd9, 0xc4, 0xf5, 0xf4, 0x3d,
    0x61, 0x9a, 0xca, 0x05, 0x65, 0x6b, 0xc6, 0x41,
    0xf9, 0xd5, 0x1c, 0x67, 0xc1, 0xd0, 0xd5, 0x6f,
    0x7b, 0x70, 0xb8, 0x8f, 0xdb, 0x19, 0x68, 0x7c,
    0xe0, 0x2d, 0x04, 0x49, 0xa9, 0xa2, 0x77, 0x4e,
    0xfc, 0x60, 0x0d, 0x7c, 0x1b, 0x93, 0x6c, 0xd2,
    0x61, 0xc4, 0x6b, 0x01, 0xe9, 0x12, 0x28, 0x6d,
    0xf5, 0x78, 0xe9, 0x99, 0x0b, 0x9c, 0x4f, 0x90,
    0x34, 0x3e, 0x06, 0x92, 0x57, 0xe3, 0x7a, 0x8f,
    0x13, 0xc7, 0xf3, 0xfe, 0xf0, 0xe2, 0x59, 0x48,
    0x15, 0xb9, 0xdb, 0x77, 0x07, 0x1d, 0x6d, 0xb5,
    0x65, 0x17, 0xdf, 0x76, 0x6f, 0xb5, 0x43, 0xde,
    0x71, 0xac, 0xf1, 0x22, 0xbf, 0xb2, 0xe5, 0xd9,
    0x22, 0xf1, 0x67, 0x76, 0x71, 0x0c, 0xff, 0x99,
    0x7b, 0x94, 0x9b, 0x24, 0x20, 0x80, 0xe3, 0xcc,
    0x06, 0x4a, 0xed, 0xdf, 0xec, 0x50, 0xd5, 0x87,
    0x3d, 0xa0, 0x7d, 0x9c, 0xe5, 0x13, 0x10, 0x98,
    0x14, 0xc3, 0x90, 0x10, 0xd9, 0x25, 0x9a, 0x59,
    0xe9, 0x37, 0x26, 0xfd, 0x87, 0xd7, 0xf4, 0xf9,
    0x11, 0x91, 0xad, 0x5c, 0x00, 0x95, 0xf5, 0x2b,
    0x37, 0xf7, 0x4e, 0xb4, 0x4b, 0x42, 0x7c, 0xb3,
    0xad, 0xd6, 0x33, 0x5f, 0x0b, 0x84, 0x57, 0x7f,
    0xa7, 0x07, 0x73, 0x37, 0x4b, 0xab, 0x2e, 0xfb,
    0xfe, 0x1e, 0xcb, 0xb6, 0x4a, 0xc1, 0x21, 0x5f,
    0xec, 0x92, 0xb7, 0xac, 0x97, 0x75, 0x20, 0xc9,
    0xd8, 0x9e, 0x93, 0xd5, 0x12, 0x7a, 0x64, 0xb9,
    0x4c, 0xed, 0x49, 0x87, 0x44, 0x5b, 0x4f, 0x90,
    0x34, 0x3e, 0x06, 0x92, 0x57, 0xe3, 0x7a, 0x8f,
    0x13, 0xc7, 0xf3, 0xfe, 0xf0, 0xe2, 0x59, 0x48,
    0x15, 0xb9, 0xdb, 0x77, 0x07, 0x1d, 0x6d, 0xb5,
    0x65, 0x17, 0xdf, 0x76, 0x6f, 0xb5, 0x43, 0xde,
    0x71, 0xac, 0xf1, 0x22, 0xbf, 0xb2, 0xe5, 0xd9
  };

  Data data;
  RandomNumberGenerator rng;
  RsaKeyParams rsaParams(1024);

  Name keyName("test");

  DecryptKey<Rsa> decryptKey = Rsa::generateKey(rng, rsaParams);
  EncryptKey<Rsa> encryptKey = Rsa::deriveEncryptKey(decryptKey.getKeyBits());

  Buffer eKey = encryptKey.getKeyBits();
  Buffer dKey = decryptKey.getKeyBits();

  EncryptParams encryptParams(type.type);
  encryptData(data, large_content, sizeof(large_content),
              keyName, eKey.buf(), eKey.size(), encryptParams);

  BOOST_CHECK_EQUAL(data.getName(), Name("/FOR").append(keyName));

  Block largeDataContent = data.getContent();
  largeDataContent.parse();
  BOOST_CHECK_EQUAL(largeDataContent.elements_size(), 2);

  Block::element_const_iterator it = largeDataContent.elements_begin();

  BOOST_CHECK(it != largeDataContent.elements_end());
  Block nonceContent(*it);
  BOOST_CHECK_EQUAL(nonceContent.type(), tlv::EncryptedContent);
  EncryptedContent encryptedNonce(nonceContent);
  BOOST_CHECK_EQUAL(encryptedNonce.getKeyLocator().getName(), keyName);
  BOOST_CHECK_EQUAL(encryptedNonce.getInitialVector().size(), 0);
  BOOST_CHECK_EQUAL(encryptedNonce.getAlgorithmType(), type.type);

  it++;
  BOOST_CHECK(it != largeDataContent.elements_end());
  Block payloadContent(*it);
  BOOST_CHECK_EQUAL(payloadContent.type(), tlv::EncryptedContent);
  EncryptedContent encryptedPayload(payloadContent);
  Name nonceKeyName = keyName.append("nonce");
  BOOST_CHECK_EQUAL(encryptedPayload.getKeyLocator().getName(), nonceKeyName);
  BOOST_CHECK_EQUAL(encryptedPayload.getInitialVector().size(), 16);
  BOOST_CHECK_EQUAL(encryptedPayload.getAlgorithmType(), tlv::AlgorithmAesCbc);

  it++;
  BOOST_CHECK(it == largeDataContent.elements_end());

  const Buffer& bufferNonce = encryptedNonce.getPayload();
  Buffer nonce = Rsa::decrypt(dKey.buf(), dKey.size(), bufferNonce.buf(), bufferNonce.size(), encryptParams);

  encryptParams.setAlgorithmType(tlv::AlgorithmAesCbc);
  encryptParams.setIV(encryptedPayload.getInitialVector().buf(), encryptedPayload.getInitialVector().size());
  const Buffer& bufferPayload = encryptedPayload.getPayload();
  Buffer largePayload = Aes::decrypt(nonce.buf(), nonce.size(), bufferPayload.buf(), bufferPayload.size(), encryptParams);

  BOOST_CHECK_EQUAL_COLLECTIONS(large_content, large_content + sizeof(large_content),
                                largePayload.begin(), largePayload.end());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace algo
} // namespace tests
} // namespace gep
} // namespace ndn
