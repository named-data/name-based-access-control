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

#include "algo/aes.hpp"

#include "boost-test.hpp"
#include <algorithm>

namespace ndn {
namespace gep {
namespace algo {
namespace tests {

const uint8_t key[] = {
  0xdd, 0x60, 0x77, 0xec, 0xa9, 0x6b, 0x23, 0x1b,
  0x40, 0x6b, 0x5a, 0xf8, 0x7d, 0x3d, 0x55, 0x32
};

const uint8_t plaintext[] = { // plaintext: AES-Encrypt-Test
  0x41, 0x45, 0x53, 0x2d, 0x45, 0x6e, 0x63, 0x72,
  0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74
};

const uint8_t ciphertext_ecb[] = {
  0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
  0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
  0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
  0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
};

const uint8_t initvector[] = {
  0x6f, 0x53, 0x7a, 0x65, 0x58, 0x6c, 0x65, 0x75,
  0x44, 0x4c, 0x77, 0x35, 0x58, 0x63, 0x78, 0x6e
};

const uint8_t ciphertext_cbc_iv[] = {
  0xb7, 0x19, 0x5a, 0xbb, 0x23, 0xbf, 0x92, 0xb0,
  0x95, 0xae, 0x74, 0xe9, 0xad, 0x72, 0x7c, 0x28,
  0x6e, 0xc6, 0x73, 0xb5, 0x0b, 0x1a, 0x9e, 0xb9,
  0x4d, 0xc5, 0xbd, 0x8b, 0x47, 0x1f, 0x43, 0x00
};

BOOST_AUTO_TEST_SUITE(TestAesAlgorithm)

BOOST_AUTO_TEST_CASE(EncryptionDecryption)
{
  RandomNumberGenerator rng;
  AesKeyParams params;

  EncryptParams eparams(ENCRYPT_MODE_ECB_AES, PADDING_SCHEME_PKCS7, 16);

  DecryptKey<Aes> decryptKey(std::move(Buffer(key, sizeof(key))));
  EncryptKey<Aes> encryptKey = Aes::deriveEncryptKey(decryptKey.getKeyBits());

  Buffer plainBuf(plaintext, sizeof(plaintext));

  Buffer cipherBuf = Aes::encrypt(encryptKey.getKeyBits(), plainBuf, eparams);
  BOOST_CHECK_EQUAL_COLLECTIONS(cipherBuf.begin(),
                                cipherBuf.end(),
                                ciphertext_ecb,
                                ciphertext_ecb + sizeof(ciphertext_ecb));

  Buffer recvBuf = Aes::decrypt(decryptKey.getKeyBits(), cipherBuf, eparams);
  BOOST_CHECK_EQUAL_COLLECTIONS(recvBuf.begin(),
                                recvBuf.end(),
                                plaintext,
                                plaintext + sizeof(plaintext));

  eparams.setEncryptMode(ENCRYPT_MODE_CBC_AES);

  cipherBuf = Aes::encrypt(encryptKey.getKeyBits(), plainBuf, eparams);
  recvBuf = Aes::decrypt(decryptKey.getKeyBits(), cipherBuf, eparams);
  BOOST_CHECK_EQUAL_COLLECTIONS(recvBuf.begin(),
                                recvBuf.end(),
                                plaintext,
                                plaintext + sizeof(plaintext));

  Buffer iv(initvector, 16);
  eparams.setIV(iv);

  cipherBuf = Aes::encrypt(encryptKey.getKeyBits(), plainBuf, eparams);
  BOOST_CHECK_EQUAL_COLLECTIONS(cipherBuf.begin(),
                                cipherBuf.end(),
                                ciphertext_cbc_iv,
                                ciphertext_cbc_iv + sizeof(ciphertext_cbc_iv));

  recvBuf = Aes::decrypt(decryptKey.getKeyBits(), cipherBuf, eparams);
  BOOST_CHECK_EQUAL_COLLECTIONS(recvBuf.begin(),
                                recvBuf.end(),
                                plaintext,
                                plaintext + sizeof(plaintext));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace algo
} // namespace gep
} // namespace ndn
