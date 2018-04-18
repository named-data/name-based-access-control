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

#include "algo/rsa.hpp"
#include "algo/encrypt-params.hpp"
#include "boost-test.hpp"
#include <ndn-cxx/security/key-params.hpp>
#include <ndn-cxx/security/transform/private-key.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <algorithm>
#include <string>

namespace ndn {
namespace nac {
namespace algo {
namespace tests {

// plaintext: RSA-Encrypt-Test
const uint8_t plainText[] = { 0x52, 0x53, 0x41, 0x2d, 0x45, 0x6e, 0x63, 0x72,
                              0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74};

BOOST_AUTO_TEST_SUITE(TestRsaAlgorithm)

BOOST_AUTO_TEST_CASE(TransformEncryptionDecryption)
{
  RsaKeyParams params;
  auto sKey = security::transform::generatePrivateKey(params);
  security::transform::PublicKey pKey;
  ConstBufferPtr pKeyBits = sKey->derivePublicKey();
  pKey.loadPkcs8(pKeyBits->data(), pKeyBits->size());

  auto cipherText = pKey.encrypt(plainText, sizeof(plainText));
  auto decrypted = sKey->decrypt(cipherText->data(), cipherText->size());
  BOOST_CHECK_EQUAL_COLLECTIONS(plainText, plainText + sizeof(plainText),
                                decrypted->begin(), decrypted->end());
}

BOOST_AUTO_TEST_CASE(EncryptionDecryption)
{
  RsaKeyParams params;
  DecryptKey<Rsa> sKey = Rsa::generateKey(params);
  EncryptKey<Rsa> pKey = Rsa::deriveEncryptKey(sKey.getKeyBits());

  auto cipherText = Rsa::encrypt(pKey.getKeyBits().data(), pKey.getKeyBits().size(),
                                 plainText, sizeof(plainText));
  auto decrypted = Rsa::decrypt(sKey.getKeyBits().data(), sKey.getKeyBits().size(),
                                cipherText.data(), cipherText.size());
  BOOST_CHECK_EQUAL_COLLECTIONS(plainText, plainText + sizeof(plainText),
                                decrypted.begin(), decrypted.end());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace algo
} // namespace nac
} // namespace ndn
