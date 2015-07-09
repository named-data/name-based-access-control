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

#include <ndn-cxx/encoding/buffer-stream.hpp>
#include "algo/encrypt-params.hpp"
#include "algo/rsa.hpp"

#include "boost-test.hpp"
#include <algorithm>
#include <string>

using namespace CryptoPP;

namespace ndn {
namespace gep {
namespace algo {
namespace tests {

const std::string privateKey = {
  "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMLY2w1PmsuZNvZ4"
  "rJs1pESLrxF1Xlk9Zg4Sc0r2HIEn/eme8f7cOxXq8OtxIjowEfjceHGvfc7YG1Nw"
  "LDh+ka4Jh6QtYqPEL9GHfrBeufynd0g2PAPVXySBvOJr/Isk+4/Fsj5ihrIPgrQ5"
  "wTBBuLYjDgwPppC/+vddsr5wu5bbAgMBAAECgYBYmRLB8riIa5q6aBTUXofbQ0jP"
  "v3avTWPicjFKnK5JbE3gtQ2Evc+AH9x8smzF2KXTayy5RPsH2uxR/GefKK5EkWbB"
  "mLwWDJ5/QPlLK1STxPs8B/89mp8sZkZ1AxnSHhV/a3dRcK1rVamVcqPMdFyM5PfX"
  "/apL3MlL6bsq2FipAQJBAOp7EJuEs/qAjh8hgyV2acLdsokUEwXH4gCK6+KQW8XS"
  "xFWAG4IbbLfq1HwEpHC2hJSzifCQGoPAxYBRgSK+h6sCQQDUuqF04o06+Qpe4A/W"
  "pWCBGE33+CD4lBtaeoIagsAs/lgcFmXiJZ4+4PhyIORmwFgql9ZDFHSpl8rAYsfk"
  "dz2RAkEAtUKpFe/BybYzJ3Galg0xuMf0ye7QvblExjKeIqiBqS1DRO0hVrSomIxZ"
  "8f0MuWz+lI0t5t8fABa3FnjrINa0vQJBAJeZKNaTXPJZ5/oU0zS0RkG5gFbmjRiY"
  "86VXCMC7zRhDaacajyDKjithR6yNpDdVe39fFWJYgYsakXLo8mruTwECQGqywoy9"
  "epf1flKx4YCCrw+qRKmbkcXWcpFV32EG2K2D1GsxkuXv/b3qO67Uxx1Arxp9o8dl"
  "k34WfzApRjNjho0="
};

const std::string publicKey = {
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDC2NsNT5rLmTb2eKybNaREi68R"
  "dV5ZPWYOEnNK9hyBJ/3pnvH+3DsV6vDrcSI6MBH43Hhxr33O2BtTcCw4fpGuCYek"
  "LWKjxC/Rh36wXrn8p3dINjwD1V8kgbzia/yLJPuPxbI+YoayD4K0OcEwQbi2Iw4M"
  "D6aQv/r3XbK+cLuW2wIDAQAB"
};

const uint8_t plaintext[] = { // plaintext: RSA-Encrypt-Test
  0x52, 0x53, 0x41, 0x2d, 0x45, 0x6e, 0x63, 0x72,
  0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74
};

const uint8_t ciphertext[] = {
  0x33, 0xfb, 0x32, 0xd4, 0x2d, 0x45, 0x75, 0x3f, 0x34, 0xde, 0x3b,
  0xaa, 0x80, 0x5f, 0x74, 0x6f, 0xf0, 0x3f, 0x01, 0x31, 0xdd, 0x2b,
  0x85, 0x02, 0x1b, 0xed, 0x2d, 0x16, 0x1b, 0x96, 0xe5, 0x77, 0xde,
  0xcd, 0x44, 0xe5, 0x3c, 0x32, 0xb6, 0x9a, 0xa9, 0x5d, 0xaa, 0x4b,
  0x94, 0xe2, 0xac, 0x4a, 0x4e, 0xf5, 0x35, 0x21, 0xd0, 0x03, 0x4a,
  0xa7, 0x53, 0xae, 0x13, 0x08, 0x63, 0x38, 0x2c, 0x92, 0xe3, 0x44,
  0x64, 0xbf, 0x33, 0x84, 0x8e, 0x51, 0x9d, 0xb9, 0x85, 0x83, 0xf6,
  0x8e, 0x09, 0xc1, 0x72, 0xb9, 0x90, 0x5d, 0x48, 0x63, 0xec, 0xd0,
  0xcc, 0xfa, 0xab, 0x44, 0x2b, 0xaa, 0xa6, 0xb6, 0xca, 0xec, 0x2b,
  0x5f, 0xbe, 0x77, 0xa5, 0x52, 0xeb, 0x0a, 0xaa, 0xf2, 0x2a, 0x19,
  0x62, 0x80, 0x14, 0x87, 0x42, 0x35, 0xd0, 0xb6, 0xa3, 0x47, 0x4e,
  0xb6, 0x1a, 0x88, 0xa3, 0x16, 0xb2, 0x19
};

BOOST_AUTO_TEST_SUITE(TestRsaAlgorithm)

BOOST_AUTO_TEST_CASE(EncryptionDecryption)
{
  RandomNumberGenerator rng;
  RsaKeyParams params;
  EncryptParams eparams(tlv::AlgorithmRsaOaep);

  OBufferStream privateKeyBuffer, publicKeyBuffer;
  StringSource privPipe(privateKey, true,
                        new Base64Decoder(new FileSink(privateKeyBuffer)));
  StringSource publPipe(publicKey, true,
                        new Base64Decoder(new FileSink(publicKeyBuffer)));

  DecryptKey<Rsa> decryptKey(std::move(*(privateKeyBuffer.buf())));
  EncryptKey<Rsa> encryptKey = Rsa::deriveEncryptKey(decryptKey.getKeyBits());

  const Buffer& encodedPublicKey = *(publicKeyBuffer.buf());
  const Buffer& derivedPublicKey = encryptKey.getKeyBits();
  const Buffer& encodedPrivateKey = *(privateKeyBuffer.buf());
  const Buffer& derivedPrivateKey = decryptKey.getKeyBits();

  BOOST_CHECK_EQUAL_COLLECTIONS(encodedPublicKey.begin(),
                                encodedPublicKey.end(),
                                derivedPublicKey.begin(),
                                derivedPublicKey.end());

  const Buffer& encryptBuf = Rsa::encrypt(encodedPublicKey.buf(), encodedPublicKey.size(),
                                          plaintext, sizeof(plaintext),
                                          eparams);

  const Buffer& recvBuf = Rsa::decrypt(encodedPrivateKey.buf(), encodedPrivateKey.size(),
                                       encryptBuf.buf(), encryptBuf.size(),
                                       eparams);

  BOOST_CHECK_EQUAL_COLLECTIONS(plaintext, plaintext + sizeof(plaintext),
                                recvBuf.begin(), recvBuf.end());

  const Buffer& convBuf = Rsa::decrypt(derivedPrivateKey.buf(), derivedPrivateKey.size(),
                                       ciphertext, sizeof(ciphertext),
                                       eparams);

  BOOST_CHECK_EQUAL_COLLECTIONS(plaintext, plaintext + sizeof(plaintext),
                                convBuf.begin(), convBuf.end());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace algo
} // namespace gep
} // namespace ndn
