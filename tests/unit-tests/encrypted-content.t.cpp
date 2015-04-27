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

#include "encrypted-content.hpp"

#include "boost-test.hpp"
#include <algorithm>

namespace ndn {
namespace gep {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestEncryptedContent)

const uint8_t encrypted[] = {
0x82, 0x24, // EncryptedContent
  0x1c, 0x16, // KeyLocator
    0x07, 0x14, // Name
      0x08, 0x04,
        0x74, 0x65, 0x73, 0x74, // 'test'
      0x08, 0x03,
        0x6b, 0x65, 0x79, // 'key'
      0x08, 0x07,
        0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, // 'locator'
  0x83, 0x01, // EncryptedAlgorithm
    0x00,
  0x84, 0x07, // EncryptedPayload
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
};

const uint8_t message[] = {
  0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
};

BOOST_AUTO_TEST_CASE(Constructor)
{
  EncryptedContent content;
  BOOST_CHECK_EQUAL(content.getAlgorithmType(), -1);
  BOOST_CHECK_EQUAL(content.getPayload() == nullptr, true);
  BOOST_CHECK_EQUAL(content.hasKeyLocator(), false);
  BOOST_CHECK_THROW(content.getKeyLocator(), EncryptedContent::Error);

  ConstBufferPtr payload = make_shared<Buffer>(message, sizeof(message));
  KeyLocator keyLocator("test/key/locator");
  EncryptedContent sha256RsaContent(tlv::AlgorithmSha256WithRsa, keyLocator, payload);
  ConstBufferPtr contentPayload = sha256RsaContent.getPayload();

  BOOST_CHECK_EQUAL(sha256RsaContent.getAlgorithmType(), tlv::AlgorithmSha256WithRsa);
  BOOST_CHECK_EQUAL_COLLECTIONS(contentPayload->begin(),
                                contentPayload->end(),
                                payload->begin(),
                                payload->end());
  BOOST_CHECK_EQUAL(sha256RsaContent.hasKeyLocator(), true);
  BOOST_CHECK_NO_THROW(sha256RsaContent.getKeyLocator());
  BOOST_CHECK_EQUAL(sha256RsaContent.getKeyLocator().getName(), Name("test/key/locator"));

  Block encryptedBlock(encrypted, sizeof(encrypted));
  const Block& encoded = sha256RsaContent.wireEncode();

  BOOST_CHECK_EQUAL_COLLECTIONS(encryptedBlock.wire(),
                                encryptedBlock.wire() + encryptedBlock.size(),
                                encoded.wire(),
                                encoded.wire() + encoded.size());

  sha256RsaContent = EncryptedContent(encryptedBlock);
  contentPayload = sha256RsaContent.getPayload();

  BOOST_CHECK_EQUAL(sha256RsaContent.getAlgorithmType(), tlv::AlgorithmSha256WithRsa);
  BOOST_CHECK_EQUAL(sha256RsaContent.hasKeyLocator(), true);
  BOOST_CHECK_EQUAL_COLLECTIONS(contentPayload->begin(),
                                contentPayload->end(),
                                payload->begin(),
                                payload->end());
  BOOST_CHECK_NO_THROW(sha256RsaContent.getKeyLocator());
  BOOST_CHECK_EQUAL(sha256RsaContent.getKeyLocator().getName(), Name("test/key/locator"));
}

BOOST_AUTO_TEST_CASE(ConstructorError)
{
  const uint8_t error1[] = {
    0x1f, 0x24, // Wrong EncryptedContent (0x82, 0x24)
      0x1c, 0x16, // KeyLocator
        0x07, 0x14, // Name
          0x08, 0x04,
            0x74, 0x65, 0x73, 0x74,
          0x08, 0x03,
            0x6b, 0x65, 0x79,
          0x08, 0x07,
            0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
      0x83, 0x01, // EncryptedAlgorithm
        0x00,
      0x84, 0x07, // EncryptedPayload
        0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
  };
  Block errorBlock1(error1, sizeof(error1));
  BOOST_CHECK_THROW(EncryptedContent info(errorBlock1), EncryptedContent::Error);

  const uint8_t error2[] = {
    0x82, 0x24, // EncryptedContent
      0x1d, 0x16, // Wrong KeyLocator (0x1c, 0x16)
        0x07, 0x14, // Name
          0x08, 0x04,
            0x74, 0x65, 0x73, 0x74,
          0x08, 0x03,
            0x6b, 0x65, 0x79,
          0x08, 0x07,
            0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
      0x83, 0x01, // EncryptedAlgorithm
        0x00,
      0x84, 0x07, // EncryptedPayload
        0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
  };
  Block errorBlock2(error2, sizeof(error2));
  BOOST_CHECK_THROW(EncryptedContent info(errorBlock2), EncryptedContent::Error);

  const uint8_t error3[] = {
    0x82, 0x24, // EncryptedContent
      0x1c, 0x16, // KeyLocator
        0x07, 0x14, // Name
          0x08, 0x04,
            0x74, 0x65, 0x73, 0x74,
          0x08, 0x03,
            0x6b, 0x65, 0x79,
          0x08, 0x07,
            0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
      0x1d, 0x01, // Wrong EncryptedAlgorithm (0x83, 0x01)
        0x00,
      0x84, 0x07, // EncryptedPayload
        0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
  };
  Block errorBlock3(error3, sizeof(error3));
  BOOST_CHECK_THROW(EncryptedContent info(errorBlock3), EncryptedContent::Error);

  const uint8_t error4[] = {
    0x82, 0x24, // EncryptedContent
      0x1c, 0x16, // KeyLocator
        0x07, 0x14, // Name
          0x08, 0x04,
            0x74, 0x65, 0x73, 0x74, // 'test'
          0x08, 0x03,
            0x6b, 0x65, 0x79, // 'key'
          0x08, 0x07,
            0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, // 'locator'
      0x83, 0x01, // EncryptedAlgorithm
        0x00,
      0x21, 0x07, // EncryptedPayload (0x84, 0x07)
        0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
  };
  Block errorBlock4(error4, sizeof(error4));
  BOOST_CHECK_THROW(EncryptedContent info(errorBlock4), EncryptedContent::Error);

  const uint8_t error5[] = {
    0x82, 0x00 // Empty EncryptedContent
  };
  Block errorBlock5(error5, sizeof(error5));
  BOOST_CHECK_THROW(EncryptedContent info(errorBlock5), EncryptedContent::Error);
}

BOOST_AUTO_TEST_CASE(SetterGetter)
{
  EncryptedContent content;
  BOOST_CHECK_EQUAL(content.getAlgorithmType(), -1);
  BOOST_CHECK_EQUAL(content.getPayload() == nullptr, true);
  BOOST_CHECK_EQUAL(content.hasKeyLocator(), false);
  BOOST_CHECK_THROW(content.getKeyLocator(), EncryptedContent::Error);

  content.setAlgorithmType(tlv::AlgorithmSha256WithRsa);
  BOOST_CHECK_EQUAL(content.getAlgorithmType(), tlv::AlgorithmSha256WithRsa);
  BOOST_CHECK_EQUAL(content.getPayload() == nullptr, true);
  BOOST_CHECK_EQUAL(content.hasKeyLocator(), false);

  KeyLocator keyLocator("/test/key/locator");
  content.setKeyLocator(keyLocator);
  BOOST_CHECK_EQUAL(content.hasKeyLocator(), true);
  BOOST_CHECK_NO_THROW(content.getKeyLocator());
  BOOST_CHECK_EQUAL(content.getKeyLocator().getName(), Name("/test/key/locator"));
  BOOST_CHECK_EQUAL(content.getPayload() == nullptr, true);

  ConstBufferPtr payload = make_shared<Buffer>(message, sizeof(message));
  content.setPayload(payload);

  ConstBufferPtr contentPayload = content.getPayload();
  BOOST_CHECK_EQUAL_COLLECTIONS(contentPayload->begin(),
                                contentPayload->end(),
                                payload->begin(),
                                payload->end());

  const Block& encoded = content.wireEncode();
  Block contentBlock(encrypted, sizeof(encrypted));

  BOOST_CHECK_EQUAL_COLLECTIONS(contentBlock.wire(),
                                contentBlock.wire() + contentBlock.size(),
                                encoded.wire(),
                                encoded.wire() + encoded.size());
}
BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace gep
} // namespace ndn
