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

#include "encrypted-content.hpp"

#include "tests-common.hpp"

#include <iostream>

namespace ndn {
namespace nac {
namespace tests {

class EncryptedContentFixture
{
public:
  EncryptedContentFixture()
  {
    BOOST_CHECK_EQUAL(randomBlock.value_size(), 3);
    BOOST_CHECK_EQUAL(randomBuffer->size(), 10);
  }

public:
  EncryptedContent content;
  Block randomBlock = "01 03 000000"_block;
  ConstBufferPtr randomBuffer = make_shared<Buffer>(10);
};

BOOST_FIXTURE_TEST_SUITE(TestEncryptedContent, EncryptedContentFixture)

BOOST_AUTO_TEST_CASE(Constructor)
{
  BOOST_CHECK_THROW(content.wireEncode(), tlv::Error);
  content.setPayload(randomBlock);

  BOOST_CHECK(!content.hasIv());
  BOOST_CHECK(!content.hasPayloadKey());
  BOOST_CHECK(!content.hasKeyLocator());

  BOOST_CHECK_EQUAL(content.wireEncode(), "82 07 84050103000000"_block);

  content.setIv(randomBlock);
  BOOST_CHECK_EQUAL(content.wireEncode(), "82[0E]=8405010300000085050103000000"_block);

  content.setKeyLocator("/random/name");
  BOOST_CHECK_EQUAL(content.wireEncode(), "82[1E]=8405010300000085050103000000070E080672616E646F6D08046E616D65"_block);

  content = EncryptedContent("82 07 84050103000000"_block);
  BOOST_CHECK(!content.hasIv());
  BOOST_CHECK(!content.hasPayloadKey());
  BOOST_CHECK(!content.hasKeyLocator());

  content = EncryptedContent("82 1E 8505010300000084050103000000070E080672616E646F6D08046E616D65"_block);
  BOOST_CHECK(content.hasIv());
  BOOST_CHECK(!content.hasPayloadKey());
  BOOST_CHECK(content.hasKeyLocator());
}

BOOST_AUTO_TEST_SUITE(SetterGetter)

BOOST_AUTO_TEST_CASE(Iv)
{
  content.setPayload(randomBlock);

  content.setIv(randomBlock);
  BOOST_REQUIRE(content.hasIv());
  BOOST_CHECK_EQUAL(content.getIv().type(), tlv::InitialVector);
  BOOST_CHECK_EQUAL(content.getIv().blockFromValue(), randomBlock);

  content.unsetIv();
  BOOST_CHECK(!content.hasIv());

  content.setIv(randomBuffer);
  BOOST_REQUIRE(content.hasIv());
  BOOST_CHECK_EQUAL(content.getIv().type(), tlv::InitialVector);
  BOOST_CHECK_THROW(content.getIv().blockFromValue(), tlv::Error);
  BOOST_CHECK_EQUAL(content.getIv().value_size(), randomBuffer->size());

  content = EncryptedContent("82[13]=84050103000000850A00000000000000000000"_block);
  BOOST_REQUIRE(content.hasIv());
  BOOST_CHECK_EQUAL(content.getIv().type(), tlv::InitialVector);
  BOOST_CHECK_THROW(content.getIv().blockFromValue(), tlv::Error);
  BOOST_CHECK_EQUAL(content.getIv().value_size(), randomBuffer->size());
}

BOOST_AUTO_TEST_CASE(Payload)
{
  content.setPayload(randomBlock);
  BOOST_CHECK_EQUAL(content.getPayload().type(), tlv::EncryptedPayload);
  BOOST_CHECK_EQUAL(content.getPayload().blockFromValue(), randomBlock);

  content.setPayload(randomBuffer);
  BOOST_CHECK_EQUAL(content.getPayload().type(), tlv::EncryptedPayload);
  BOOST_CHECK_THROW(content.getPayload().blockFromValue(), tlv::Error);
  BOOST_CHECK_EQUAL(content.getPayload().value_size(), randomBuffer->size());

  content = EncryptedContent("82[0C]=840A00000000000000000000"_block);
  BOOST_CHECK_EQUAL(content.getPayload().type(), tlv::EncryptedPayload);
  BOOST_CHECK_THROW(content.getPayload().blockFromValue(), tlv::Error);
  BOOST_CHECK_EQUAL(content.getPayload().value_size(), randomBuffer->size());
}

BOOST_AUTO_TEST_CASE(PayloadKey)
{
  content.setPayload(randomBlock);

  content.setPayloadKey(randomBlock);
  BOOST_REQUIRE(content.hasPayloadKey());
  BOOST_CHECK_EQUAL(content.getPayloadKey().type(), tlv::EncryptedPayloadKey);
  BOOST_CHECK_EQUAL(content.getPayloadKey().blockFromValue(), randomBlock);

  content.unsetPayloadKey();
  BOOST_CHECK(!content.hasPayloadKey());

  content.setPayloadKey(randomBuffer);
  BOOST_REQUIRE(content.hasPayloadKey());
  BOOST_CHECK_EQUAL(content.getPayloadKey().type(), tlv::EncryptedPayloadKey);
  BOOST_CHECK_THROW(content.getPayloadKey().blockFromValue(), tlv::Error);
  BOOST_CHECK_EQUAL(content.getPayloadKey().value_size(), randomBuffer->size());

  content = EncryptedContent("82[13]=84050103000000860A00000000000000000000"_block);
  BOOST_CHECK_EQUAL(content.getPayloadKey().type(), tlv::EncryptedPayloadKey);
  BOOST_CHECK_THROW(content.getPayloadKey().blockFromValue(), tlv::Error);
  BOOST_CHECK_EQUAL(content.getPayloadKey().value_size(), randomBuffer->size());
}

BOOST_AUTO_TEST_CASE(KeyLocator)
{
  content.setPayload(randomBlock);

  content.setKeyLocator("/random/name");
  BOOST_REQUIRE(content.hasKeyLocator());
  BOOST_CHECK_EQUAL(content.getKeyLocator(), "/random/name");

  content.unsetPayloadKey();
  BOOST_CHECK(!content.hasPayloadKey());

  content = EncryptedContent("82[17]=84050103000000070E080672616E646F6D08046E616D65"_block);
  BOOST_REQUIRE(content.hasKeyLocator());
  BOOST_CHECK_EQUAL(content.getKeyLocator(), "/random/name");
}

BOOST_AUTO_TEST_SUITE_END() // SetterGetter

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nac
} // namespace ndn
