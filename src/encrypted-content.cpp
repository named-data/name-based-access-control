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
 *
 * @author Yingdi Yu <yingdi@cs.ucla.edu>
 * @author Zhiyi Zhang <zhiyi@cs.ucla.edu>
 */

#include "encrypted-content.hpp"
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/util/concepts.hpp>
#include <boost/lexical_cast.hpp>

namespace ndn {
namespace nac {

BOOST_CONCEPT_ASSERT((boost::EqualityComparable<EncryptedContent>));
BOOST_CONCEPT_ASSERT((WireEncodable<EncryptedContent>));
BOOST_CONCEPT_ASSERT((WireDecodable<EncryptedContent>));
static_assert(std::is_base_of<ndn::tlv::Error, EncryptedContent::Error>::value,
              "EncryptedContent::Error must inherit from tlv::Error");

EncryptedContent::EncryptedContent()
  : m_type(-1)
  , m_hasKeyLocator(false)
{
}

EncryptedContent::EncryptedContent(tlv::AlgorithmTypeValue type,
                                   const KeyLocator& keyLocator,
                                   const uint8_t* payload,
                                   size_t payloadLen,
                                   const uint8_t* iv,
                                   size_t ivLen)
  : m_type(type)
  , m_hasKeyLocator(true)
  , m_keyLocator(keyLocator)
  , m_payload(payload, payloadLen)
{
  if (iv != nullptr && ivLen != 0)
    m_iv = Buffer(iv, ivLen);
}

EncryptedContent::EncryptedContent(const Block& block)
{
  wireDecode(block);
}

void
EncryptedContent::setAlgorithmType(tlv::AlgorithmTypeValue type)
{
  m_wire.reset();
  m_type = type;
}

void
EncryptedContent::setKeyLocator(const KeyLocator& keyLocator)
{
  m_wire.reset();
  m_keyLocator = keyLocator;
  m_hasKeyLocator = true;
}

const KeyLocator&
EncryptedContent::getKeyLocator() const
{
  if (m_hasKeyLocator)
    return m_keyLocator;
  else
    BOOST_THROW_EXCEPTION(Error("KeyLocator does not exist"));
}

void
EncryptedContent::setInitialVector(const uint8_t* iv, size_t ivLen)
{
  m_wire.reset();
  m_iv = Buffer(iv, ivLen);
}

const Buffer&
EncryptedContent::getInitialVector() const
{
  return m_iv;
}

void
EncryptedContent::setPayload(const uint8_t* payload, size_t payloadLen)
{
  m_wire.reset();
  m_payload = Buffer(payload, payloadLen);
}

const Buffer&
EncryptedContent::getPayload() const
{
  return m_payload;
}

template<encoding::Tag TAG>
size_t
EncryptedContent::wireEncode(EncodingImpl<TAG>& block) const
{
  size_t totalLength = 0;

  if (m_payload.size() != 0)
    totalLength +=
      block.prependByteArrayBlock(tlv::EncryptedPayload, m_payload.data(), m_payload.size());
  else
    BOOST_THROW_EXCEPTION(Error("EncryptedContent does not have a payload"));

  if (m_iv.size() != 0) {
    totalLength += block.prependByteArrayBlock(tlv::InitialVector, m_iv.data(), m_iv.size());
  }

  if (m_type != -1)
    totalLength += prependNonNegativeIntegerBlock(block, tlv::EncryptionAlgorithm, m_type);
  else
    BOOST_THROW_EXCEPTION(Error("EncryptedContent does not have an encryption algorithm"));

  if (m_hasKeyLocator)
    totalLength += m_keyLocator.wireEncode(block);
  else
    BOOST_THROW_EXCEPTION(Error("EncryptedContent does not have a key locator"));

  totalLength += block.prependVarNumber(totalLength);
  totalLength += block.prependVarNumber(tlv::EncryptedContent);
  return totalLength;
}

const Block&
EncryptedContent::wireEncode() const
{
  if (m_wire.hasWire())
    return m_wire;

  EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  m_wire = buffer.block();
  return m_wire;
}

void
EncryptedContent::wireDecode(const Block& wire)
{
  if (!wire.hasWire()) {
    BOOST_THROW_EXCEPTION(Error("The supplied block does not contain wire format"));
  }

  m_hasKeyLocator = false;

  m_wire = wire;
  m_wire.parse();

  if (m_wire.type() != tlv::EncryptedContent)
    BOOST_THROW_EXCEPTION(Error("Unexpected TLV type when decoding Name"));

  Block::element_const_iterator it = m_wire.elements_begin();

  if (it != m_wire.elements_end() && it->type() == ndn::tlv::KeyLocator) {
    m_keyLocator.wireDecode(*it);
    m_hasKeyLocator = true;
    it++;
  }
  else
    BOOST_THROW_EXCEPTION(Error("EncryptedContent does not have key locator"));

  if (it != m_wire.elements_end() && it->type() == tlv::EncryptionAlgorithm) {
    m_type = readNonNegativeInteger(*it);
    it++;
  }
  else
    BOOST_THROW_EXCEPTION(Error("EncryptedContent does not have encryption algorithm"));

  if (it != m_wire.elements_end() && it->type() == tlv::InitialVector) {
    m_iv = Buffer(it->value_begin(), it->value_end());
    it++;
  }
  else
    m_iv = Buffer();

  if (it != m_wire.elements_end() && it->type() == tlv::EncryptedPayload) {
    m_payload = Buffer(it->value_begin(), it->value_end());
    it++;
  }
  else
    BOOST_THROW_EXCEPTION(Error("EncryptedContent has missing payload"));

  if (it != m_wire.elements_end()) {
    BOOST_THROW_EXCEPTION(Error("EncryptedContent has extraneous sub-TLVs"));
  }
}

bool
EncryptedContent::operator==(const EncryptedContent& rhs) const
{
  return (wireEncode() == rhs.wireEncode());
}

} // namespace nac
} // namespace ndn
