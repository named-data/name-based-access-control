/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2020, Regents of the University of California
 *
 * NAC library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * NAC library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of NAC library authors and contributors.
 */

#include "encrypted-content.hpp"

#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/util/concepts.hpp>
#include <ndn-cxx/util/exception.hpp>

namespace ndn {
namespace nac {

BOOST_CONCEPT_ASSERT((boost::EqualityComparable<EncryptedContent>));
BOOST_CONCEPT_ASSERT((WireEncodable<EncryptedContent>));
BOOST_CONCEPT_ASSERT((WireDecodable<EncryptedContent>));
static_assert(std::is_base_of<ndn::tlv::Error, EncryptedContent::Error>::value,
              "EncryptedContent::Error must inherit from tlv::Error");

EncryptedContent::EncryptedContent(const Block& block)
{
  wireDecode(block);
}

EncryptedContent&
EncryptedContent::setPayload(Block payload)
{
  m_wire.reset();
  if (payload.type() != tlv::EncryptedPayload) {
    m_payload = Block(tlv::EncryptedPayload, std::move(payload));
  }
  else {
    m_payload = std::move(payload);
  }
  return *this;
}

EncryptedContent&
EncryptedContent::setPayload(ConstBufferPtr payload)
{
  m_wire.reset();
  m_payload = Block(tlv::EncryptedPayload, std::move(payload));
  return *this;
}

EncryptedContent&
EncryptedContent::setIv(Block iv)
{
  m_wire.reset();
  if (iv.type() != tlv::InitializationVector) {
    m_iv = Block(tlv::InitializationVector, std::move(iv));
  }
  else {
    m_iv = std::move(iv);
  }
  return *this;
}

EncryptedContent&
EncryptedContent::setIv(ConstBufferPtr iv)
{
  m_wire.reset();
  m_iv = Block(tlv::InitializationVector, iv);
  return *this;
}

EncryptedContent&
EncryptedContent::unsetIv()
{
  m_wire.reset();
  m_iv = Block();
  return *this;
}

EncryptedContent&
EncryptedContent::setPayloadKey(Block key)
{
  m_wire.reset();
  if (key.type() != tlv::EncryptedPayloadKey) {
    m_payloadKey = Block(tlv::EncryptedPayloadKey, std::move(key));
  }
  else {
    m_payloadKey = std::move(key);
  }
  return *this;
}

EncryptedContent&
EncryptedContent::setPayloadKey(ConstBufferPtr key)
{
  m_wire.reset();
  m_payloadKey = Block(tlv::EncryptedPayloadKey, std::move(key));
  return *this;
}

EncryptedContent&
EncryptedContent::unsetPayloadKey()
{
  m_wire.reset();
  m_payloadKey = Block();
  return *this;
}

EncryptedContent&
EncryptedContent::setKeyLocator(Name keyLocator)
{
  m_wire.reset();
  m_keyLocator = std::move(keyLocator);
  return *this;
}

EncryptedContent&
EncryptedContent::unsetKeyLocator()
{
  m_wire.reset();
  m_keyLocator = Name();
  return *this;
}

template<encoding::Tag TAG>
size_t
EncryptedContent::wireEncode(EncodingImpl<TAG>& block) const
{
  size_t totalLength = 0;

  if (hasKeyLocator()) {
    totalLength += m_keyLocator.wireEncode(block);
  }

  if (hasPayloadKey()) {
    totalLength += block.prependBlock(m_payloadKey);
  }

  if (hasIv()) {
    totalLength += block.prependBlock(m_iv);
  }

  if (m_payload.isValid()) {
    totalLength += block.prependBlock(m_payload);
  }
  else {
    NDN_THROW(Error("Required EncryptedPayload is not set on EncryptedContent"));
  }

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
    NDN_THROW(Error("The supplied block does not contain wire format"));
  }

  m_payload.reset();
  m_iv.reset();
  m_payloadKey.reset();

  m_wire = wire;
  m_wire.parse();

  if (m_wire.type() != tlv::EncryptedContent) {
    NDN_THROW(Error("Unexpected TLV type (expecting EncryptedContent, got " +
                    ndn::to_string(m_wire.type()) + ")"));
  }

  auto block = m_wire.find(tlv::EncryptedPayload);
  if (block != m_wire.elements_end()) {
    m_payload = *block;
  }
  else {
    NDN_THROW(Error("Required EncryptedPayload not found in EncryptedContent"));
  }

  block = m_wire.find(tlv::InitializationVector);
  if (block != m_wire.elements_end()) {
    m_iv = *block;
  }

  block = m_wire.find(tlv::EncryptedPayloadKey);
  if (block != m_wire.elements_end()) {
    m_payloadKey = *block;
  }

  block = m_wire.find(tlv::Name);
  if (block != m_wire.elements_end()) {
    m_keyLocator.wireDecode(*block);
  }
}

bool
EncryptedContent::operator==(const EncryptedContent& rhs) const
{
  return wireEncode() == rhs.wireEncode();
}

} // namespace nac
} // namespace ndn
