/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2018, Regents of the University of California
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

#ifndef NDN_NAC_ENCRYPTED_CONTENT_HPP
#define NDN_NAC_ENCRYPTED_CONTENT_HPP

#include "common.hpp"

#include <ndn-cxx/encoding/tlv.hpp>

namespace ndn {
namespace nac {

/**
 * @brief Encrypted content
 *
 * <code>
 *     EncryptedContent ::= ENCRYPTED-CONTENT-TYPE TLV-LENGTH
 *                            InitialVector
 *                            EncryptedPayload
 *                            EncryptedPayloadKey
 *                            Name
 *
 *     InitialVector ::= INITIAL-VECTOR-TYPE TLV-LENGTH(=N) BYTE{N}
 *     EncryptedPayload ::= ENCRYPTED-PAYLOAD-TYPE TLV-LENGTH(=N) BYTE{N}
 *     EncryptedPayloadKey ::= ENCRYPTED-PAYLOAD-KEY-TYPE TLV-LENGTH(=N) BYTE{N}
 *     InitialVector ::= INITIAL-VECTOR-TYPE TLV-LENGTH(=N) BYTE{N}
 * </code>
 */
class EncryptedContent
{
public:
  class Error : public ndn::tlv::Error
  {
  public:
    using ndn::tlv::Error::Error;
  };

public:
  EncryptedContent() = default;

  explicit
  EncryptedContent(const Block& block);

  const Block&
  getPayload() const
  {
    return m_payload;
  }

  EncryptedContent&
  setPayload(Block payload);

  EncryptedContent&
  setPayload(ConstBufferPtr payload);

  bool
  hasIv() const
  {
    return !m_iv.empty();
  }

  const Block&
  getIv() const
  {
    return m_iv;
  }

  EncryptedContent&
  unsetIv();

  EncryptedContent&
  setIv(Block iv);

  EncryptedContent&
  setIv(ConstBufferPtr iv);

  bool
  hasPayloadKey() const
  {
    return !m_payloadKey.empty();
  }

  const Block&
  getPayloadKey() const
  {
    return m_payloadKey;
  }

  EncryptedContent&
  setPayloadKey(Block key);

  EncryptedContent&
  setPayloadKey(ConstBufferPtr key);

  EncryptedContent&
  unsetPayloadKey();

  bool
  hasKeyLocator() const
  {
    return !m_keyLocator.empty();
  }

  const Name&
  getKeyLocator() const
  {
    return m_keyLocator;
  }

  EncryptedContent&
  setKeyLocator(Name keyLocator);

  EncryptedContent&
  unsetKeyLocator();

  template<encoding::Tag TAG>
  size_t
  wireEncode(EncodingImpl<TAG>& block) const;

  const Block&
  wireEncode() const;

  void
  wireDecode(const Block& wire);

public:
  bool
  operator==(const EncryptedContent& rhs) const;

  bool
  operator!=(const EncryptedContent& rhs) const
  {
    return !(*this == rhs);
  }

private:
  Block m_iv;
  Block m_payload;
  Block m_payloadKey; ///< for public key encryption, public key encodes a random key that is used
                      ///< for symmetric encryption of the content
  Name m_keyLocator;

  mutable Block m_wire;
};

} // namespace nac
} // namespace ndn

#endif // NDN_NAC_ENCRYPTED_CONTENT_HPP
