/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2018,  Regents of the University of California
 *
 * This file is part of gep (Group-based Encryption Protocol for NDN).
 * See AUTHORS.md for complete list of gep authors and contributors.
 *
 * gep is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * gep is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * gep, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_ENCRYPTED_CONTENT_HPP
#define NDN_ENCRYPTED_CONTENT_HPP

#include "tlv.hpp"
#include <list>
#include <ndn-cxx/encoding/tlv.hpp>
#include <ndn-cxx/key-locator.hpp>

namespace ndn {
namespace gep {

class EncryptedContent
{
public:
  class Error : public ndn::tlv::Error
  {
  public:
    explicit Error(const std::string& what)
      : ndn::tlv::Error(what)
    {
    }
  };

public:
  EncryptedContent();

  EncryptedContent(tlv::AlgorithmTypeValue type,
                   const KeyLocator& keyLocator,
                   const uint8_t* payload,
                   size_t payloadLen,
                   const uint8_t* iv = 0,
                   size_t ivLen = 0);

  explicit EncryptedContent(const Block& block);

  void
  setAlgorithmType(tlv::AlgorithmTypeValue type);

  int32_t
  getAlgorithmType() const
  {
    return m_type;
  }

  bool
  hasKeyLocator() const
  {
    return m_hasKeyLocator;
  }

  void
  setKeyLocator(const KeyLocator& keyLocator);

  const KeyLocator&
  getKeyLocator() const;

  void
  setInitialVector(const uint8_t* iv, size_t ivLen);

  const Buffer&
  getInitialVector() const;

  void
  setPayload(const uint8_t* payload, size_t payloadLen);

  const Buffer&
  getPayload() const;

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
  int32_t m_type;
  bool m_hasKeyLocator;
  KeyLocator m_keyLocator;
  Buffer m_payload;
  Buffer m_iv;

  mutable Block m_wire;
};

} // namespace gep
} // namespace ndn

#endif // NDN_ENCRYPTED_CONTENT_HPP
