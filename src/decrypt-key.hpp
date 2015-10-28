/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2015,  Regents of the University of California
 *
 * This file is part of ndn-group-encrypt (Group-based Encryption Protocol for NDN).
 * See AUTHORS.md for complete list of ndn-group-encrypt authors and contributors.
 *
 * ndn-group-encrypt is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-group-encrypt is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndn-group-encrypt, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NDN_GEP_DECRYPT_KEY_HPP
#define NDN_GEP_DECRYPT_KEY_HPP

#include "encrypt-key.hpp"

namespace ndn {
namespace gep {

template<class Algorithm>
class DecryptKey
{
public:
  DecryptKey(Buffer&& keyBits)
    : m_keyBits(keyBits)
  {
  }

  EncryptKey<Algorithm>
  deriveEncryptKey()
  {
    return Algorithm::deriveEncryptKey(m_keyBits);
  }

  Buffer
  decrypt(const Buffer& encryptedData)
  {
    return Algorithm::decrypt(m_keyBits, encryptedData);
  }

  const Buffer&
  getKeyBits() const
  {
    return m_keyBits;
  }

private:
  Buffer m_keyBits;
};

} // namespace gep
} // namespace ndn

#endif // NDN_GEP_DECRYPT_KEY_HPP
