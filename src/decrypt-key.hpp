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

#ifndef NDN_NAC_DECRYPT_KEY_HPP
#define NDN_NAC_DECRYPT_KEY_HPP

#include "encrypt-key.hpp"

namespace ndn {
namespace nac {

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

} // namespace nac
} // namespace ndn

#endif // NDN_NAC_DECRYPT_KEY_HPP
