/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2015,  Regents of the University of California
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
 */

#include "random-number-generator.hpp"
#include "encrypt-params.hpp"

namespace ndn {
namespace gep {
namespace algo {

EncryptParams::EncryptParams(EncryptionMode encryptMode, PaddingScheme paddingScheme, uint8_t ivLength = 0)
  : m_encryptMode(encryptMode)
  , m_paddingScheme(paddingScheme)
{
  if (ivLength != 0){
    RandomNumberGenerator rng;
    m_iv.resize(ivLength);
    rng.GenerateBlock(m_iv.buf(), m_iv.size());
  }
}

void
EncryptParams::setIV(const Buffer& iv)
{
  m_iv = iv;
}

void
EncryptParams::setEncryptMode(const EncryptionMode& encryptMode)
{
  m_encryptMode = encryptMode;
}

void
EncryptParams::setPaddingScheme(const PaddingScheme& paddingScheme)
{
  m_paddingScheme = paddingScheme;
}

Buffer
EncryptParams::getIV() const
{
  return m_iv;
}

EncryptionMode
EncryptParams::getEncryptMode() const
{
  return m_encryptMode;
}

PaddingScheme
EncryptParams::getPaddingScheme() const
{
  return m_paddingScheme;
}

} // namespace algo
} // namespace gep
} // namespace ndn