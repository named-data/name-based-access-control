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

#include "../random-number-generator.hpp"
#include "encrypt-params.hpp"

namespace ndn {
namespace gep {
namespace algo {

EncryptParams::EncryptParams(tlv::AlgorithmTypeValue algorithm, uint8_t ivLength)
  : m_algo(algorithm)
{
  if (ivLength != 0){
    RandomNumberGenerator rng;
    m_iv.resize(ivLength);
    rng.GenerateBlock(m_iv.buf(), m_iv.size());
  }
}

void
EncryptParams::setIV(const uint8_t* iv, size_t ivLen)
{
  m_iv = Buffer(iv, ivLen);
}

void
EncryptParams::setAlgorithmType(tlv::AlgorithmTypeValue algorithm)
{
  m_algo = algorithm;
}

Buffer
EncryptParams::getIV() const
{
  return m_iv;
}

tlv::AlgorithmTypeValue
EncryptParams::getAlgorithmType() const
{
  return m_algo;
}

} // namespace algo
} // namespace gep
} // namespace ndn
