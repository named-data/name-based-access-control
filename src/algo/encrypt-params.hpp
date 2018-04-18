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

#ifndef NDN_NAC_ENCRYPT_PARAMS_HPP
#define NDN_NAC_ENCRYPT_PARAMS_HPP

#include "../tlv.hpp"
#include <ndn-cxx/encoding/buffer-stream.hpp>

namespace ndn {
namespace nac {
namespace algo {

class EncryptParams
{
public:
  EncryptParams(tlv::AlgorithmTypeValue algorithm, uint8_t ivLength = 0);

  void
  setIV(const uint8_t* iv, size_t ivLen);

  void
  setAlgorithmType(tlv::AlgorithmTypeValue algorithm);

  Buffer
  getIV() const;

  tlv::AlgorithmTypeValue
  getAlgorithmType() const;

private:
  tlv::AlgorithmTypeValue m_algo;
  Buffer m_iv;
};

} // namespace algo
} // namespace nac
} // namespace ndn

#endif // NDN_NAC_ENCRYPT_PARAMS_HPP
