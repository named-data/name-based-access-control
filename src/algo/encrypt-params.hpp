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
 */

#ifndef NDN_GEP_ENCRYPT_PARAMS_HPP
#define NDN_GEP_ENCRYPT_PARAMS_HPP

#include "../tlv.hpp"
#include <ndn-cxx/encoding/buffer-stream.hpp>

namespace ndn {
namespace gep {
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
} // namespace gep
} // namespace ndn

#endif // NDN_GEP_ENCRYPT_PARAMS_HPP
