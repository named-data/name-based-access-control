/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
* Copyright (c) 2013-2014 Regents of the University of California.
*
* This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
*
* ndn-cxx library is free software: you can redistribute it and/or modify it under the
* terms of the GNU Lesser General Public License as published by the Free Software
* Foundation, either version 3 of the License, or (at your option) any later version.
*
* ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
* PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
*
* You should have received copies of the GNU General Public License and GNU Lesser
* General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
* <http://www.gnu.org/licenses/>.
*
* See AUTHORS.md for complete list of ndn-cxx authors and contributors.
*/

#ifndef NDN_GEP_TLV_HPP
#define NDN_GEP_TLV_HPP

namespace ndn {
namespace gep {
namespace tlv {

enum {
  EncryptedContent = 130,
  EncryptionAlgorithm = 131,
  EncryptedPayload = 132,
  InitialVector = 133,

  // for repetitive interval
  StartDate = 134,
  EndDate = 135,
  IntervalStartHour = 136,
  IntervalEndHour = 137,
  NRepeats = 138,
  RepeatUnit = 139,
  RepetitiveInterval = 140,

  // for schedule
  WhiteIntervalList = 141,
  BlackIntervalList = 142,
  Schedule = 143
};

enum AlgorithmTypeValue {
  AlgorithmAesEcb = 0,
  AlgorithmAesCbc = 1,
  AlgorithmRsaPkcs = 2,
  AlgorithmRsaOaep = 3
};

} // namespace tlv
} // namespace gep
} // namespace ndn

#endif // NDN_GEP_TLV_HPP
