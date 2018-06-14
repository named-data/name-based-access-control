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

#include "common.hpp"

namespace ndn {
namespace nac {

Name
convertKekNameToKdkPrefix(const Name& kekName, const ErrorCallback& onFailure)
{
  // * <access-namespace>/KEK/<key-id>  =>>   <access-namespace>/KDK/<key-id>
  if (kekName.size() < 2 || kekName.get(-2) != KEK) {
    onFailure(ErrorCode::KekInvalidName, "Invalid KEK name [" + kekName.toUri() + "]");
    return {};
  }

  return kekName.getPrefix(-2).append(KDK).append(kekName.get(-1));
}

std::tuple<Name, Name, Name>
extractKdkInfoFromCkName(const Name& ckDataName, const Name& ckName, const ErrorCallback& onFailure)
{
  // <full-ck-name-with-id> | /ENCRYPTED-BY/<kek-prefix>/NAC/KEK/<key-id>

  if (ckDataName.size() < ckName.size() + 1 ||
      ckDataName.getPrefix(ckName.size()) != ckName ||
      ckDataName.get(ckName.size()) != ENCRYPTED_BY) {
    onFailure(ErrorCode::CkInvalidName, "Invalid CK name [" + ckDataName.toUri() + "]");
    return {};
  }

  auto kekName = ckDataName.getSubName(ckName.size() + 1);
  return std::make_tuple(convertKekNameToKdkPrefix(kekName, onFailure),
                         kekName.getPrefix(-2),
                         kekName.getPrefix(-2).append("KEY").append(kekName.get(-1)));
}

} // namespace nac
} // namespace ndn
