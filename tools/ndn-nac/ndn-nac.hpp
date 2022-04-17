/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2022, Regents of the University of California
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

#ifndef NAC_TOOLS_NDN_NAC_NDN_NAC_HPP
#define NAC_TOOLS_NDN_NAC_NDN_NAC_HPP

#include "common.hpp"

#include <iostream>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>

#include <ndn-cxx/util/dummy-client-face.hpp>
#include <ndn-cxx/util/exception.hpp>
#include <ndn-cxx/util/io.hpp>

namespace ndn::nac {

int
nac_dump_kek(int argc, char** argv);

int
nac_add_member(int argc, char** argv);

inline Certificate
loadCertificate(const std::string& fileName)
{
  try {
    if (fileName == "-") {
      return io::loadTlv<Certificate>(std::cin, io::BASE64);
    }

    std::ifstream file(fileName);
    if (!file) {
      NDN_THROW(std::runtime_error("Cannot open '" + fileName + "'"));
    }
    return io::loadTlv<Certificate>(file, io::BASE64);
  }
  catch (const io::Error& e) {
    NDN_THROW_NESTED(std::runtime_error("Cannot load certificate from '" + fileName +
                                        "': malformed TLV or not in base64 format (" + e.what() + ")"));
  }
}

} // namespace ndn::nac

#endif // NAC_TOOLS_NDN_NAC_NDN_NAC_HPP
