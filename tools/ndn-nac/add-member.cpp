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

#include "ndn-nac.hpp"
#include "access-manager.hpp"

namespace ndn {
namespace nac {

int
nac_add_member(int argc, char** argv)
{
  namespace po = boost::program_options;

  Name identityName;
  Name datasetName;
  std::string output;
  std::string member;

  po::options_description description("General Usage\n"
                                      "  ndn-nac add-member [-h] [-o output] [-d dataset] [-i] identity [-m] memberCert\n"
                                      "General options");
  description.add_options()
    ("help,h", "Produce help message")
    ("output,o", po::value<std::string>(&output), "(Optional) output file, stdout if not specified")
    ("identity,i", po::value<Name>(&identityName), "Data owner's namespace identity")
    ("dataset,d", po::value<Name>(&datasetName), "Name of dataset to control")
    ("member,m", po::value<std::string>(&member), "File with member's certificate, stdin if -")
    ;

  po::positional_options_description p;
  p.add("identity", 1);
  p.add("member", 1);

  po::variables_map vm;
  try {
    po::store(po::command_line_parser(argc, argv).options(description).positional(p).run(), vm);
    po::notify(vm);
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    std::cerr << description << std::endl;
    return 1;
  }

  if (vm.count("help") != 0) {
    std::cerr << description << std::endl;
    return 0;
  }

  if (vm.count("identity") == 0) {
    std::cerr << "ERROR: identity must be specified" << std::endl;
    std::cerr << description << std::endl;
    return 1;
  }

  if (vm.count("member") == 0) {
    std::cerr << "ERROR: member must be specified" << std::endl;
    std::cerr << description << std::endl;
    return 1;
  }

  if (vm.count("output") == 0)
    output = "-";

  try {
    security::v2::KeyChain keyChain;
    security::Identity id = keyChain.getPib().getIdentity(identityName);

    auto cert = loadCertificate(member);

    util::DummyClientFace face(keyChain); // to avoid any real IO
    AccessManager manager(id, datasetName, keyChain, face);

    auto kdk = manager.addMember(cert);

    if (output == "-")
      io::save(kdk, std::cout);
    else
      io::save(kdk, output);

    return 0;
  }
  catch (const std::runtime_error& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}

} // namespace nac
} // namespace ndn
