/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2020, Regents of the University of California
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
nac_dump_kek(int argc, char** argv)
{
  namespace po = boost::program_options;

  Name identityName;
  Name datasetName;
  std::string output;

  po::options_description description("General Usage\n"
                                      "  ndn-nac dump-kek [-h] [-o output] [-d dataset] [-i] identity \n"
                                      "General options");
  description.add_options()
    ("help,h", "Produce help message")
    ("output,o", po::value<std::string>(&output), "(Optional) output file, stdout if not specified")
    ("identity,i", po::value<Name>(&identityName), "Data owner's namespace identity")
    ("dataset,d", po::value<Name>(&datasetName), "Name of dataset to control")
    ;

  po::positional_options_description p;
  p.add("identity", 1);

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

  if (vm.count("output") == 0)
    output = "-";

  try {
    KeyChain keyChain;
    Identity id = keyChain.getPib().getIdentity(identityName);

    util::DummyClientFace face(keyChain); // to avoid any real IO
    AccessManager manager(id, datasetName, keyChain, face);

    if (manager.size() != 1) {
      std::cerr << "ERROR: Incorrect state of AccessManager instance (expect 1 KDK)" << std::endl;
      return 2;
    }

    if (output == "-")
      io::save(*manager.begin(), std::cout);
    else
      io::save(*manager.begin(), output);

    return 0;
  }
  catch (const std::runtime_error& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}

} // namespace nac
} // namespace ndn
