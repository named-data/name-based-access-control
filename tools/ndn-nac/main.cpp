/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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
#include "version.hpp"

#include <boost/exception/diagnostic_information.hpp>

#include <ndn-cxx/util/logger.hpp>

NDN_LOG_INIT(nac.Cmd);

const char NAC_HELP_TEXT[] = R"STR(
  help         Show all commands
  version      Show version and exit
  dump-kek     Dump KEK
  add-member   Create KDK for the member
)STR";

int
main(int argc, char** argv)
{
  if (argc < 2) {
    std::cerr << NAC_HELP_TEXT << std::endl;
    return 2;
  }

  using namespace ndn::nac;

  std::string command(argv[1]);
  try {
    if (command == "help")              { std::cout << NAC_HELP_TEXT << std::endl; }
    else if (command == "version")      { std::cout << NDN_NAC_VERSION_BUILD_STRING << std::endl; }
    else if (command == "dump-kek")     { return nac_dump_kek(argc - 1, argv + 1); }
    else if (command == "add-member")   { return nac_add_member(argc - 1, argv + 1); }
    else {
      std::cerr << "ERROR: Unknown command '" << command << "'\n"
                << "\n"
                << NAC_HELP_TEXT << std::endl;
      return 2;
    }
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    NDN_LOG_ERROR(boost::diagnostic_information(e));
    return 1;
  }

  return 0;
}
