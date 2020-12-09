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

#ifndef NAC_TESTS_IO_KEY_CHAIN_FIXTURE_HPP
#define NAC_TESTS_IO_KEY_CHAIN_FIXTURE_HPP

#include "tests/clock-fixture.hpp"
#include "tests/key-chain-fixture.hpp"

#include <boost/asio/io_service.hpp>

namespace ndn {
namespace nac {
namespace tests {

class IoKeyChainFixture : public ClockFixture, public KeyChainFixture
{
private:
  void
  afterTick() final
  {
    if (m_io.stopped()) {
#if BOOST_VERSION >= 106600
      m_io.restart();
#else
      m_io.reset();
#endif
    }
    m_io.poll();
  }

protected:
  boost::asio::io_service m_io;
};

} // namespace tests
} // namespace nac
} // namespace ndn

#endif // NAC_TESTS_IO_KEY_CHAIN_FIXTURE_HPP
