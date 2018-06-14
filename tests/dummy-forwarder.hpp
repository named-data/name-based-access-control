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

#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/lp/nack.hpp>
#include <ndn-cxx/util/dummy-client-face.hpp>
#include <ndn-cxx/security/key-chain.hpp>

#ifndef NAC_TESTS_TEST_DUMMY_FORWARDER_HPP
#define NAC_TESTS_TEST_DUMMY_FORWARDER_HPP

namespace ndn {
namespace nac {
namespace tests {

/**
 * @brief Very basic implementation of the dummy forwarder
 *
 * Interests expressed by any added face, will be forwarded to all other faces.
 * Similarly, any pushed data, will be pushed to all other faces.
 */
class DummyForwarder
{
public:
  DummyForwarder(boost::asio::io_service& io, KeyChain& keyChain);

  Face&
  addFace();

  Face&
  getFace(size_t nFace)
  {
    return *m_faces.at(nFace);
  }

private:
  boost::asio::io_service& m_io;
  KeyChain& m_keyChain;
  std::vector<shared_ptr<util::DummyClientFace>> m_faces;
};

} // namespace tests
} // namespace nac
} // namespace ndn

#endif // NAC_TESTS_TEST_DUMMY_FORWARDER_HPP
