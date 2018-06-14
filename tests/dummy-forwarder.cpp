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

#include "dummy-forwarder.hpp"

#include <boost/asio/io_service.hpp>

namespace ndn {
namespace nac {
namespace tests {

DummyForwarder::DummyForwarder(boost::asio::io_service& io, KeyChain& keyChain)
  : m_io(io)
  , m_keyChain(keyChain)
{
}

Face&
DummyForwarder::addFace()
{
  auto face = std::make_shared<util::DummyClientFace>(m_io, m_keyChain, util::
                                                      DummyClientFace::Options{true, true});
  face->onSendInterest.connect([this, face] (const Interest& interest) {
      for (auto& otherFace : m_faces) {
        if (&*face == &*otherFace) {
          continue;
        }
        otherFace->receive(interest);
      }
    });

  face->onSendData.connect([this, face] (const Data& data) {
      for (auto& otherFace : m_faces) {
        if (&*face == &*otherFace) {
          continue;
        }
        otherFace->receive(data);
      }
    });

  face->onSendNack.connect([this, face] (const lp::Nack& nack) {
      for (auto& otherFace : m_faces) {
        if (&*face == &*otherFace) {
          continue;
        }
        otherFace->receive(nack);
      }
    });

  m_faces.push_back(face);
  return *face;
}

} // namespace tests
} // namespace nac
} // namespace ndn
