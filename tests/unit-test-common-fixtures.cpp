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

#include "unit-test-common-fixtures.hpp"

namespace ndn {
namespace nac {
namespace tests {

UnitTestTimeFixture::UnitTestTimeFixture()
  : steadyClock(make_shared<time::UnitTestSteadyClock>())
  , systemClock(make_shared<time::UnitTestSystemClock>())
{
  time::setCustomClocks(steadyClock, systemClock);
}

UnitTestTimeFixture::~UnitTestTimeFixture()
{
  time::setCustomClocks(nullptr, nullptr);
}

void
UnitTestTimeFixture::advanceClocks(const time::nanoseconds& tick, size_t nTicks)
{
  this->advanceClocks(tick, tick * nTicks);
}

void
UnitTestTimeFixture::advanceClocks(const time::nanoseconds& tick, const time::nanoseconds& total)
{
  BOOST_ASSERT(tick > time::nanoseconds::zero());
  BOOST_ASSERT(total >= time::nanoseconds::zero());

  time::nanoseconds remaining = total;
  while (remaining > time::nanoseconds::zero()) {
    if (remaining >= tick) {
      steadyClock->advance(tick);
      systemClock->advance(tick);
      remaining -= tick;
    }
    else {
      steadyClock->advance(remaining);
      systemClock->advance(remaining);
      remaining = time::nanoseconds::zero();
    }

    if (m_io.stopped())
      m_io.reset();
    m_io.poll();
  }
}

} // namespace tests
} // namespace nac
} // namespace ndn
