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

#include "tests/key-chain-fixture.hpp"

#include <ndn-cxx/util/io.hpp>

#include <boost/filesystem.hpp>

namespace ndn {
namespace nac {
namespace tests {

using namespace ndn::security;

KeyChainFixture::KeyChainFixture()
  : m_keyChain("pib-memory:", "tpm-memory:")
{
}

KeyChainFixture::~KeyChainFixture()
{
  boost::system::error_code ec;
  for (const auto& certFile : m_certFiles) {
    boost::filesystem::remove(certFile, ec); // ignore error
  }
}

Certificate
KeyChainFixture::makeCert(const Key& key, const std::string& issuer, const Key& signingKey)
{
  Certificate cert;
  cert.setName(Name(key.getName())
               .append(issuer)
               .appendVersion());

  // set metainfo
  cert.setContentType(tlv::ContentType_Key);
  cert.setFreshnessPeriod(1_h);

  // set content
  cert.setContent(key.getPublicKey().data(), key.getPublicKey().size());

  // set signature info
  ndn::SignatureInfo info;
  auto now = time::system_clock::now();
  info.setValidityPeriod(ValidityPeriod(now - 30_days, now + 30_days));

  m_keyChain.sign(cert, signingByKey(signingKey ? signingKey : key).setSignatureInfo(info));
  return cert;
}

bool
KeyChainFixture::saveCert(const Data& cert, const std::string& filename)
{
  m_certFiles.push_back(filename);
  try {
    ndn::io::save(cert, filename);
    return true;
  }
  catch (const ndn::io::Error&) {
    return false;
  }
}

bool
KeyChainFixture::saveIdentityCert(const Identity& identity, const std::string& filename)
{
  Certificate cert;
  try {
    cert = identity.getDefaultKey().getDefaultCertificate();
  }
  catch (const Pib::Error&) {
    return false;
  }

  return saveCert(cert, filename);
}

bool
KeyChainFixture::saveIdentityCert(const Name& identityName, const std::string& filename,
                                  bool allowCreate)
{
  Identity id;
  try {
    id = m_keyChain.getPib().getIdentity(identityName);
  }
  catch (const Pib::Error&) {
    if (allowCreate) {
      id = m_keyChain.createIdentity(identityName);
    }
  }

  if (!id) {
    return false;
  }

  return saveIdentityCert(id, filename);
}

} // namespace tests
} // namespace nac
} // namespace ndn
