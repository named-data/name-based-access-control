/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2024, Regents of the University of California
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

#include "access-manager.hpp"
#include "encrypted-content.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/random.hpp>

namespace ndn::nac {

NDN_LOG_INIT(nac.AccessManager);

AccessManager::AccessManager(const Identity& identity, const Name& dataset,
                             KeyChain& keyChain, Face& face)
  : m_identity(identity)
  , m_keyChain(keyChain)
  , m_face(face)
{
  // NAC Identity: <identity>/NAC/<dataset>
  // generate NAC key
  auto nacId = m_keyChain.createIdentity(Name(identity.getName()).append(NAC).append(dataset), RsaKeyParams());
  m_nacKey = nacId.getDefaultKey();
  if (m_nacKey.getKeyType() != KeyType::RSA) {
    NDN_LOG_INFO("Cannot re-use existing KEK/KDK pair, as it is not an RSA key, regenerating");
    m_nacKey = m_keyChain.createKey(nacId, RsaKeyParams());
  }
  auto nacKeyId = m_nacKey.getName().at(-1);

  auto kekPrefix = Name(m_nacKey.getIdentity()).append(KEK);

  auto kek = std::make_shared<Data>(m_nacKey.getDefaultCertificate());
  kek->setName(Name(kekPrefix).append(nacKeyId));
  kek->setFreshnessPeriod(DEFAULT_KEK_FRESHNESS_PERIOD);
  m_keyChain.sign(*kek, signingByIdentity(m_identity));
  // kek looks like a cert, but doesn't have ValidityPeriod
  m_ims.insert(*kek);

  auto serveFromIms = [this] (const Name&, const Interest& interest) {
    auto data = m_ims.find(interest);
    if (data != nullptr) {
      NDN_LOG_DEBUG("Serving " << data->getName() << " from InMemoryStorage");
      m_face.put(*data);
    }
    else {
      NDN_LOG_DEBUG("Didn't find data for " << interest.getName());
      // send NACK?
    }
  };

  auto handleError = [] (const Name& prefix, const std::string& msg) {
    NDN_LOG_ERROR("Failed to register prefix " << prefix << ": " << msg);
  };

  m_kekReg = m_face.setInterestFilter(kekPrefix, serveFromIms, handleError);

  auto kdkPrefix = Name(m_nacKey.getIdentity()).append(KDK).append(nacKeyId);
  m_kdkReg = m_face.setInterestFilter(kdkPrefix, serveFromIms, handleError);
}

Data
AccessManager::addMember(const Certificate& memberCert)
{
  Name kdkName(m_nacKey.getIdentity());
  kdkName
    .append(KDK)
    .append(m_nacKey.getName().at(-1)) // key-id
    .append(ENCRYPTED_BY)
    .append(memberCert.getKeyName());

  const size_t secretLength = 32;
  uint8_t secret[secretLength + 1];
  random::generateSecureBytes({secret, secretLength});
  // because of stupid bug in ndn-cxx, remove all \0 in generated secret, replace with 1
  for (size_t i = 0; i < secretLength; ++i) {
    if (secret[i] == 0) {
      secret[i] = 1;
    }
  }
  secret[secretLength] = 0;

  auto kdkData = m_keyChain.exportSafeBag(m_nacKey.getDefaultCertificate(),
                                          reinterpret_cast<const char*>(secret), secretLength);

  PublicKey memberKey;
  memberKey.loadPkcs8(memberCert.getPublicKey());

  EncryptedContent content;
  content.setPayload(kdkData->wireEncode());
  content.setPayloadKey(memberKey.encrypt({secret, secretLength}));

  auto kdk = std::make_shared<Data>(kdkName);
  kdk->setContent(content.wireEncode());
  // FreshnessPeriod can serve as a soft access control for revoking access
  kdk->setFreshnessPeriod(DEFAULT_KDK_FRESHNESS_PERIOD);
  m_keyChain.sign(*kdk, signingByIdentity(m_identity));

  m_ims.insert(*kdk);

  return *kdk;
}

void
AccessManager::removeMember(const Name& identity)
{
  m_ims.erase(Name(m_nacKey.getName()).append(KDK).append(ENCRYPTED_BY).append(identity));
}

} // namespace ndn::nac
