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

#include "encryptor.hpp"

#include <ndn-cxx/security/transform/block-cipher.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/util/logger.hpp>

namespace ndn {
namespace nac {

NDN_LOG_INIT(nac.Encryptor);

const size_t N_RETRIES = 3;

Encryptor::Encryptor(const Name& accessPrefix,
                     const Name& ckPrefix, SigningInfo ckDataSigningInfo,
                     const ErrorCallback& onFailure,
                     Validator&, KeyChain& keyChain, Face& face)
  : m_accessPrefix(accessPrefix)
  , m_ckPrefix(ckPrefix)
  , m_ckBits(AES_KEY_SIZE)
  , m_ckDataSigningInfo(std::move(ckDataSigningInfo))
  , m_isKekRetrievalInProgress(false)
  , m_onFailure(onFailure)
  , m_keyChain(keyChain)
  , m_face(face)
  , m_scheduler(face.getIoService())
{
  regenerateCk();

  auto serveFromIms = [this] (const Name&, const Interest& interest) {
    auto data = m_ims.find(interest);
    if (data != nullptr) {
      NDN_LOG_DEBUG("Serving " << data->getName() << " from InMemoryStorage");
      m_face.put(*data);
    }
    else {
      NDN_LOG_DEBUG("Didn't find CK data for " << interest.getName());
      // send NACK?
    }
  };

  auto handleError = [] (const Name& prefix, const std::string& msg) {
    NDN_LOG_ERROR("Failed to register prefix " << prefix << ": " << msg);
  };

  m_ckReg = m_face.setInterestFilter(Name(ckPrefix).append(CK), serveFromIms, handleError);
}

Encryptor::~Encryptor()
{
  m_kekPendingInterest.cancel();
}

void
Encryptor::retryFetchingKek()
{
  if (m_isKekRetrievalInProgress) {
    return;
  }

  NDN_LOG_DEBUG("Retrying fetching of KEK");
  m_isKekRetrievalInProgress = true;
  fetchKekAndPublishCkData([&] {
      NDN_LOG_DEBUG("KEK retrieved and published");
      m_isKekRetrievalInProgress = false;
    },
    [=] (const ErrorCode& code, const std::string& msg) {
      NDN_LOG_ERROR("Failed to retrieved KEK: " + msg);
      m_isKekRetrievalInProgress = false;
      m_onFailure(code, msg);
    },
    N_RETRIES);
}

void
Encryptor::regenerateCk()
{
  m_ckName = m_ckPrefix;
  m_ckName
    .append(CK)
    .appendVersion(); // version = ID of CK
  NDN_LOG_DEBUG("Generating new CK: " << m_ckName);
  random::generateSecureBytes(m_ckBits.data(), m_ckBits.size());

  // one implication: if CK updated before KEK fetched, KDK for the old CK will not be published
  if (!m_kek) {
    retryFetchingKek();
  }
  else {
    makeAndPublishCkData(m_onFailure);
  }
}

EncryptedContent
Encryptor::encrypt(const uint8_t* data, size_t size)
{
  // Generate IV
  auto iv = make_shared<Buffer>(AES_IV_SIZE);
  random::generateSecureBytes(iv->data(), iv->size());

  OBufferStream os;
  security::transform::bufferSource(data, size)
    >> security::transform::blockCipher(BlockCipherAlgorithm::AES_CBC,
                                        CipherOperator::ENCRYPT,
                                        m_ckBits.data(), m_ckBits.size(), iv->data(), iv->size())
    >> security::transform::streamSink(os);

  EncryptedContent content;
  content.setIv(iv);
  content.setPayload(os.buf());
  content.setKeyLocator(m_ckName);

  return content;
}

void
Encryptor::fetchKekAndPublishCkData(const std::function<void()>& onReady,
                                    const ErrorCallback& onFailure,
                                    size_t nTriesLeft)
{
  // interest for <access-prefix>/KEK to retrieve <access-prefix>/KEK/<key-id> KekData

  NDN_LOG_DEBUG("Fetching KEK " << Name(m_accessPrefix).append(KEK));

  auto kekInterest = Interest(Name(m_accessPrefix).append(KEK))
                     .setCanBePrefix(true)
                     .setMustBeFresh(true);
  m_kekPendingInterest = m_face.expressInterest(kekInterest,
    [=] (const Interest&, const Data& kek) {
      // @todo verify if the key is legit
      m_kek = kek;
      if (makeAndPublishCkData(onFailure)) {
        onReady();
      }
      // otherwise, failure has been already declared
    },
    [=] (const Interest& i, const lp::Nack& nack) {
      if (nTriesLeft > 1) {
        m_scheduler.schedule(RETRY_DELAY_AFTER_NACK, [=] {
          fetchKekAndPublishCkData(onReady, onFailure, nTriesLeft - 1);
        });
      }
      else {
        onFailure(ErrorCode::KekRetrievalFailure, "Retrieval of KEK [" + i.getName().toUri() +
                  "] failed. Got NACK with reason " + boost::lexical_cast<std::string>(nack.getReason()));
        NDN_LOG_DEBUG("Scheduling retry from NACK");
        m_scheduler.schedule(RETRY_DELAY_KEK_RETRIEVAL, [this] { retryFetchingKek(); });
      }
    },
    [=] (const Interest& i) {
      if (nTriesLeft > 1) {
        fetchKekAndPublishCkData(onReady, onFailure, nTriesLeft - 1);
      }
      else {
        onFailure(ErrorCode::KekRetrievalTimeout,
                  "Retrieval of KEK [" + i.getName().toUri() + "] timed out");
        NDN_LOG_DEBUG("Scheduling retry after all timeouts");
        m_scheduler.schedule(RETRY_DELAY_KEK_RETRIEVAL, [this] { retryFetchingKek(); });
      }
    });
}

bool
Encryptor::makeAndPublishCkData(const ErrorCallback& onFailure)
{
  try {
    PublicKey kek;
    kek.loadPkcs8(m_kek->getContent().value(), m_kek->getContent().value_size());

    EncryptedContent content;
    content.setPayload(kek.encrypt(m_ckBits.data(), m_ckBits.size()));

    auto ckData = make_shared<Data>(Name(m_ckName).append(ENCRYPTED_BY).append(m_kek->getName()));
    ckData->setContent(content.wireEncode());
    // FreshnessPeriod can serve as a soft access control for revoking access
    ckData->setFreshnessPeriod(DEFAULT_CK_FRESHNESS_PERIOD);
    m_keyChain.sign(*ckData, m_ckDataSigningInfo);
    m_ims.insert(*ckData);

    NDN_LOG_DEBUG("Publishing CK data: " << ckData->getName());
    return true;
  }
  catch (const std::runtime_error&) {
    onFailure(ErrorCode::EncryptionFailure,
              "Failed to encrypt generated CK with KEK " + m_kek->getName().toUri());
    return false;
  }
}

} // namespace nac
} // namespace ndn
