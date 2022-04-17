/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2022, Regents of the University of California
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

#include "decryptor.hpp"

#include <ndn-cxx/security/transform/block-cipher.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/util/exception.hpp>
#include <ndn-cxx/util/logger.hpp>

namespace ndn::nac {

NDN_LOG_INIT(nac.Decryptor);

const size_t N_RETRIES = 3;

Decryptor::Decryptor(const Key& credentialsKey, Validator& validator, KeyChain& keyChain, Face& face)
  : m_credentialsKey(credentialsKey)
  // , m_validator(validator)
  , m_face(face)
  , m_keyChain(keyChain)
  , m_internalKeyChain("pib-memory:", "tpm-memory:")
{
}

Decryptor::~Decryptor()
{
  for (auto& i : m_cks) {
    if (i.second.pendingInterest) {
      i.second.pendingInterest->cancel();
      for (const auto& p : i.second.pendingDecrypts) {
        p.onFailure(ErrorCode::CkRetrievalFailure,
                    "Cancel pending decrypt as ContentKey is being destroyed");
      }
    }
  }
}

void
Decryptor::decrypt(const Block& encryptedContent,
                   const DecryptSuccessCallback& onSuccess,
                   const ErrorCallback& onFailure)
{
  EncryptedContent ec(encryptedContent);
  if (!ec.hasKeyLocator()) {
    NDN_LOG_INFO("Missing required KeyLocator in the supplied EncryptedContent block");
    return onFailure(ErrorCode::MissingRequiredKeyLocator,
                     "Missing required KeyLocator in the supplied EncryptedContent block");
  }

  if (!ec.hasIv()) {
    NDN_LOG_INFO("Missing required InitialVector in the supplied EncryptedContent block");
    return onFailure(ErrorCode::MissingRequiredKeyLocator,
                     "Missing required InitialVector in the supplied EncryptedContent block");
  }

  auto [ck, isNew] = m_cks.emplace(ec.getKeyLocator(), ContentKey{});

  if (ck->second.isRetrieved) {
    doDecrypt(ec, ck->second.bits, onSuccess, onFailure);
  }
  else {
    NDN_LOG_DEBUG("CK " << ec.getKeyLocator() << " not yet available, adding decrypt to the pending queue");
    ck->second.pendingDecrypts.push_back({ec, onSuccess, onFailure});
  }

  if (isNew) {
    fetchCk(ck, onFailure, N_RETRIES);
  }
}

void
Decryptor::fetchCk(ContentKeys::iterator ck, const ErrorCallback& onFailure, size_t nTriesLeft)
{
  // full name of CK is

  // <whatever-prefix>/CK/<ck-id>  /ENCRYPTED-BY /<kek-prefix>/KEK/<key-id>
  // \                          /                \                        /
  //  -----------  -------------                  -----------  -----------
  //             \/                                          \/
  //   from the encrypted data          unknown (name in retrieved CK is used to determine KDK)

  const Name& ckName = ck->first;
  NDN_LOG_DEBUG("Fetching CK " << ckName);

  ck->second.pendingInterest = m_face.expressInterest(Interest(ckName)
                                                       .setMustBeFresh(false) // ?
                                                       .setCanBePrefix(true),
    [=] (const Interest& ckInterest, const Data& ckData) {
      ck->second.pendingInterest = std::nullopt;
      // TODO: verify that the key is legit
      auto [kdkPrefix, kdkIdentity, kdkKeyName] =
        extractKdkInfoFromCkName(ckData.getName(), ckInterest.getName(), onFailure);
      if (kdkPrefix.empty()) {
        return; // error has been already reported
      }

      // check if KDK already exists (there is a corresponding
      auto kdkIdentityIt = m_internalKeyChain.getPib().getIdentities().find(kdkIdentity);
      if (kdkIdentityIt != m_internalKeyChain.getPib().getIdentities().end()) {
        auto kdkKeyIt = (*kdkIdentityIt).getKeys().find(kdkKeyName);
        if (kdkKeyIt != (*kdkIdentityIt).getKeys().end()) {
          // KDK was already fetched and imported
          NDN_LOG_DEBUG("KDK " << kdkKeyName << " already exists, directly using it to decrypt CK");
          return decryptCkAndProcessPendingDecrypts(ck, ckData, kdkKeyName, onFailure);
        }
      }

      fetchKdk(ck, kdkPrefix, ckData, onFailure, N_RETRIES);
    },
    [=] (const Interest& i, const lp::Nack& nack) {
      ck->second.pendingInterest = std::nullopt;
      onFailure(ErrorCode::CkRetrievalFailure,
                "Retrieval of CK [" + i.getName().toUri() + "] failed. "
                "Got NACK (" + boost::lexical_cast<std::string>(nack.getReason()) + ")");
    },
    [=] (const Interest& i) {
      ck->second.pendingInterest = std::nullopt;
      if (nTriesLeft > 1) {
        fetchCk(ck, onFailure, nTriesLeft - 1);
      }
      else {
        onFailure(ErrorCode::CkRetrievalTimeout,
                  "Retrieval of CK [" + i.getName().toUri() + "] timed out");
      }
    });
}

void
Decryptor::fetchKdk(ContentKeys::iterator ck, const Name& kdkPrefix, const Data& ckData,
                    const ErrorCallback& onFailure, size_t nTriesLeft)
{
  // <kdk-prefix>/KDK/<kdk-id>    /ENCRYPTED-BY  /<credential-identity>/KEY/<key-id>
  // \                          /                \                                /
  //  -----------  -------------                  ---------------  ---------------
  //             \/                                              \/
  //     from the CK data                                from configuration

  Name kdkName = kdkPrefix;
  kdkName
    .append(ENCRYPTED_BY)
    .append(m_credentialsKey.getName());

  NDN_LOG_DEBUG("Fetching KDK " << kdkName);

  ck->second.pendingInterest = m_face.expressInterest(Interest(kdkName).setMustBeFresh(true),
    [=] (const Interest&, const Data& kdkData) {
      ck->second.pendingInterest = std::nullopt;
      // TODO: verify that the key is legit

      bool isOk = decryptAndImportKdk(kdkData, onFailure);
      if (!isOk)
        return;
      decryptCkAndProcessPendingDecrypts(ck, ckData,
                                         kdkPrefix.getPrefix(-2).append("KEY").append(kdkPrefix.get(-1)), // a bit hacky
                                         onFailure);
    },
    [=] (const Interest& i, const lp::Nack& nack) {
      ck->second.pendingInterest = std::nullopt;
      onFailure(ErrorCode::KdkRetrievalFailure,
                "Retrieval of KDK [" + i.getName().toUri() + "] failed. "
                "Got NACK (" + boost::lexical_cast<std::string>(nack.getReason()) + ")");
    },
    [=] (const Interest& i) {
      ck->second.pendingInterest = std::nullopt;
      if (nTriesLeft > 1) {
        fetchKdk(ck, kdkPrefix, ckData, onFailure, nTriesLeft - 1);
      }
      else {
        onFailure(ErrorCode::KdkRetrievalTimeout,
                  "Retrieval of KDK [" + i.getName().toUri() + "] timed out");
      }
    });
}

bool
Decryptor::decryptAndImportKdk(const Data& kdkData, const ErrorCallback& onFailure)
{
  try {
    NDN_LOG_DEBUG("Decrypting and importing KDK " << kdkData.getName());
    EncryptedContent content(kdkData.getContent().blockFromValue());

    SafeBag safeBag(content.getPayload().blockFromValue());
    auto secret = m_keyChain.getTpm().decrypt(content.getPayloadKey().value_bytes(),
                                              m_credentialsKey.getName());
    if (secret == nullptr) {
      onFailure(ErrorCode::TpmKeyNotFound,
                "Could not decrypt secret, " + m_credentialsKey.getName().toUri() + " not found in TPM");
      return false;
    }

    m_internalKeyChain.importSafeBag(safeBag, reinterpret_cast<const char*>(secret->data()), secret->size());
    return true;
  }
  catch (const std::runtime_error& e) {
    // can be tlv::Error, pib::Error, tpm::Error, and bunch of other runtime-derived errors
    onFailure(ErrorCode::KdkDecryptionFailure,
              "Failed to decrypt KDK [" + kdkData.getName().toUri() + "]: " + e.what());
    return false;
  }
}

void
Decryptor::decryptCkAndProcessPendingDecrypts(ContentKeys::iterator ck, const Data& ckData, const Name& kdkKeyName,
                                              const ErrorCallback& onFailure)
{
  NDN_LOG_DEBUG("Decrypting CK data " << ckData.getName());

  EncryptedContent content(ckData.getContent().blockFromValue());

  auto ckBits = m_internalKeyChain.getTpm().decrypt(content.getPayload().value_bytes(), kdkKeyName);
  if (ckBits == nullptr) {
    onFailure(ErrorCode::TpmKeyNotFound, "Could not decrypt secret, " + kdkKeyName.toUri() + " not found in TPM");
    return;
  }

  ck->second.bits = *ckBits;
  ck->second.isRetrieved = true;

  for (const auto& item : ck->second.pendingDecrypts) {
    doDecrypt(item.encryptedContent, ck->second.bits, item.onSuccess, item.onFailure);
  }
  ck->second.pendingDecrypts.clear();
}

void
Decryptor::doDecrypt(const EncryptedContent& content, const Buffer& ckBits,
                     const DecryptSuccessCallback& onSuccess,
                     const ErrorCallback& onFailure)
{
  if (!content.hasIv()) {
    NDN_THROW(Error("Expecting Initialization Vector in the encrypted content, but it is not present"));
  }

  OBufferStream os;
  security::transform::bufferSource(content.getPayload().value_bytes())
    >> security::transform::blockCipher(BlockCipherAlgorithm::AES_CBC,
                                        CipherOperator::DECRYPT,
                                        ckBits, content.getIv().value_bytes())
    >> security::transform::streamSink(os);

  onSuccess(os.buf());
}

} // namespace ndn::nac
