/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2015,  Regents of the University of California
 *
 * This file is part of ndn-group-encrypt (Group-based Encryption Protocol for NDN).
 * See AUTHORS.md for complete list of ndn-group-encrypt authors and contributors.
 *
 * ndn-group-encrypt is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * ndn-group-encrypt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndn-group-encrypt, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Zhiyi Zhang <dreamerbarrychang@gmail.com>
 * @author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "consumer.hpp"
#include "encrypted-content.hpp"

namespace ndn {
namespace gep {

// public
Consumer::Consumer(Face& face, const Name& groupName, const Name& consumerName, const std::string& dbDir)
  : m_db(dbDir)
  , m_validator(new ValidatorNull)
  , m_face(face)
  , m_groupName(groupName)
  , m_consumerName(consumerName)
{
}

void
Consumer::setGroup(const Name& groupName)
{
  m_groupName = groupName;
}

void
Consumer::addDecryptionKey(const Name& keyName, const Buffer& keyBuf)
{
  BOOST_ASSERT(m_consumerName.isPrefixOf(keyName));

  m_db.addKey(keyName, keyBuf);
}

void
Consumer::consume(const Name& contentName,
                  const ConsumptionCallBack& consumptionCallBack,
                  const ErrorCallBack& errorCallBack)
{
  shared_ptr<Interest> interest = make_shared<Interest>(contentName);

  // prepare callback functions
  auto onData = [=] (const Interest& contentInterest, const Data& contentData) {
    if (!contentInterest.matchesData(contentData))
      return;

    this->m_validator->validate(contentData,
      [=] (const shared_ptr<const Data>& validData) {
        // decrypt content
        decryptContent(*validData,
                       [=] (const Buffer& plainText) {consumptionCallBack(contentData, plainText);},
                       errorCallBack);
      },
      [=] (const shared_ptr<const Data>& d, const std::string& e) {
        errorCallBack(ErrorCode::Validation, e);
      });
  };

  auto onTimeout = [=] (const Interest& contentInterest) {
    // we should re-try at least once.
    this->m_face.expressInterest(*interest, onData,
      [=] (const Interest& contentInterest) {
        errorCallBack(ErrorCode::Timeout, interest->getName().toUri());
      });
  };

  // express Interest packet
  m_face.expressInterest(*interest, onData, onTimeout);
}

// private

void
Consumer::decrypt(const Block& encryptedBlock,
                  const Buffer& keyBits,
                  const PlainTextCallBack& plainTextCallBack,
                  const ErrorCallBack& errorCallBack)
{
  EncryptedContent encryptedContent(encryptedBlock);
  const Buffer& payload = encryptedContent.getPayload();

  switch (encryptedContent.getAlgorithmType()) {
    case tlv::AlgorithmAesCbc: {
      // prepare parameter
      algo::EncryptParams decryptParams(tlv::AlgorithmAesCbc);
      decryptParams.setIV(encryptedContent.getInitialVector().buf(),
                          encryptedContent.getInitialVector().size());

      // decrypt content
      Buffer content = algo::Aes::decrypt(keyBits.buf(), keyBits.size(),
                                          payload.buf(), payload.size(),
                                          decryptParams);
      plainTextCallBack(content);
      break;
    }
    case tlv::AlgorithmRsaOaep: {
      // prepare parameter
      algo::EncryptParams decryptParams(tlv::AlgorithmRsaOaep);

      // decrypt content
      Buffer content = algo::Rsa::decrypt(keyBits.buf(), keyBits.size(),
                                          payload.buf(), payload.size(),
                                          decryptParams);
      plainTextCallBack(content);
      break;
    }
    default: {
      errorCallBack(ErrorCode::UnsupportedEncryptionScheme,
                    std::to_string(encryptedContent.getAlgorithmType()));
    }
  }
}

void
Consumer::decryptContent(const Data& data,
                         const PlainTextCallBack& plainTextCallBack,
                         const ErrorCallBack& errorCallBack)
{
  // get encrypted content
  Block encryptedContent = data.getContent().blockFromValue();
  Name cKeyName = EncryptedContent(encryptedContent).getKeyLocator().getName();

  // check if content key already in store
  auto it = m_cKeyMap.find(cKeyName);

  if (it != m_cKeyMap.end()) { // decrypt content directly
    decrypt(encryptedContent, it->second, plainTextCallBack, errorCallBack);
  }
  else {
    // retrieve the C-Key Data from network
    Name interestName = cKeyName;
    interestName.append(NAME_COMPONENT_FOR).append(m_groupName);
    shared_ptr<Interest> interest = make_shared<Interest>(interestName);

    // prepare callback functions
    auto onData = [=] (const Interest& cKeyInterest, const Data& cKeyData) {
      if (!cKeyInterest.matchesData(cKeyData))
        return;

      this->m_validator->validate(cKeyData,
        [=] (const shared_ptr<const Data>& validCKeyData) {
          decryptCKey(*validCKeyData,
                      [=] (const Buffer& cKeyBits) {
                        decrypt(encryptedContent, cKeyBits, plainTextCallBack, errorCallBack);
                        this->m_cKeyMap.insert(std::make_pair(cKeyName, cKeyBits));
                      },
                      errorCallBack);},
        [=] (const shared_ptr<const Data>& d, const std::string& e) {
          errorCallBack(ErrorCode::Validation, e);
        });
    };

    auto onTimeout = [=] (const Interest& cKeyInterest) {
      // we should re-try at least once.
      this->m_face.expressInterest(*interest, onData,
        [=] (const Interest& contentInterest) {
          errorCallBack(ErrorCode::Timeout, interest->getName().toUri());
        });
    };

    // express Interest packet
    m_face.expressInterest(*interest, onData, onTimeout);
  }
}

void
Consumer::decryptCKey(const Data& cKeyData,
                      const PlainTextCallBack& plainTextCallBack,
                      const ErrorCallBack& errorCallBack)
{
  // get encrypted content
  Block cKeyContent = cKeyData.getContent().blockFromValue();
  Name eKeyName = EncryptedContent(cKeyContent).getKeyLocator().getName();
  Name dKeyName = eKeyName.getPrefix(-3);
  dKeyName.append(NAME_COMPONENT_D_KEY).append(eKeyName.getSubName(-2));

  // check if decryption key already in store
  auto it = m_dKeyMap.find(dKeyName);

  if (it != m_dKeyMap.end()) { // decrypt C-Key directly
    decrypt(cKeyContent, it->second, plainTextCallBack, errorCallBack);
  }
  else {
    // get the D-Key Data
    Name interestName = dKeyName;
    interestName.append(NAME_COMPONENT_FOR).append(m_consumerName);

    // fix bug here in Nov.23.2015 : change dKeyName to interestName
    shared_ptr<Interest> interest = make_shared<Interest>(interestName);

    // prepare callback functions
    auto onData = [=] (const Interest& dKeyInterest, const Data& dKeyData) {
      if (!dKeyInterest.matchesData(dKeyData))
        return;

      this->m_validator->validate(dKeyData,
        [=] (const shared_ptr<const Data>& validDKeyData) {
          decryptDKey(*validDKeyData,
                      [=] (const Buffer& dKeyBits) {
                        decrypt(cKeyContent, dKeyBits, plainTextCallBack, errorCallBack);
                        this->m_dKeyMap.insert(std::make_pair(dKeyName, dKeyBits));
                      },
                      errorCallBack);},
        [=] (const shared_ptr<const Data>& d, const std::string& e) {
          errorCallBack(ErrorCode::Validation, e);
        });
    };

    auto onTimeout = [=] (const Interest& dKeyInterest) {
      // we should re-try at least once.
      this->m_face.expressInterest(*interest, onData,
        [=] (const Interest& contentInterest) {
          errorCallBack(ErrorCode::Timeout, interest->getName().toUri());
        });
    };

    // express Interest packet
    m_face.expressInterest(*interest, onData, onTimeout);
  }
}

void
Consumer::decryptDKey(const Data& dKeyData,
                      const PlainTextCallBack& plainTextCallBack,
                      const ErrorCallBack& errorCallBack)
{
  // get encrypted content
  Block dataContent = dKeyData.getContent();
  dataContent.parse();

  if (dataContent.elements_size() != 2)
    errorCallBack(ErrorCode::InvalidEncryptedFormat,
                  "Data packet does not satisfy D-KEY packet format");

  // process nonce;
  auto it = dataContent.elements_begin();
  Block encryptedNonceBlock = *it;
  EncryptedContent encryptedNonce(encryptedNonceBlock);
  Name consumerKeyName = encryptedNonce.getKeyLocator().getName();

  // get consumer decryption key
  Buffer consumerKeyBuf = getDecryptionKey(consumerKeyName);
  if (consumerKeyBuf.empty()) {
    errorCallBack(ErrorCode::NoDecryptKey,
                  "No desired consumer decryption key in database");
    return;
  }

  // process d-key
  it++;
  Block encryptedPayloadBlock = *it;

  // decrypt d-key
  decrypt(encryptedNonceBlock, consumerKeyBuf,
          [&] (const Buffer& nonceKeyBits) {
            decrypt(encryptedPayloadBlock, nonceKeyBits, plainTextCallBack, errorCallBack);
          },
          errorCallBack);
}

const Buffer
Consumer::getDecryptionKey(const Name& decryptionKeyName)
{
  return m_db.getKey(decryptionKeyName);
}

} // namespace gep
} // namespace ndn
