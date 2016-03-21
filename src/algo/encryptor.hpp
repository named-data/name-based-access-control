/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2015,  Regents of the University of California
 *
 * This file is part of ndn-group-encrypt (Group-based Encryption Protocol for NDN).
 * See AUTHORS.md for complete list of ndn-group-encrypt authors and contributors.
 *
 * ndn-group-encrypt is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-group-encrypt is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndn-group-encrypt, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NDN_ENCRYPTOR_HPP
#define NDN_ENCRYPTOR_HPP

#include <ndn-cxx/data.hpp>
#include "encrypt-params.hpp"

namespace ndn {
namespace gep {
namespace algo {

/**
 * @brief Prepare an encrypted data packet.
 *
 * This method will encrypt @p payload using @p key according to @p params.
 * In addition, it will prepare the EncryptedContent TLVs with the encryption
 * result with @p keyName and @p params. The TLV will be set as the content of
 * @p data. If @p params defines an asymmetric encryption and the payload is
 * larger than the max plaintext size, this method will encrypt the payload
 * with a symmetric key that will be asymmetrically encrypted and provided as
 * a nonce in the content of @p data.
 */
void
encryptData(Data& data, const uint8_t* payload, size_t payloadLen,
            const Name& keyName, const uint8_t* key, size_t keyLen,
            const EncryptParams& params);

} // namespace algo
} // namespace gep
} // namespace ndn

#endif // NDN_ENCRYPTOR_HPP
