#ifndef NDN_GEP_ENCRYPT_PARAMS_HPP
#define NDN_GEP_ENCRYPT_PARAMS_HPP

#include <ndn-cxx/encoding/buffer-stream.hpp>

namespace ndn {
namespace gep {

enum EncryptionMode {
  ENCRYPT_MODE_ECB_AES,
  ENCRYPT_MODE_CBC_AES,
  ENCRYPT_MODE_RSA
};

enum PaddingScheme {
  PADDING_SCHEME_PKCS7,
  PADDING_SCHEME_PKCS1v15,
  PADDING_SCHEME_OAEP_SHA
};

namespace algo {

class EncryptParams
{
public:
  EncryptParams(EncryptionMode encryptMode, PaddingScheme paddingScheme, uint8_t ivLength);

  virtual
  ~EncryptParams()
  {
  }

  void
  setIV(const Buffer& iv);

  void
  setEncryptMode(const EncryptionMode& encryptMode);

  void
  setPaddingScheme(const PaddingScheme& paddingScheme);

  Buffer
  getIV() const;

  EncryptionMode
  getEncryptMode() const;

  PaddingScheme
  getPaddingScheme() const;

private:
  EncryptionMode m_encryptMode;
  PaddingScheme m_paddingScheme;
  Buffer m_iv;
};

} // namespace algo
} // namespace gep
} // namespace ndn

#endif // NDN_GEP_ENCRYPT_PARAMS_HPP
