#ifndef NDN_ENCRYPTED_CONTENT_HPP
#define NDN_ENCRYPTED_CONTENT_HPP

#include <ndn-cxx/encoding/tlv.hpp>
#include <ndn-cxx/key-locator.hpp>
#include <list>

#include "tlv.hpp"

namespace ndn {
namespace gep {

class EncryptedContent
{
public:
  class Error : public ndn::tlv::Error
  {
    public:
      explicit
      Error(const std::string& what)
      : ndn::tlv::Error(what)
      {
      }
  };

public:
  EncryptedContent();

  EncryptedContent(tlv::AlgorithmTypeValue type, const KeyLocator& keyLocator, const ConstBufferPtr& payload);

  explicit
  EncryptedContent(const Block& block);

  void
  setAlgorithmType(tlv::AlgorithmTypeValue type);

  int32_t
  getAlgorithmType() const
  {
    return m_type;
  }

  bool
  hasKeyLocator() const
  {
   return m_hasKeyLocator;
  }

  void
  setKeyLocator(const KeyLocator& keyLocator);

  const KeyLocator&
  getKeyLocator() const;

  void
  setPayload(const ConstBufferPtr& payload);

  const ConstBufferPtr
  getPayload() const;

  template<encoding::Tag TAG>
  size_t
  wireEncode(EncodingImpl<TAG>& block) const;

  const Block&
  wireEncode() const;

  void
  wireDecode(const Block& wire);

public:
  bool
  operator==(const EncryptedContent& rhs) const;
  bool
  operator!=(const EncryptedContent& rhs) const
  {
    return !(*this == rhs);
  }

private:
  int32_t m_type;
  bool m_hasKeyLocator;
  KeyLocator m_keyLocator;
  ConstBufferPtr m_payload;

  mutable Block m_wire;
};

} // namespace gep
} // namespace ndn

#endif // NDN_ENCRYPTED_CONTENT_HPP
