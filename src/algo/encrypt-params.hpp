#ifndef NDN_GEP_ENCRYPT_PARAMS_HPP
#define NDN_GEP_ENCRYPT_PARAMS_HPP

#include <ndn-cxx/encoding/buffer-stream.hpp>
#include "../tlv.hpp"

namespace ndn {
namespace gep {
namespace algo {

class EncryptParams
{
public:
  EncryptParams(tlv::AlgorithmTypeValue algorithm, uint8_t ivLength = 0);

  void
  setIV(const uint8_t* iv, size_t ivLen);

  void
  setAlgorithmType(tlv::AlgorithmTypeValue algorithm);

  Buffer
  getIV() const;

  tlv::AlgorithmTypeValue
  getAlgorithmType() const;

private:
  tlv::AlgorithmTypeValue m_algo;
  Buffer m_iv;
};

} // namespace algo
} // namespace gep
} // namespace ndn

#endif // NDN_GEP_ENCRYPT_PARAMS_HPP
