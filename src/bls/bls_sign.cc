#include "bls/bls_sign.h"

#include "libff/common/profiling.hpp"

namespace tenon {

namespace bls {

BlsSign::BlsSign() {}

BlsSign::~BlsSign() {}

void BlsSign::Sign(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_Fr& secret_key,
        const std::string& message,
        libff::alt_bn128_G1* sign) {
    auto hash_bytes_arr = std::make_shared<std::array<uint8_t, 32>>();
    memcpy(hash_bytes_arr->data(), message.c_str(), 32);
    signatures::Bls bls_instance = signatures::Bls(t, n);
    libff::alt_bn128_G1 hash = bls_instance.HashtoG1(hash_bytes_arr);
    *sign = bls_instance.Signing(hash, secret_key);
}

int BlsSign::Verify(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_G1& sign,
        const std::string& message,
        const libff::alt_bn128_G2& pkey) {
    if (!sign.is_well_formed()) {
        BLS_ERROR("sign.is_well_formed() error.");
        return kBlsError;
    }

    libff::inhibit_profiling_info = true;
    signatures::Bls bls_instance = signatures::Bls(t, n);
    auto hash_bytes_arr = std::make_shared<std::array<uint8_t, 32>>();
    memcpy(hash_bytes_arr->data(), message.c_str(), 32);
    if (!bls_instance.Verification(hash_bytes_arr, sign, pkey)) {
        BLS_ERROR("bls_instance.Verification error.");
        return kBlsError;
    }
    
    return kBlsSuccess;
}

};  // namespace bls

};  // namespace tenon
