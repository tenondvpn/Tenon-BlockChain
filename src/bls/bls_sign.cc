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
    libBLS::Bls bls_instance = libBLS::Bls(t, n);
    libff::alt_bn128_G1 hash = bls_instance.Hashing(message);
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

    if (!pkey.is_well_formed()) {
        BLS_ERROR("pkey.is_well_formed() error.");
        return kBlsError;
    }

    libBLS::Bls bls_instance = libBLS::Bls(t, n);
    if (!bls_instance.Verification(message, sign, pkey)) {
        BLS_ERROR("bls_instance.Verification error.");
        return kBlsError;
    }
    
    return kBlsSuccess;
}

};  // namespace bls

};  // namespace tenon
