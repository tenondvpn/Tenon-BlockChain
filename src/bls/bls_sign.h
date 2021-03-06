#pragma once

#include <libbls/tools/utils.h>
#include <libbls/bls/bls.h>
#include <libbls/bls/BLSPublicKey.h>

#include "bls/bls_utils.h"

namespace tenon {

namespace bls {

class BlsSign {
public:
    BlsSign();
    ~BlsSign();
    static void Sign(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_Fr& sec_key,
        const std::string& sign_msg,
        libff::alt_bn128_G1* common_signature);
    static int Verify(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_G1& sign,
        const std::string& to_be_hashed,
        const libff::alt_bn128_G2& pkey);

private:

};

};  // namespace bls

};  // namespace tenon
