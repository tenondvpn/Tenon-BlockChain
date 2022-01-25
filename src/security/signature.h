#pragma once

#include <memory>
#include <string>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <secp256k1/secp256k1.h>

#include "common/utils.h"

namespace tenon {

namespace security {

class Signature {
public:
    Signature();
    Signature(const std::string& challenge_src, const std::string& response_src);
    Signature(const std::string& sig);
    Signature(const secp256k1_ecdsa_signature& sig);
    Signature(const Signature& src);
    ~Signature();
    Signature& operator=(const Signature& src);
    bool operator==(const Signature& r) const;
    uint32_t Serialize(std::string& challenge_dst, std::string& response_dst) const;
    int Deserialize(const std::string& challenge_src, const std::string& response_src);
    const std::string& str_sign() const {
        return str_sign_;
    }

    const secp256k1_ecdsa_signature* sig() const{
        return &sig_;
    }

private:
    std::string r_;
    std::string s_;
    secp256k1_ecdsa_signature sig_;
    std::string str_sign_;
};

}  // namespace security

}  // namespace tenon
