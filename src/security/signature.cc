#include "stdafx.h"
#include "security/signature.h"

#include <cassert>

#include "security/crypto_utils.h"
#include "security/security_string_trans.h"
#include "security/secp256k1.h"

namespace tenon {

namespace security {

Signature::Signature() {}

Signature::Signature(const secp256k1_ecdsa_signature& sig) : sig_(sig) {
    uint8_t data[kSignatureSize];
    secp256k1_ecdsa_signature_serialize_compact(
        Secp256k1::Instance()->getCtx(),
        data,
        &sig_);
    str_sign_ = std::string((char*)data, sizeof(data));
    r_ = str_sign_.substr(0, 32);
    s_ = str_sign_.substr(32, 32);
}

Signature::Signature(const std::string& sig) {
    str_sign_ = sig;
    Deserialize(str_sign_.substr(0, 32), str_sign_.substr(32, 32));
}

Signature::Signature(const std::string& challenge_src, const std::string& response_src) {
    Deserialize(challenge_src, response_src);
}

Signature::Signature(const Signature& src)
        : r_(src.r_),
          s_(src.s_),
          sig_(src.sig_),
          str_sign_(src.r_ + src.s_){}

Signature& Signature::operator=(const Signature& src) {
    if (this == &src) {
        return *this;
    }

    r_ = src.r_;
    s_ = src.s_;
    sig_ = src.sig_;
    str_sign_ = r_ + s_;
    return *this;
}

bool Signature::operator==(const Signature& r) const {
    return str_sign_ == r.str_sign_;
}

Signature::~Signature() {}

uint32_t Signature::Serialize(std::string& challenge_dst, std::string& response_dst) const {
    challenge_dst = r_;
    response_dst = s_;
    return kChallengeSize + kResponseSize;
}

int Signature::Deserialize(const std::string& challenge_src, const std::string& response_src) {
    r_ = challenge_src;
    s_ = response_src;
    if (secp256k1_ecdsa_signature_parse_compact(
            Secp256k1::Instance()->getCtx(),
            &sig_,
            (uint8_t*)(r_ + s_).c_str()) != 1) {
        return 1;
    }

    str_sign_ = r_ + s_;
    return 0;
}

}  // namespace security

}  // namespace tenon
