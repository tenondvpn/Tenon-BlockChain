#include "stdafx.h"
#include "security/challenge.h"

#include <cassert>

#include "security/crypto_utils.h"
#include "security/sha256.h"
#include "security/security.h"
#include "security/security_string_trans.h"

namespace tenon {

namespace security {

Challenge::Challenge() : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
}

Challenge::Challenge(
        const CommitPoint& agg_commit,
        const PublicKey& agg_pubkey,
        const std::string& message) : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
    Set(agg_commit, agg_pubkey, message);
    assert(inited_);
}

Challenge::Challenge(const std::string& src) {
    int res = Deserialize(src);
    assert(res == 0);
}

Challenge::Challenge(const Challenge& src) : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
    auto res = BN_copy(bignum_.get(), src.bignum_.get());
    assert(res != nullptr);
    inited_ = true;
}

Challenge::~Challenge() {}

uint32_t Challenge::Serialize(std::string& dst) const {
    if (inited_) {
        SecurityStringTrans::Instance()->BignumToString(bignum_, dst);
    }
    return kChallengeSize;
}

int Challenge::Deserialize(const std::string& src) {
    try {
        bignum_ = SecurityStringTrans::Instance()->StringToBignum(src);
        if (bignum_ == nullptr) {
            CRYPTO_ERROR("Deserialization failure");
            inited_ = false;
        } else {
            inited_ = true;
        }
    } catch (const std::exception& e) {
        CRYPTO_ERROR("Error with Challenge::Deserialize.[%s]", e.what());
        return -1;
    }
    return 0;
}

void Challenge::Set(
        const CommitPoint& agg_commit,
        const PublicKey& agg_pubkey,
        const std::string& message) {}

Challenge& Challenge::operator=(const Challenge& src) {
    if (this == &src) {
        return *this;
    }
    inited_ = (BN_copy(bignum_.get(), src.bignum_.get()) == bignum_.get());
    assert(inited_);
    assert(src.inited_);
    return *this;
}

bool Challenge::operator==(const Challenge& r) const {
    if (this == &r) {
        return true;
    }
    assert(inited_);
    assert(r.inited_);
    return (inited_ && r.inited_ && (BN_cmp(bignum_.get(), r.bignum_.get()) == 0));
}

}  // namespace security

}  // namespace tenon
