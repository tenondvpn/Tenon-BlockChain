#include "stdafx.h"
#include "security/crypto_utils.h"

#include <mutex>

#include "common/encode.h"
#include "security/security_string_trans.h"

namespace tenon {

namespace security {

bool IsValidPublicKey(const std::string& pubkey) {
    auto ptr = SecurityStringTrans::Instance()->StringToEcPoint(pubkey);
    return ptr != nullptr;
}

bool IsValidSignature(const std::string& ch, const std::string& res) {
    auto challenge = SecurityStringTrans::Instance()->StringToBignum(ch);
    if (challenge == nullptr) {
        return false;
    }

    auto response = SecurityStringTrans::Instance()->StringToBignum(res);
    if (response == nullptr) {
        return false;
    }

    return true;
}

}  // namespace security

}  // namespace tenon
