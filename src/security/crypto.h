#pragma once

#include "common/utils.h"

namespace tenon {

namespace security {

class Crypto {
public:
    static Crypto* Instance();
    std::string AesEncrypt(
        const std::string& cipher,
        const std::string& password,
        uint32_t rounds,
        const std::string& salt);
    std::string AesDecrypt(
        const std::string& cipher,
        const std::string& password,
        uint32_t rounds,
        const std::string& salt);

private:
    Crypto() {}
    ~Crypto() {}
    DISALLOW_COPY_AND_ASSIGN(Crypto);
};

};  // namespace security

};  // namespace tenon