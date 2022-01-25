#pragma once

#include <string>
#include <memory>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include "common/utils.h"

namespace tenon {

namespace security {

class PrivateKey {
public:
    PrivateKey();
    PrivateKey(const PrivateKey& src);
    explicit PrivateKey(const std::string& src);
    const std::shared_ptr<BIGNUM>& bignum() const {
        return bignum_;
    }
    PrivateKey& operator=(const PrivateKey&);
    bool operator==(const PrivateKey& r) const;
    const std::string& private_key() const {
        return private_key_;
    }
    uint32_t Serialize(std::string& dst) const;
    int Deserialize(const std::string& src);

private:

    std::shared_ptr<BIGNUM> bignum_;
    std::string private_key_;
};

}  // namespace security

}  // namespace tenon
