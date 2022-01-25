#pragma once

#include <memory>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <secp256k1/secp256k1.h>

#include "common/utils.h"
#include "security/private_key.h"

namespace tenon {

namespace security {

class PublicKey {
public:
    PublicKey();
    explicit PublicKey(PrivateKey& privkey);
    explicit PublicKey(const std::string& src);
    PublicKey(const PublicKey&);
    ~PublicKey();
    PublicKey& operator=(const PublicKey& src);
    uint32_t Serialize(std::string& dst, bool compress = true) const;
    int Deserialize(const std::string& src);
    const secp256k1_pubkey* pubkey() const {
        return &pubkey_;
    }

private:
    secp256k1_pubkey pubkey_;
};

}  // namespace security

}  // namespace tenon
