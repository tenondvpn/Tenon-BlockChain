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
    static PublicKey GetPubKeyFromString(const std::string&);
    PublicKey();
    explicit PublicKey(PrivateKey& privkey);
    explicit PublicKey(const std::string& src);
    PublicKey(const PublicKey&);
    ~PublicKey();
    const std::shared_ptr<EC_POINT>& ec_point() const {
        return ec_point_;
    }

    PublicKey& operator=(const PublicKey& src);
    bool operator<(const PublicKey& r) const;
    bool operator>(const PublicKey& r) const;
    bool operator==(const PublicKey& r) const;
    uint32_t Serialize(std::string& dst, bool compress = true) const;
    int Deserialize(const std::string& src);
    const secp256k1_pubkey* pubkey() const {
        return &pubkey_;
    }

    const std::string& str_pubkey() const {
        return str_pubkey_;
    }

private:
    int DeserializeToSecp256k1(const std::string& src);

    std::shared_ptr<EC_POINT> ec_point_{ nullptr };
    secp256k1_pubkey pubkey_;
    std::string str_pubkey_;
};

}  // namespace security

}  // namespace tenon
