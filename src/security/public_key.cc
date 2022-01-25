#include "stdafx.h"
#include "security/public_key.h"

#include "common/encode.h"
#include "security/schnorr.h"
#include "security/crypto_utils.h"
#include "security/security_string_trans.h"
#include "security/secp256k1.h"

namespace tenon {

namespace security {

PublicKey::PublicKey() {}

PublicKey::PublicKey(PrivateKey& privkey) {
    secp256k1_ec_pubkey_create(
        Secp256k1::Instance()->getCtx(),
        &pubkey_,
        (uint8_t*)privkey.private_key().c_str());
}

PublicKey::PublicKey(const std::string& src) {
    Deserialize(src);
}

PublicKey::PublicKey(const PublicKey& src) : pubkey_(src.pubkey_) {}

PublicKey::~PublicKey() {}

PublicKey& PublicKey::operator=(const PublicKey& src) {
    if (this == &src) {
        return *this;
    }

    pubkey_ = src.pubkey_;
    return *this;
}

uint32_t PublicKey::Serialize(std::string& dst, bool compress) const {
    uint8_t pubkey_data[256];
    size_t len = 0;
    if (secp256k1_ec_pubkey_serialize(
            Secp256k1::Instance()->getCtx(),
            pubkey_data,
            &len,
            &pubkey_,
            compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED) != 1) {
        // ERROR
    }

    dst = std::string((char*)pubkey_data, len);
    return compress ? kPublicKeySize: kPublicKeyUncompressSize;
}

int PublicKey::Deserialize(const std::string& src) {
    uint8_t pubkey_data[kPublicCompresssedSizeBytes];
    size_t len = kPublicCompresssedSizeBytes;
    if (secp256k1_ec_pubkey_parse(
            Secp256k1::Instance()->getCtx(),
            &pubkey_,
            (uint8_t*)src.c_str(),
            src.size()) != 1) {
        return 1;
    }

    return 0;
}

}  // namespace security

}  // namespace tenon
