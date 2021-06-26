#include "security/crypto.h"

#include "common/encode.h"
#include "security/ecdh_create_key.h"
#include "security/aes.h"

namespace tenon {

namespace security {

Crypto* Crypto::Instance() {
    static Crypto ins;
    return &ins;
}

std::string Crypto::GetEncryptData(
        const security::PublicKey& pub_key,
        const std::string& message) {
    std::string seckey;
    auto res = security::EcdhCreateKey::Instance()->CreateKey(pub_key, seckey);
    if (res != security::kSecuritySuccess) {
        return "";
    }

    uint32_t data_size = (message.size() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE + AES_BLOCK_SIZE;
    std::string res_enc(data_size, 0);
    if (security::Aes::Encrypt(
            (char*)message.c_str(),
            message.size(),
            (char*)seckey.c_str(),
            seckey.size(),
            (char*)&res_enc[0]) != security::kSecuritySuccess) {
        return "";
    }

    printf(" encrypt data_size encrypt message![%u, %u] sec: %s, message: %s, encmsg: %s ",
        data_size, data_size, common::Encode::HexEncode(seckey).c_str(),
        common::Encode::HexEncode(message).c_str(), common::Encode::HexEncode(res_enc).c_str());
    return res_enc;
}

std::string Crypto::GetDecryptData(
        const std::string& pubkey,
        const std::string& crypt_message) {
    security::PublicKey pub_key(pubkey);
    std::string seckey;
    auto res = tenon::security::EcdhCreateKey::Instance()->CreateKey(pub_key, seckey);
    if (res != tenon::security::kSecuritySuccess) {
        CRYPTO_ERROR("create ecdh key failed!");
        return "";
    }

    std::string res_dec(crypt_message.size(), 0);
    if (security::Aes::Decrypt(
            (char*)crypt_message.c_str(),
            crypt_message.size(),
            (char*)seckey.c_str(),
            seckey.size(),
            (char*)&res_dec[0]) != security::kSecuritySuccess) {
        CRYPTO_ERROR("Decrypt error!");
        return "";
    }

    printf(" decrypt data_size decrypt message![%u, %u] sec: %s, encmsg: %s, dec msg: %s",
        crypt_message.size(), crypt_message.size(), common::Encode::HexEncode(seckey).c_str(),
        common::Encode::HexEncode(crypt_message).c_str(),
        common::Encode::HexEncode(res_dec).c_str());
    return res_dec;
}
};  // namespace security

};  // namespace tenon