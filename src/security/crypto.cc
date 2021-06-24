#include "security/crypto.h"

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
    char* tmp_out_enc = (char*)malloc(data_size);
    memset(tmp_out_enc, 0, data_size);
    if (security::Aes::Encrypt(
            (char*)message.c_str(),
            message.size(),
            (char*)seckey.c_str(),
            seckey.size(),
            tmp_out_enc) != security::kSecuritySuccess) {
        free(tmp_out_enc);
        return "";
    }

    free(tmp_out_enc);
    return std::string(tmp_out_enc, data_size);
}

std::string Crypto::GetDecryptData(
        const std::string& pubkey,
        const std::string& crypt_message) {
    security::PublicKey pub_key(pubkey);
    std::string seckey;
    auto res = tenon::security::EcdhCreateKey::Instance()->CreateKey(pub_key, seckey);
    if (res != tenon::security::kSecuritySuccess) {
        return "";
    }

    uint32_t data_size = (crypt_message.size() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE + AES_BLOCK_SIZE;
    if (data_size != crypt_message.size()) {
        return "";
    }

    char* tmp_out_enc = (char*)malloc(data_size);
    memset(tmp_out_enc, 0, data_size);
    if (security::Aes::Decrypt(
            (char*)crypt_message.c_str(),
            crypt_message.size(),
            (char*)seckey.c_str(),
            seckey.size(),
            tmp_out_enc) != security::kSecuritySuccess) {
        free(tmp_out_enc);
        return "";
    }

    free(tmp_out_enc);
    return std::string(tmp_out_enc, data_size);
}
};  // namespace security

};  // namespace tenon