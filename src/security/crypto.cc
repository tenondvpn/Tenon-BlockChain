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

    return res_enc;
}

std::string Crypto::GetDecryptData(
        const security::PublicKey& pub_key,
        const std::string& crypt_message) {
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

    return res_dec;
}
std::string Crypto::GetDecryptData(
        const std::string& pubkey,
        const std::string& crypt_message) {
    security::PublicKey pub_key(pubkey);
    return GetDecryptData(pub_key, crypt_message);
}

int Crypto::GetEncryptData(
        const std::string& enc_key,
        const std::string& message,
        std::string* enc_data) {
    uint32_t data_size = (message.size() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE + AES_BLOCK_SIZE;
    enc_data->resize(data_size, 0);
    if (security::Aes::Encrypt(
            (char*)message.c_str(),
            message.size(),
            (char*)enc_key.c_str(),
            enc_key.size(),
            (char*)&(*enc_data)[0]) != security::kSecuritySuccess) {
        return kSecurityError;
    }

    return kSecuritySuccess;
}

int Crypto::GetDecryptData(
        const std::string& enc_key,
        const std::string& crypt_message,
        std::string* dec_data) {
    dec_data->resize(crypt_message.size(), 0);
    if (security::Aes::Decrypt(
            (char*)crypt_message.c_str(),
            crypt_message.size(),
            (char*)enc_key.c_str(),
            enc_key.size(),
            (char*)&(*dec_data)[0]) != security::kSecuritySuccess) {
            CRYPTO_ERROR("Decrypt error!");
        return kSecurityError;
    }

    return kSecuritySuccess;
}



};  // namespace security

};  // namespace tenon