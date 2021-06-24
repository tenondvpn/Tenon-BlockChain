#include "security/crypto.h"

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include "security/ecdh_create_key.h"
#include "security/aes.h"

namespace tenon {

namespace security {

Crypto* Crypto::Instance() {
    static Crypto ins;
    return &ins;
}

std::string Crypto::AesEncrypt(
        const std::string& cipher,
        const std::string& password,
        uint32_t rounds,
        const std::string& salt) {

    return "";
}

std::string Crypto::AesDecrypt(
        const std::string& cipher,
        const std::string& password,
        uint32_t rounds,
        const std::string& salt) {
    uint8_t target[64] = { 0 };
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256>().DeriveKey(
        target,
        sizeof(target),
        0,
        (uint8_t*)password.c_str(),
        password.size(),
        (uint8_t*)salt.c_str(),
        salt.size(),
        rounds);

    try
    {
        CryptoPP::AES::Decryption aes_desc(target, 16);
        auto ci = cipher.substr(16, cipher.size() - 16);
        auto iv = cipher.substr(0, 16);
        CryptoPP::CBC_Mode_ExternalCipher::Decryption cbc_decryption(aes_desc, (uint8_t*)iv.c_str());
        std::string decrypted;
        CryptoPP::StreamTransformationFilter stf_decryptor(cbc_decryption, new CryptoPP::StringSink(decrypted));
        stf_decryptor.Put((uint8_t*)ci.c_str(), ci.size());
        stf_decryptor.MessageEnd();
        return decrypted;
    }
    catch (std::exception const& e)
    {
        std::cerr << e.what() << '\n';
        return "";
    }
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