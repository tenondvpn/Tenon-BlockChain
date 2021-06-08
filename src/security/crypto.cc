#include "security/crypto.h"

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>

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

};  // namespace security

};  // namespace tenon