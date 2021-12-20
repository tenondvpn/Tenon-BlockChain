#include "dht/dht_utils.h"

#include "dht/proto/dht.pb.h"
#include "dht/dht_key.h"
#include "openssl/aes.h"
#include "security/crypto_utils.h"
#include "security/ecdh_create_key.h"
#include "security/aes.h"
#include "security/schnorr.h"

namespace tenon {

namespace dht {

int DefaultDhtSignCallback(
        const std::string& peer_pubkey,
        const std::string& append_data,
        std::string* enc_data,
        std::string* sign_ch,
        std::string* sign_re) {
    std::string sec_key;
    security::PublicKey pubkey(peer_pubkey);
    if (security::EcdhCreateKey::Instance()->CreateKey(
        pubkey,
        sec_key) != security::kSecuritySuccess) {
        return dht::kDhtError;
    }

    auto now_tm_sec = std::chrono::steady_clock::now().time_since_epoch().count() /
        1000000000llu;
    std::string enc_src_data = std::to_string(now_tm_sec);
    uint32_t data_size = (enc_src_data.size() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE + AES_BLOCK_SIZE;
    char* tmp_out_enc = (char*)malloc(data_size);
    memset(tmp_out_enc, 0, data_size);
    if (security::Aes::Encrypt(
            (char*)enc_src_data.c_str(),
            enc_src_data.size(),
            (char*)sec_key.c_str(),
            sec_key.size(),
            tmp_out_enc) != security::kSecuritySuccess) {
        free(tmp_out_enc);
        return dht::kDhtError;
    }
    
    *enc_data = std::string(tmp_out_enc, data_size);
    free(tmp_out_enc);
    security::Signature sign;
    bool sign_res = security::Schnorr::Instance()->Sign(
        *enc_data,
        *(security::Schnorr::Instance()->prikey()),
        *(security::Schnorr::Instance()->pubkey()),
        sign);
    if (!sign_res) {
        return dht::kDhtError;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    *sign_ch = sign_challenge_str;
    *sign_re = sign_response_str;
    return dht::kDhtSuccess;
}

}  // namespace dht

}  // namespace tenon
