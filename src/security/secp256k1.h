#pragma once

#include <memory>

#include <secp256k1/secp256k1.h>
#include <secp256k1/secp256k1_ecdh.h>
#include <secp256k1/secp256k1_recovery.h>

#include "common/utils.h"

namespace tenon {

namespace security {

class Secp256k1 {
public:
    static Secp256k1* Instance();
    secp256k1_context const* getCtx() {
        static std::unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)> s_ctx{
            secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY),
            &secp256k1_context_destroy
        };
        return s_ctx.get();
    }

    std::string recover(const std::string& sign, const std::string& hash);
    std::string sha3(const std::string& input);
    bool ToPublic(const std::string& prikey, bool compress, std::string* pub_key);
    std::string ToPublicFromCompressed(const std::string& in_pubkey);
    std::string ToAddressWithPublicKey(const std::string& pub_key);
    std::string ToAddressWithPrivateKey(const std::string& pri_key);
    std::string GetContractAddress(
        const std::string& from,
        const std::string& gid,
        const std::string& bytes_code);

private:
    Secp256k1();
    ~Secp256k1();

    DISDISALLOW_COPY_AND_ASSIGN(Secp256k1);

};

}  // namespace security

}  // namespace tenon
