#include "stdafx.h"
#include "security/schnorr.h"

#include <memory.h>

#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ossl_typ.h>

#include "security/curve.h"
#include "security/crypto_utils.h"
#include "security/sha256.h"
#include "security/secp256k1.h"

#if OPENSSL_VERSION_NUMBER < 0x1010007fL  // only needed before OpenSSL 1.1.0g
//#define ARMEABI_V7A
#ifndef ARMEABI_V7A
#ifdef __cplusplus
extern "C" {
#endif

int BN_generate_dsa_nonce(
        BIGNUM *out,
        const BIGNUM *range,
        const BIGNUM *priv,
        const unsigned char *message,
        size_t message_len,
        BN_CTX *ctx) {
    SHA512_CTX sha;
    unsigned char random_bytes[64];
    unsigned char digest[SHA512_DIGEST_LENGTH];
    unsigned done, todo;
    const unsigned num_k_bytes = BN_num_bytes(range) + 8;
    unsigned char private_bytes[96];
    unsigned char *k_bytes;
    int ret = 0;

    k_bytes = (unsigned char *)OPENSSL_malloc(num_k_bytes);
    if (k_bytes == NULL)
        goto err;

    todo = sizeof(priv->d[0]) * priv->top;
    if (todo > sizeof(private_bytes)) {
        goto err;
    }
    memcpy(private_bytes, priv->d, todo);
    memset(private_bytes + todo, 0, sizeof(private_bytes) - todo);

    for (done = 0; done < num_k_bytes;) {
        if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1)
            goto err;
        SHA512_Init(&sha);
        SHA512_Update(&sha, &done, sizeof(done));
        SHA512_Update(&sha, private_bytes, sizeof(private_bytes));
        SHA512_Update(&sha, message, message_len);
        SHA512_Update(&sha, random_bytes, sizeof(random_bytes));
        SHA512_Final(digest, &sha);

        todo = num_k_bytes - done;
        if (todo > SHA512_DIGEST_LENGTH)
            todo = SHA512_DIGEST_LENGTH;
        memcpy(k_bytes + done, digest, todo);
        done += todo;
    }

    if (!BN_bin2bn(k_bytes, num_k_bytes, out))
        goto err;
    if (BN_mod(out, out, range, ctx) != 1)
        goto err;
    ret = 1;

err:
    OPENSSL_free(k_bytes);
    OPENSSL_cleanse(private_bytes, sizeof(private_bytes));
    return ret;
}
#ifdef __cplusplus
}
#endif
#endif

#endif

namespace tenon {

namespace security {

Schnorr* Schnorr::Instance() {
    static Schnorr ins;
    return &ins;
}

Schnorr::Schnorr() {}

Schnorr::~Schnorr() {}

void Schnorr::GenPublicKey(PrivateKey& prikey, PublicKey& pubkey) {
    std::lock_guard<std::mutex> guard(schonorr_mutex_);
    pubkey = PublicKey(prikey);
}

void Schnorr::set_prikey(const std::shared_ptr<PrivateKey>& prikey) {
    prikey_ptr_ = prikey;
    prikey_ptr_->Serialize(str_prikey_);
    assert(str_prikey_.size() == 32);
    pubkey_ptr_ = std::make_shared<PublicKey>(*(prikey.get()));
    pubkey_ptr_->Serialize(str_pubkey_, true);
    pubkey_ptr_->Serialize(str_pubkey_uncompress_, false);
}

bool Schnorr::Sign(
        const std::string& message,
        const PrivateKey& privkey,
        const PublicKey& pubkey,
        Signature& result) {
    std::string sig;
    bool res = security::Secp256k1::Instance()->Secp256k1Sign(
        message,
        privkey,
        &sig);
    if (!res) {
        return res;
    }

    result = Signature(sig);
    return res;
}

bool Schnorr::Verify(
        const std::string& message,
        const Signature& toverify,
        const PublicKey& pubkey) {
    return security::Secp256k1::Instance()->Secp256k1Verify(message, pubkey, toverify);
}

}  // namespace security

}  // namespace tenon
