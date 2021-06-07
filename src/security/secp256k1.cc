#include "security/secp256k1.h"

#include <array>
#include <cassert>

#include <ethash/keccak.hpp>
#include "common/string_utils.h"
#include "common/encode.h"
#include "common/hash.h"
#include "block/block_utils.h"
#include "security/crypto_utils.h"

namespace tenon {

namespace security {

Secp256k1::Secp256k1() {}

Secp256k1::~Secp256k1() {}

Secp256k1* Secp256k1::Instance() {
    static Secp256k1 ins;
    return &ins;
}

std::string Secp256k1::recover(const std::string& sign, const std::string& hash) {
    std::string str_v = sign.substr(0, 32);
    std::string str_sig = sign.substr(32, sign.size() - 32);
    uint8_t v = (uint8_t)str_v[31] - (uint8_t)27;
    str_sig += (char)(v);
    if (v > 3) {
        return "";
    }

    auto* ctx = getCtx();
    secp256k1_ecdsa_recoverable_signature raw_sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            ctx,
            &raw_sig,
            (uint8_t*)str_sig.c_str(),
            v)) {
        return "";
    }

    secp256k1_pubkey raw_pubkey;
    if (!secp256k1_ecdsa_recover(ctx, &raw_pubkey, &raw_sig, (uint8_t*)hash.c_str())) {
        return "";
    }

    std::array<uint8_t, 65> serialized_pubkey;
    size_t serialized_pubkey_size = serialized_pubkey.size();
    secp256k1_ec_pubkey_serialize(
        ctx, serialized_pubkey.data(), &serialized_pubkey_size,
        &raw_pubkey, SECP256K1_EC_UNCOMPRESSED
    );

    return std::string((char*)&serialized_pubkey[1], 64);
}

std::string Secp256k1::sha3(const std::string& input) {
    ethash::hash256 h = ethash::keccak256((uint8_t*)input.c_str(), input.size());
    return std::string((char*)h.bytes, 32);
}

bool Secp256k1::ToPublic(const std::string& prikey, uint32_t flags, std::string* pub_key) {
    auto* ctx = getCtx();
    secp256k1_pubkey raw_pubkey;
    // Creation will fail if the secret key is invalid.
    if (!secp256k1_ec_pubkey_create(ctx, &raw_pubkey, (const uint8_t*)prikey.c_str())) {
        return false;
    }

    size_t serialized_pubkey_size = kPublicKeyUncompressSize;
    uint8_t data[kPublicKeyUncompressSize];
    secp256k1_ec_pubkey_serialize(ctx, data, &serialized_pubkey_size, &raw_pubkey, flags);
    *pub_key = std::string((char*)data, sizeof(data));
    return true;
}

std::string Secp256k1::ToPublicFromCompressed(const std::string& in_pubkey) {
    assert(in_pubkey.size() == kPublicKeySize);
    auto* ctx = getCtx();
    secp256k1_pubkey raw_pubkey;
    if (!secp256k1_ec_pubkey_parse(
            ctx,
            &raw_pubkey,
            (uint8_t*)in_pubkey.c_str(),
            in_pubkey.size())) {
        return "";
    }

    std::array<uint8_t, 65> serialized_pubkey;
    auto serialized_pubkey_size = serialized_pubkey.size();
    secp256k1_ec_pubkey_serialize(
        ctx,
        serialized_pubkey.data(),
        &serialized_pubkey_size,
        &raw_pubkey,
        SECP256K1_EC_UNCOMPRESSED);
    assert(serialized_pubkey_size == serialized_pubkey.size());
    assert(serialized_pubkey[0] == 0x04);
    return std::string((char*)serialized_pubkey.data(), serialized_pubkey.size());
}

std::string Secp256k1::ToAddressWithPublicKey(const std::string& pub_key) {
    if (!IsValidPublicKey(pub_key)) {
        return "";
    }

    if (pub_key.size() == kPublicKeySize) {
        return block::UnicastAddress(common::Hash::keccak256(
            ToPublicFromCompressed(pub_key).substr(1, 64)));
    }

    if (pub_key.size() == kPublicKeyUncompressSize) {
        return block::UnicastAddress(common::Hash::keccak256(pub_key.substr(1, 64)));
    }

    assert(pub_key.size() == kPublicKeyUncompressSize - 1);
    return block::UnicastAddress(common::Hash::keccak256(pub_key));
}

std::string Secp256k1::ToAddressWithPrivateKey(const std::string& pri_key) {
    std::string pub_key;
    if (!ToPublic(pri_key, SECP256K1_EC_UNCOMPRESSED, &pub_key)) {
        return "";
    }

    return block::UnicastAddress(common::Hash::keccak256(pub_key.substr(1, 64)));
}

std::string Secp256k1::GetContractAddress(
        const std::string& from,
        const std::string& gid,
        const std::string& bytes_code) {
    return block::UnicastAddress(common::Hash::keccak256(from + gid + bytes_code));
}

}  // namespace security

}  // namespace tenon
