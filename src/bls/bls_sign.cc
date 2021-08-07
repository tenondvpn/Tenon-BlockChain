#include "bls/bls_sign.h"

namespace tenon {

namespace bls {

BlsSign::BlsSign() {}

BlsSign::~BlsSign() {}

static int char2int(char _input) {
    if (_input >= '0' && _input <= '9') {
        return _input - '0';
    }

    if (_input >= 'A' && _input <= 'F') {
        return _input - 'A' + 10;
    }

    if (_input >= 'a' && _input <= 'f') {
        return _input - 'a' + 10;
    }

    return -1;
}

static bool hex2carray(const char* _hex, uint64_t* _bin_len, uint8_t* _bin) {
    int len = strnlen(_hex, 2 * 1024);

    if (len == 0 && len % 2 == 1) {
        return false;
    }

    *_bin_len = len / 2;
    for (int i = 0; i < len / 2; i++) {
        int high = char2int((char)_hex[i * 2]);
        int low = char2int((char)_hex[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        _bin[i] = (unsigned char)(high * 16 + low);
    }

    return true;
}

int BlsSign::Sign(
        uint32_t t,
        uint32_t n,
        libff::alt_bn128_Fr& secret_key,
        const std::string& message,
        libff::alt_bn128_G1* common_signature) {
    auto hash_bytes_arr = std::make_shared< std::array< uint8_t, 32 > >();
    uint64_t bin_len;
    if (!hex2carray(message.c_str(), &bin_len, hash_bytes_arr->data())) {
        return kBlsError;
    }

    signatures::Bls bls_instance = signatures::Bls(t, n);
    libff::alt_bn128_G1 hash = bls_instance.HashtoG1(hash_bytes_arr);
    *common_signature = bls_instance.Signing(hash, secret_key);
    common_signature->to_affine_coordinates();
    return kBlsSuccess;
}

int BlsSign::Verify(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_G1& sign,
        const std::string& message,
        const libff::alt_bn128_G2& pkey) {
    if (!sign.is_well_formed()) {
        return kBlsError;
    }

    libff::inhibit_profiling_info = true;
    signatures::Bls bls_instance = signatures::Bls(t, n);
    auto hash_bytes_arr = std::make_shared< std::array< uint8_t, 32 > >();
    uint64_t bin_len;
    if (!hex2carray(message.c_str(), &bin_len, hash_bytes_arr->data())) {
        return kBlsError;
    }

    bool bRes = bls_instance.Verification(hash_bytes_arr, sign, pkey);
    if (!bRes) {
        return kBlsError;
    }
    
    return kBlsSuccess;
}

};  // namespace bls

};  // namespace tenon
