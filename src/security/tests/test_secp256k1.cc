#include <stdlib.h>
#include <math.h>

#include <iostream>
#include <vector>

#include <gtest/gtest.h>
#include "openssl/aes.h"

#include "common/random.h"
#include "common/encode.h"
#include "security/secp256k1.h"

namespace tenon {

namespace security {

namespace test {

class TestSecp256k1 : public testing::Test {
public:
    static void SetUpTestCase() {
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }
};

TEST_F(TestSecp256k1, TestPrikeyPubkeyId) {
    static const char* kRootNodeIdEndFix = "2f72f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b4851";
    std::vector<std::string> pri_vec;
    for (uint32_t i = 1; i < 100; ++i) {
        char from_data[128];
        snprintf(from_data, sizeof(from_data), "%04d%s", i, kRootNodeIdEndFix);
        std::string pri_key(from_data);
        pri_key = common::Encode::HexDecode(pri_key);
        std::cout << "pri_key: " << common::Encode::HexEncode(pri_key) << std::endl;
        std::string to_pubkey_compress;
        security::Secp256k1::Instance()->ToPublic(pri_key, true, &to_pubkey_compress);
        std::cout << "to_pubkey_compress: " << common::Encode::HexEncode(to_pubkey_compress) << std::endl;
        std::string to_pubkey_uncompress;
        security::Secp256k1::Instance()->ToPublic(pri_key, false, &to_pubkey_uncompress);
        std::cout << "to_pubkey_uncompress: " << common::Encode::HexEncode(to_pubkey_uncompress) << std::endl;
        std::string recover_from_compress_pubkey = security::Secp256k1::Instance()->ToPublicFromCompressed(to_pubkey_compress);
        ASSERT_EQ(recover_from_compress_pubkey, to_pubkey_uncompress);
        std::string addr_from_compress_pubkey = Secp256k1::Instance()->ToAddressWithPublicKey(to_pubkey_compress);
        std::string addr_from_uncompress_pubkey = Secp256k1::Instance()->ToAddressWithPublicKey(to_pubkey_uncompress);
        std::string addr_from_prikey = Secp256k1::Instance()->ToAddressWithPrivateKey(pri_key);
        ASSERT_EQ(addr_from_compress_pubkey, addr_from_compress_pubkey);
        ASSERT_EQ(addr_from_prikey, addr_from_compress_pubkey);
    }
}

}  // namespace test

}  // namespace security

}  // namespace tenon
