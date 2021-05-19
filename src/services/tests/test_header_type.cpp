#include <stdlib.h>
#include <math.h>

#include <iostream>

#include <gtest/gtest.h>

#include "common/utils.h"
#ifdef __cplusplus
extern "C" {
#endif

#include "ssr/crypto.h"

#ifdef __cplusplus
}
#endif
#define private public
#define UNIT_TEST

#include "common/global_info.h"
#include "common/header_type.h"
#include "common/time_utils.h"
#include "security/schnorr.h"
#include "services/proto/service_proto.h"

namespace tenon {

namespace vpn {

namespace test {

class TestHeaderType : public testing::Test {
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

TEST_F(TestHeaderType, FecOpenFecDecoder1) {
    common::HeaderType header_type;
    header_type.Init();
    buffer_t* buf = (buffer_t*)ss_malloc(sizeof(buffer_t));
    ASSERT_TRUE(buf != NULL);
    balloc(buf, 1024);
    std::cout << "buf->capacity: " << buf->capacity << std::endl;
    ASSERT_TRUE(buf->data != NULL);
    uint32_t* head = (uint32_t*)(buf->data);
    head[0] = header_type.GetRandNum(common::kStreamConnect);
    head[1] = common::kStreamMagicNum;
    head[2] = 1;
    struct in_addr s;
    inet_pton(AF_INET, "192.168.9.10", &s);
    head[3] = s.s_addr;
    uint16_t* local_port = (uint16_t*)(head + 4);
    buf->len = sizeof(uint32_t) * 4 + sizeof(uint16_t);
    common::HeaderType::Instance()->Encrypt(head[0], buf);
}

}  // namespace test

}  // namespace vpn

}  // namespace tenon
