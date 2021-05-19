#include <stdlib.h>
#include <math.h>

#include <iostream>

#include <gtest/gtest.h>

#include "common/utils.h"

#define private public
#define UNIT_TEST

#include "common/global_info.h"
#include "services/vpn_server/fec_openfec_encoder.h"
#include "services/vpn_server/fec_openfec_decoder.h"

namespace tenon {

namespace vpn {

namespace test {

class TestOpenFec : public testing::Test {
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

static const int32_t kParamK = 16;
static const int32_t kParamT = 1400;
static const double kCodeRate = 0.667;

TEST_F(TestOpenFec, FecOpenFecEncoder0) {
    FecOpenFecEncoder fec_encoder;
    struct sockaddr_in des_addr;
    if (uv_ip4_addr("127.0.0.1", 7891, &des_addr) != 0) {
        VPNSVR_ERROR("create uv ipv4 addr failed!");
        return;
    }

    ASSERT_EQ(fec_encoder.Init(
            kParamK,
            kParamT,
            kCodeRate,
            0,
            (struct sockaddr*)&des_addr), kVpnsvrSuccess);
    for (uint32_t i = 0; i < kParamK + 5; ++i) {
        void* data = malloc(kParamT);
        fec_encoder.Push(data);
    }

    ASSERT_EQ(fec_encoder.fec_no_, 1);
    usleep((fec_encoder.kOutputTimeoutMs + 10) * 1000);
    fec_encoder.Output();
    ASSERT_EQ(fec_encoder.fec_no_, 2);
}

void FecDecoderCallback(
        transport::TransportHeader* header,
        struct sockaddr* addr,
        char* data,
        uint32_t len) {
    uint32_t* udata = (uint32_t*)data;
    for (uint32_t idx = 0; idx < len / 4; ++idx) {
        ASSERT_EQ(udata[idx], idx);
    }
}

TEST_F(TestOpenFec, FecOpenFecDecoder0) {
    FecOpenFecEncoder fec_encoder;
    struct sockaddr_in des_addr;
    if (uv_ip4_addr("127.0.0.1", 7891, &des_addr) != 0) {
        VPNSVR_ERROR("create uv ipv4 addr failed!");
        return;
    }

    ASSERT_EQ(fec_encoder.Init(
        kParamK,
        kParamT,
        kCodeRate,
        0,
        (struct sockaddr*)&des_addr), kVpnsvrSuccess);
    uint32_t fec_no = 0;
    for (uint32_t i = 0; i < kParamK; ++i) {
        uint32_t len = rand() % (64000 - 100) + 100;
        void* data = malloc(len);
        uint32_t* udata = (uint32_t*)data;
        for (uint32_t idx = 0; idx < len / 4; ++idx) {
            udata[idx] = idx;
        }

        fec_no += (len / (fec_encoder.symbol_size_ - sizeof(transport::TransportHeader)));
        if (len % (fec_encoder.symbol_size_ - sizeof(transport::TransportHeader)) != 0) {
            ++fec_no;
        }

        fec_encoder.Push((char*)data, len, 1);
    }

    fec_no /= kParamK;
    ASSERT_EQ(fec_no, fec_encoder.fec_no_);
    if (fec_encoder.fec_data_index_ > 0) {
        usleep((fec_encoder.kOutputTimeoutMs + 10) * 1000);
        fec_encoder.Output();
        ASSERT_EQ(fec_encoder.fec_no_, fec_no + 1);
    }

    ASSERT_EQ(fec_encoder.fec_data_index_, 0);

}

TEST_F(TestOpenFec, FecOpenFecDecoder1) {
    FecOpenFecEncoder fec_encoder;
    struct sockaddr_in des_addr;
    if (uv_ip4_addr("127.0.0.1", 7891, &des_addr) != 0) {
        VPNSVR_ERROR("create uv ipv4 addr failed!");
        return;
    }

    ASSERT_EQ(fec_encoder.Init(
        kParamK,
        kParamT,
        kCodeRate,
        0,
        (struct sockaddr*)&des_addr), kVpnsvrSuccess);

    for (uint32_t i = 0; i < kParamK; ++i) {
        uint32_t len = fec_encoder.symbol_size_ - sizeof(transport::TransportHeader);
        void* data = malloc(len);
        uint32_t* udata = (uint32_t*)data;
        for (uint32_t idx = 0; idx < len / 4; ++idx) {
            udata[idx] = idx;
        }

        fec_encoder.Push((char*)data, len, 1);
    }

    ASSERT_EQ(fec_encoder.fec_data_index_, 0);
    ASSERT_EQ(fec_encoder.fec_no_, 1);
    FecOpenFecDecoder fec_decoder;
    ASSERT_EQ(fec_decoder.Init(
            kParamK,
            kParamT,
            (struct sockaddr*)&des_addr,
            FecDecoderCallback), kVpnsvrSuccess);
    ASSERT_EQ(fec_encoder.fec_param_n_, 23);
    srand(time(0));
    for (uint32_t i = 0; i < fec_encoder.fec_param_k_; ++i) {
        if (i == 2 || i == 8 || i == 9) {
            continue;
        }

        void* data = malloc(fec_encoder.symbol_size_);
        memcpy(data, fec_encoder.enc_symbols_tab_[i], fec_encoder.symbol_size_);
        fec_decoder.Set(data);
    }

    transport::TransportHeader* fec_header =
            (transport::TransportHeader*)fec_encoder.enc_symbols_tab_[0];
    for (uint32_t i = fec_encoder.fec_param_k_; i < fec_encoder.fec_param_n_; ++i) {
        if (i == 3 || i == 5) {
            continue;
        }

        void* data = malloc(fec_encoder.symbol_size_ + sizeof(transport::TransportHeader));
        transport::TransportHeader* header = (transport::TransportHeader*)data;
        *header = *fec_header;
        header->size = 0;
        fec_header->fec_index = i;
        memcpy(
                (char*)data + sizeof(transport::TransportHeader),
                fec_encoder.enc_symbols_tab_[i],
                fec_encoder.symbol_size_);
        fec_decoder.Set(data);
    }

    ASSERT_EQ(fec_decoder.fec_no_, 1);
}

}  // namespace test

}  // namespace vpn

}  // namespace tenon
