#include <stdlib.h>
#include <math.h>

#include <iostream>

#include <gtest/gtest.h>

#include "common/utils.h"

#define private public
#define UNIT_TEST

#include "common/global_info.h"
#include "services/vpn_server/fec_window.h"

namespace tenon {

namespace vpn {

namespace test {

class TestFecWindow : public testing::Test {
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

TEST_F(TestFecWindow, SendPush) {
    FecWindow fec_window;
    struct sockaddr_in des_addr;
    if (uv_ip4_addr("127.0.0.1", 7891, &des_addr) != 0) {
        VPNSVR_ERROR("create uv ipv4 addr failed!");
        return;
    }
    
    static const int32_t kParamT = 1400;
    static const double kLossRate = 0.2;

    fec_window.Init(kParamT, kLossRate, (struct sockaddr*)&des_addr, 0);
    char data[FecWindow::kFecParamK][1400];
    for (uint32_t i = 0; i < FecWindow::kFecParamK; ++i) {
        fec_window.SendPush(data[i]);
    }

    ASSERT_EQ(fec_window.fec_no_, 1);

//     int32_t overhead = (int32_t)((FecWindow::kFecParamK * kLossRate + 10.0) / (1.0 - kLossRate));
//     ASSERT_EQ(overhead, fec_window.fec_encoder_.overhead());
//     std::cout << "over load: " << fec_window.fec_encoder_.overhead() << std::endl;
//     char **received = new char*[FecWindow::kFecParamK + fec_window.fec_encoder_.overhead()];
//     for (int32_t i = 0; i < FecWindow::kFecParamK + fec_window.fec_encoder_.overhead(); i++) {
//         received[i] = new char[1400];
//     }
// 
//     int *esi = new int[FecWindow::kFecParamK + fec_window.fec_encoder_.overhead()];
//     int lost_count = 0;
//     int *lost = new int[FecWindow::kFecParamK];
//     int receive_count = 0;
//     for (int32_t i = 0; i < FecWindow::kFecParamK; i++) {
//         if (rand() / (RAND_MAX + 1.0) > fec_encoder.lossrate_ && i != 2) {
//             memcpy(received[receive_count], data[i], kParamT);
//             esi[receive_count] = i;
//             receive_count++;
//         }
//         else {
//             lost[lost_count++] = i;
//         }
//     }
// 
//     for (int32_t i = 0; i < fec_encoder.overhead_; i++) {
//         if (rand() / (RAND_MAX + 1.0) > fec_encoder.lossrate_) {
//             memcpy(received[receive_count], res[i]->data, kParamT);
//             esi[receive_count] = kParamK + i;
//             receive_count++;
//         }
//     }
}

}  // namespace test

}  // namespace vpn

}  // namespace tenon
