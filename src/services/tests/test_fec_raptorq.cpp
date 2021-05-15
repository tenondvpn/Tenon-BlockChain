#include <stdlib.h>
#include <math.h>

#include <iostream>

#include <gtest/gtest.h>

#include "common/utils.h"
#include "common/time_utils.h"

#define private public
#include "common/global_info.h"
#include "services/vpn_server/fec_raptorq.h"

namespace lego {

namespace vpn {

namespace test {

class TestFecRaptorQ : public testing::Test {
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

TEST_F(TestFecRaptorQ, All) {
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    uint64_t t3 = 0;
    uint64_t t4 = 0;
    uint64_t t5 = 0;
    uint64_t t6 = 0;
    uint64_t at0 = 0;
    uint64_t at1 = 0;
    uint64_t at2 = 0;
    uint64_t at3 = 0;
    uint64_t at4 = 0;
    uint64_t at5 = 0;
    uint64_t at6 = 0;
    static const uint32_t kTestCount = 1;
    for (uint32_t i = 0; i < kTestCount; ++i) {
        t1 = common::TimeUtils::TimestampUs();
        srand((unsigned)time(NULL));
        static const int32_t kParamK = 8;
        static const int32_t kParamT = 1400;
        static const double kLossRate = 0.05;

        FecRaptorQ fec_encoder(true);
        fec_encoder.SetParam(kParamK, kParamT, kLossRate);
        char** data = new char*[kParamK];
        for (uint32_t i = 0; i < kParamK; ++i) {
            data[i] = new char[kParamT];
            memset(data[i], 0, kParamT);
            uint32_t* int_arr = (uint32_t*)data[i];
            for (uint32_t i = 0; i < 1400 / 4; ++i) {
                int_arr[i] = i;
            }
        }

        char **received = new char*[kParamK + fec_encoder.overhead_];
        for (int32_t i = 0; i < kParamK + fec_encoder.overhead_; i++) {
            received[i] = new char[kParamT];
        }

        t2 = common::TimeUtils::TimestampUs();
        Symbol** res = fec_encoder.EncodeData(data);
        t3 = common::TimeUtils::TimestampUs();
        int *esi = new int[kParamK + fec_encoder.overhead_];
        int lost_count = 0;
        int *lost = new int[kParamK];
        int receive_count = 0;
        for (int32_t i = 0; i < kParamK; i++) {
            if ((rand() % RAND_MAX) / (RAND_MAX + 1.0) > fec_encoder.lossrate_ && i != 2) {
                memcpy(received[receive_count], data[i], kParamT);
                esi[receive_count] = i;
                receive_count++;
            } else {
                lost[lost_count++] = i;
            }
        }

        for (int32_t i = 0; i < fec_encoder.overhead_; i++) {
            if ((rand() % RAND_MAX) / (RAND_MAX + 1.0) > fec_encoder.lossrate_) {
                memcpy(received[receive_count], res[i]->data, kParamT);
                esi[receive_count] = kParamK + i;
                receive_count++;
            }
        }

        {
            FecRaptorQ fec_decoder(false);
            fec_decoder.SetParam(kParamK, kParamT, fec_decoder.lossrate_);
            t4 = common::TimeUtils::TimestampUs();
            fec_decoder.DecodeData(received, receive_count, esi);
            for (int32_t i = 0; i < lost_count; ++i) {
                Symbol* s = fec_decoder.RecoverData(lost[i]);
                EXPECT_TRUE(memcmp(s->data, data[lost[i]], kParamT) == 0);
            }
            t5 = common::TimeUtils::TimestampUs();
        }

        delete[] lost;
        delete[] esi;
        for (int32_t i = 0; i < kParamK + fec_encoder.overhead_; i++) {
            delete[] received[i];
        }
        delete[] received;

        for (int32_t i = 0; i < kParamK; i++) {
            delete[] data[i];
        }
        delete[] data;
        t6 = common::TimeUtils::TimestampUs();
        at0 += t6 - t1;
        at1 += t2 - t1;
        at2 += t3 - t2;
        at3 += t4 - t3;
        at4 += t5 - t4;
        at5 += t6 - t5;
    }

    std::cout << "at0: " << at0 / kTestCount
        << ", at1: " << at1 / kTestCount
        << ", at2: " << at2 / kTestCount
        << ", at3: " << at3 / kTestCount
        << ", at4: " << at4 / kTestCount
        << ", at5: " << at5 / kTestCount
        << std::endl;
}

}  // namespace test

}  // namespace common

}  // namespace lego
