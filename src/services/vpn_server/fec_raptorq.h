#pragma once

#include "common/utils.h"
#include "raptorQ/Helper.h"
#include "raptorQ/Symbol.h"

namespace lego {

namespace vpn {

class FecRaptorQ {
public:
    FecRaptorQ(bool is_encoder) : is_encoder_(is_encoder) {}
    ~FecRaptorQ() {}
    void SetParam(int32_t param_k, int32_t param_t, double lossrate);
    Symbol** EncodeData(char** data);
    void DecodeData(char** data, int32_t received_count, int32_t* esi);
    Symbol* RecoverData(int32_t lost_index);
    int32_t overhead() {
        return overhead_;
    }

private:
    bool is_encoder_{ false };
    int32_t param_k_{ 8 };
    int32_t param_t_{ 1400 };
    double lossrate_{ 0.2 };
    int32_t overhead_{ 0 };
    std::shared_ptr<Encoder> encoder_{ nullptr };
    std::shared_ptr<Decoder> decoder_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(FecRaptorQ);
};

}  // namespace vpn

}  // namespace lego
