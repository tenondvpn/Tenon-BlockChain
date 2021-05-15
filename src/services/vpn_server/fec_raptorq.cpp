#include "services/vpn_server/fec_raptorq.h"

namespace lego {

namespace vpn {

void FecRaptorQ::SetParam(int32_t param_k, int32_t param_t, double lossrate) {
    param_k_ = param_k;
    param_t_ = param_t;
    lossrate_ = lossrate;
    overhead_ = (int32_t)((param_k_ * lossrate_ + 2.5) / (1.0 - lossrate_));

    if (is_encoder_) {
        encoder_ = std::make_shared<Encoder>();
        encoder_->init(param_k_, param_t_);
    } else {
        decoder_ = std::make_shared<Decoder>();
        decoder_->init(param_k_, param_t_);
    }
}

Symbol** FecRaptorQ::EncodeData(char** data) {
    return encoder_->encode(data, overhead_);
}

void FecRaptorQ::DecodeData(char** data, int32_t received_count, int32_t* esi) {
    decoder_->decode(data, received_count, esi);
}

Symbol* FecRaptorQ::RecoverData(int32_t lost_index) {
    return decoder_->recover(lost_index);
}

}  // namespace vpn

}  // namespace lego
