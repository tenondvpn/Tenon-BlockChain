#pragma once

#include "common/utils.h"
#include "common/thread_safe_queue.h"
#include "transport/transport_utils.h"
#include "services/vpn_server/vpn_svr_utils.h"

namespace tenon {

namespace vpn {

class FecOpenFecEncoder {
public:
    FecOpenFecEncoder() {}

    ~FecOpenFecEncoder() {}

    int Init(
            uint32_t param_k,
            uint32_t symbol_size,
            double loss_rate,
            int32_t socket,
            struct sockaddr* addr) {
        symbol_size_ = symbol_size;
        fec_param_k_ = param_k;
        socket_ = socket;
        addr_ = *addr;
        fec_param_n_ = (uint32_t)floor((double)fec_param_k_ / (double)loss_rate);
        of_rs_2_m_parameters_t	*my_params;
        my_params = (of_rs_2_m_parameters_t *)calloc(1, sizeof(*my_params));
        my_params->m = 8;
        fec_parameters_ = (of_parameters_t *)my_params;
        fec_parameters_->nb_source_symbols = fec_param_k_;
        fec_parameters_->nb_repair_symbols = fec_param_n_ - fec_param_k_;
        fec_parameters_->encoding_symbol_length = symbol_size;
        if (of_create_codec_instance(
                &fec_session_,
                fec_codec_id_,
                OF_ENCODER,
                0) != OF_STATUS_OK) {
            return kVpnsvrError;
        }

        if (of_set_fec_parameters(fec_session_, fec_parameters_) != OF_STATUS_OK) {
            return kVpnsvrError;
        }
        enc_symbols_tab_ = (void**)calloc(fec_param_n_, sizeof(void*));
        for (uint32_t i = fec_param_k_; i < fec_param_n_; ++i) {
            enc_symbols_tab_[i] = (char*)calloc(symbol_size_, 1);
            memset(enc_symbols_tab_[i], 0, symbol_size_);
        }

        fec_data_ = new char[symbol_size_ + sizeof(transport::TransportHeader)];
        reserve_data_ = (void**)calloc(fec_param_n_, sizeof(void*));
        for (uint32_t i = 0; i < fec_param_k_; ++i) {
            reserve_data_[i] = calloc(symbol_size_, 1);
            memset(reserve_data_[i], 0, symbol_size_);
        }

        return kVpnsvrSuccess;
    }

    void Push(void* data) {
        send_queue_.push(data);
        Output(false);
    }

    void Output(bool flush) {
        void* data = nullptr;
        if (send_queue_.pop(&data)) {
            enc_symbols_tab_[fec_data_index_++] = data;
        }

        if (fec_data_index_ == fec_param_k_ || flush) {
            transport::TransportHeader* fec_header = (transport::TransportHeader*)fec_data_;
            fec_header->type = kFecStream;
            fec_header->msg_no = fec_no_++;
            fec_header->frag.frag_sum = fec_data_index_;
            for (uint32_t i = fec_data_index_; i < fec_param_k_; ++i) {
                enc_symbols_tab_[i] = reserve_data_[i];
            }

            for (uint32_t i = fec_param_k_; i < fec_param_n_; ++i) {
                if (of_build_repair_symbol(fec_session_, enc_symbols_tab_, i) != OF_STATUS_OK) {
                    continue;
                }
            }

            for (uint32_t i = 0; i < fec_param_n_; ++i) {
                fec_header->frag.frag_no = i;
                fec_header->msg_index = i;
                memcpy(
                        fec_data_ + sizeof(transport::TransportHeader),
                        enc_symbols_tab_[i],
                        symbol_size_);
                sendto(
                        socket_,
                        fec_data_,
                        symbol_size_ + sizeof(transport::TransportHeader),
                        0,
                        (const struct sockaddr*)&addr_,
                        sizeof(addr_));
            }

            fec_data_index_ = 0;
        }
    }

private:
    of_parameters_t* fec_parameters_{ nullptr };
    uint32_t fec_param_k_{ kDefaultK };
    uint32_t fec_param_n_{ 0 };
    of_codec_id_t fec_codec_id_{ OF_CODEC_REED_SOLOMON_GF_2_M_STABLE };
    void** enc_symbols_tab_{ NULL };
    of_session_t* fec_session_{ NULL };
    uint32_t symbol_size_;
    uint32_t fec_data_index_{ 0 };
    common::ThreadSafeQueue<void*> send_queue_;
    uint32_t fec_no_{ 0 };
    char* fec_data_{ nullptr };
    void** reserve_data_{ nullptr };
    int32_t socket_{ 0 };
    struct sockaddr addr_;

    DISSALLOW_COPY_AND_ASSIGN(FecOpenFecEncoder);
};

}  // namespace vpn

}  // namespace tenon
