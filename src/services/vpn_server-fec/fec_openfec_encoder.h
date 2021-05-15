#pragma once

#include "common/utils.h"
#include "common/thread_safe_queue.h"
#include "common/time_utils.h"
#include "transport/transport_utils.h"
#include "services/vpn_server/vpn_svr_utils.h"

namespace lego {

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
        if (symbol_size_ + sizeof(transport::TransportHeader) >
                common::GlobalInfo::Instance()->udp_mtu()) {
            return kVpnsvrError;
        }

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

    void Push(char* item, uint32_t src_len, uint32_t server_id) {
        uint32_t content_len = symbol_size_ - sizeof(transport::TransportHeader);
        uint8_t frag_count = src_len / content_len;
        if (src_len % content_len > 0) {
            ++frag_count;
        }

        for (uint32_t i = 0; i < frag_count; ++i) {
            uint32_t len = content_len;
            if (i == (frag_count - 1)) {
                len = src_len % content_len;
                if (len == 0) {
                    len = content_len;
                }
            }

            char* tmp_buf = (char*)malloc(symbol_size_);
            transport::TransportHeader* header = (transport::TransportHeader*)tmp_buf;
            header->server_id = server_id;
            header->msg_no = msg_no_;
            header->type = kFecStream;
            header->frag.frag_sum = frag_count;
            header->frag.frag_no = i;
            header->frag.mtu = content_len;
            header->frag_len = len;
            header->size = src_len;
            uint32_t data_offset = (uint32_t)i * content_len;
            memcpy(tmp_buf + sizeof(transport::TransportHeader), item + data_offset, len);
            send_queue_.push(tmp_buf);
            Output();
        }

        ++msg_no_;
    }

    void Push(void* data) {
        send_queue_.push(data);
        Output();
    }

    void Output() {
        if (start_msg_no_)
        if (prev_output_tm_ms_ == 0) {
            prev_output_tm_ms_ = common::TimeUtils::TimestampMs();
        }

        void* data = nullptr;
        while (send_queue_.pop(&data)) {
            enc_symbols_tab_[fec_data_index_++] = data;
            if (fec_data_index_ == fec_param_k_) {
                break;
            }
        }

        if (fec_data_index_ == 0) {
            return;
        }

        auto now_tm_ms = common::TimeUtils::TimestampMs();
        if (fec_data_index_ == fec_param_k_ /*|| (now_tm_ms - prev_output_tm_ms_ >= kOutputTimeoutMs)*/) {
            transport::TransportHeader* b_header = (transport::TransportHeader*)enc_symbols_tab_[0];
            for (uint32_t i = fec_data_index_; i < fec_param_k_; ++i) {
                transport::TransportHeader* header = (transport::TransportHeader*)reserve_data_[i];
                *header = *b_header;
                header->frag.frag_no = 0;
                header->frag.frag_sum = 0;
                header->frag_len = 0;
                header->size = symbol_size_;
                header->fec_index = i;
                enc_symbols_tab_[i] = reserve_data_[i];
            }

            for (uint32_t i = fec_param_k_; i < fec_param_n_; ++i) {
                if (of_build_repair_symbol(fec_session_, enc_symbols_tab_, i) != OF_STATUS_OK) {
                    continue;
                }
            }
            static uint32_t t1 = 0;
            for (uint32_t i = 0; i < fec_param_k_; ++i) {
                transport::TransportHeader* fec_header = (transport::TransportHeader*)enc_symbols_tab_[i];
                fec_header->fec_no = fec_no_;
                fec_header->fec_index = i;
                sendto(
                        socket_,
                        (char*)enc_symbols_tab_[i],
                        symbol_size_,
                        0,
                        (const struct sockaddr*)&addr_,
                        sizeof(addr_));
                ++start_msg_no_;
                t1++;
            }

            for (uint32_t i = fec_param_k_; i < fec_param_n_; ++i) {
                transport::TransportHeader* header = (transport::TransportHeader*)fec_data_;
                *header = *b_header;
                header->size = 0;
                header->fec_index = i;
                memcpy(fec_data_ + sizeof(transport::TransportHeader), enc_symbols_tab_[i], symbol_size_);
                sendto(
                        socket_,
                        fec_data_,
                        symbol_size_ + sizeof(transport::TransportHeader),
                        0,
                        (const struct sockaddr*)&addr_,
                        sizeof(addr_));
                ++start_msg_no_;
                t1++;
            }

            for (uint32_t i = 0; i < fec_data_index_; ++i) {
                free((char*)enc_symbols_tab_[i]);
            }

            for (uint32_t i = fec_param_k_; i < fec_param_n_; ++i) {
                memset(enc_symbols_tab_[i], 0, symbol_size_);
            }

            ++fec_no_;
            fec_data_index_ = 0;
            prev_output_tm_ms_ = now_tm_ms;
            std::cout << "send fec pkgs: " << t1 << std::endl;
        }
    }

private:
    static const uint32_t kOutputTimeoutMs = 300u;
    static const uint32_t kWinodwSize = 1024;

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
    uint64_t prev_output_tm_ms_{ 0 };
    uint32_t msg_no_{ 0 };

    uint32_t start_msg_no_{ 0 };
    uint32_t ack_msg_no_{ 0 };

    DISSALLOW_COPY_AND_ASSIGN(FecOpenFecEncoder);
};

}  // namespace vpn

}  // namespace lego
