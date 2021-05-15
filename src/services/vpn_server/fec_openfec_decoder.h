#pragma once

#include <unordered_map>
#include <map>

#include "common/utils.h"
#include "common/thread_safe_queue.h"
#include "transport/transport_utils.h"
#include "services/vpn_server/vpn_svr_utils.h"

namespace lego {

namespace vpn {

struct SessionItem {
    of_session_t* fec_session;
    uint32_t count;
};

typedef void(*FecDecoderCallback)(
        transport::TransportHeader* header,
        struct sockaddr* from_addr,
        char* data,
        uint32_t len);

class FecOpenFecDecoder {
public:
    FecOpenFecDecoder() {}

    ~FecOpenFecDecoder() {}

    int Init(
            uint32_t param_k,
            uint32_t symbol_size,
            struct sockaddr* addr,
            FecDecoderCallback callback) {
        symbol_size_ = symbol_size;
        fec_param_k_ = param_k;
        fec_param_n_ = (uint32_t)floor((double)fec_param_k_ / (double)kCodeRate);
        of_rs_2_m_parameters_t	*my_params;
        my_params = (of_rs_2_m_parameters_t *)calloc(1, sizeof(*my_params));
        my_params->m = 8;
        fec_parameters_ = (of_parameters_t *)my_params;
        fec_parameters_->nb_source_symbols = fec_param_k_;
        fec_parameters_->nb_repair_symbols = fec_param_n_ - fec_param_k_;
        fec_parameters_->encoding_symbol_length = symbol_size;
        src_symbols_tab_ = (void**)calloc(fec_param_n_, sizeof(void*));
        callback_ = callback;
        addr_ = *addr;
        return kVpnsvrSuccess;
    }

    void Set(void* data) {
        transport::TransportHeader* fec_header = (transport::TransportHeader*)data;
        if (fec_header->msg_no < fec_no_) {
            return;
        }

        auto iter = receive_map_.find(fec_header->msg_no);
        of_session_t* fec_session{ NULL };
        uint32_t receive_count = 0;
        if (iter == receive_map_.end()) {
            if (of_create_codec_instance(
                    &fec_session,
                    fec_codec_id_,
                    OF_DECODER,
                    0) != OF_STATUS_OK) {
                return;
            }

            if (of_set_fec_parameters(
                    fec_session,
                    fec_parameters_) != OF_STATUS_OK) {
                return;
            }

            receive_map_[fec_header->msg_no] = { fec_session, 1 };
            receive_count = 1;
        } else {
            receive_count = ++iter->second.count;
            fec_session = iter->second.fec_session;
        }

        if (of_decode_with_new_symbol(
                fec_session,
                (char*)data + sizeof(transport::TransportHeader),
                fec_header->msg_index) == OF_STATUS_ERROR) {
            std::cout << "of_decode_with_new_symbol error." << std::endl;
            return;
        }

        if ((receive_count >= fec_param_k_) && of_is_decoding_complete(fec_session)) {
            if (of_get_source_symbols_tab(fec_session, src_symbols_tab_) == OF_STATUS_OK) {
                for (uint32_t i = 0; i < fec_param_k_; ++i) {
                    auto header = (transport::TransportHeader*)src_symbols_tab_[i];
                    callback_(
                            header,
                            &addr_,
                            (char*)src_symbols_tab_[i] + sizeof(transport::TransportHeader),
                            symbol_size_ - sizeof(transport::TransportHeader));
                    std::cout << "i: " << i << std::endl;
                }
            }

            if (fec_header->msg_no >= fec_no_) {
                for (uint32_t i = fec_no_; i <= fec_header->msg_no; ++i) {
                    of_release_codec_instance(receive_map_[i].fec_session);
                    receive_map_.erase(i);
                }

                fec_no_ = fec_header->msg_no + 1;
            }
        }

        if (fec_header->msg_no > max_fec_no_) {
            max_fec_no_ = fec_header->msg_no;
        }
    }

private:
    of_parameters_t* fec_parameters_{ nullptr };
    uint32_t fec_param_k_{ kDefaultK };
    uint32_t fec_param_n_{ 0 };
    of_codec_id_t fec_codec_id_{ OF_CODEC_REED_SOLOMON_GF_2_M_STABLE };
    uint32_t symbol_size_;
    uint32_t fec_no_{ 0 };
    std::unordered_map<uint32_t, SessionItem> receive_map_;
    uint32_t max_fec_no_{ 0 };
    void** src_symbols_tab_{ NULL };
    FecDecoderCallback callback_;
    struct sockaddr addr_;

    DISALLOW_COPY_AND_ASSIGN(FecOpenFecDecoder);
};

}  // namespace vpn

}  // namespace lego
