#pragma once

#include <unordered_map>
#include <map>
#include <vector>

#include "common/utils.h"
#include "common/thread_safe_queue.h"
#include "common/bitmap.h"
#include "transport/transport_utils.h"
#include "services/vpn_server/vpn_svr_utils.h"

namespace lego {

namespace vpn {

struct SessionItem {
    of_session_t* fec_session;
    uint32_t count;
    std::vector<void*> data;
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
        static uint32_t t1 = 0;
        t1++;
        std::cout << "receive fec pkgs: " << t1 << std::endl;
        transport::TransportHeader* fec_header = (transport::TransportHeader*)data;
        if (handled_fec_no_.find(fec_header->fec_no) != handled_fec_no_.end()) {
            return;
        }

        auto iter = receive_map_.find(fec_header->fec_no);
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

            std::vector<void*> data_vec;
            data_vec.push_back(data);
            receive_map_[fec_header->fec_no] = { fec_session, 1, data_vec };
            receive_count = 1;
        } else {
            receive_count = ++iter->second.count;
            fec_session = iter->second.fec_session;
            iter->second.data.push_back(data);
        }

        if (fec_header->size == 0) {
            if (of_decode_with_new_symbol(
                    fec_session,
                    (char*)data + sizeof(transport::TransportHeader),
                    fec_header->fec_index) == OF_STATUS_ERROR) {
                return;
            }
        } else {
            if (of_decode_with_new_symbol(
                    fec_session,
                    (char*)data,
                    fec_header->fec_index) == OF_STATUS_ERROR) {
                return;
            }
        }

        if ((receive_count >= fec_param_k_) && of_is_decoding_complete(fec_session)) {
            if (of_get_source_symbols_tab(fec_session, src_symbols_tab_) == OF_STATUS_OK) {
                for (uint32_t i = 0; i < fec_param_k_; ++i) {
                    HandleDataSet((char*)src_symbols_tab_[i], symbol_size_);
                }

                auto iter = receive_map_.find(fec_header->fec_no);
                assert(iter != receive_map_.end());
                for (auto data_iter = iter->second.data.begin();
                    data_iter != iter->second.data.end(); ++data_iter) {
                    free(*data_iter);
                }

                of_release_codec_instance(iter->second.fec_session);
                receive_map_.erase(iter);
            }

            handled_fec_no_.insert(fec_header->fec_no);
        }

        if (fec_header->fec_no > max_fec_no_) {
            max_fec_no_ = fec_header->fec_no;
        }
    }

private:
    void HandleDataSet(char* item, uint32_t len) {
        transport::TransportHeader* in_header = (transport::TransportHeader*)item;
        if (in_header->frag.frag_sum == 1) {
            callback_(
                    in_header,
                    &addr_,
                    item + sizeof(transport::TransportHeader),
                    in_header->size);
        } else if (in_header->frag.frag_sum > 1) {
            auto iter = window_map_.find(in_header->msg_no);
            char* tmp_buf = nullptr;
            if (iter == window_map_.end()) {
                tmp_buf = new char[in_header->size + sizeof(transport::TransportHeader)];
                transport::TransportHeader* header = (transport::TransportHeader*)tmp_buf;
                *header = *in_header;
                common::Bitmap* bitmap = new common::Bitmap(64);
                bitmap->Set(in_header->frag.frag_no);
                window_map_[in_header->msg_no] = std::make_pair(
                        tmp_buf,
                        bitmap);
                iter = window_map_.find(in_header->msg_no);
            } else {
                tmp_buf = iter->second.first;
                if (!iter->second.second->Valid(in_header->frag.frag_no)) {
                    iter->second.second->Set(in_header->frag.frag_no);
                }
            }

            uint32_t data_offset = (
                    (uint32_t)in_header->frag.frag_no * (uint32_t)in_header->frag.mtu +
                    sizeof(transport::TransportHeader));
            memcpy(
                    tmp_buf + data_offset,
                    item + sizeof(transport::TransportHeader),
                    in_header->frag_len);
            if (iter->second.second->valid_count() == in_header->frag.frag_sum) {
                callback_(
                        in_header,
                        &addr_,
                        tmp_buf + sizeof(transport::TransportHeader),
                        in_header->size);
                delete iter->second.second;
                delete[] iter->second.first;
                window_map_.erase(in_header->msg_no);
            }
        }
    }

    of_parameters_t* fec_parameters_{ nullptr };
    uint32_t fec_param_k_{ kDefaultK };
    uint32_t fec_param_n_{ 0 };
    of_codec_id_t fec_codec_id_{ OF_CODEC_REED_SOLOMON_GF_2_M_STABLE };
    uint32_t symbol_size_;
    std::unordered_map<uint32_t, SessionItem> receive_map_;
    uint32_t max_fec_no_{ 0 };
    void** src_symbols_tab_{ NULL };
    FecDecoderCallback callback_;
    struct sockaddr addr_;
    std::unordered_map<uint32_t, std::pair<char*, common::Bitmap*>> window_map_;
    std::unordered_set<uint32_t> handled_fec_no_;

    DISSALLOW_COPY_AND_ASSIGN(FecOpenFecDecoder);
};

}  // namespace vpn

}  // namespace lego
