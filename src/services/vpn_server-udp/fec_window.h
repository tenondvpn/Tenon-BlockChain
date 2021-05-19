#pragma once

#include <unordered_map>

#include "common/thread_safe_queue.h"
#include "services/vpn_server/fec_raptorq.h"
#include "services/vpn_server/vpn_svr_utils.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace vpn {

class FecWindow {
private:
    static const uint32_t kFecParamK{ 8 };
    typedef char* FecArray[kFecParamK];

public:
    FecWindow() {}
    ~FecWindow() {}

    void Init(int32_t fec_param_t, double lost_rate, struct sockaddr* addr, int sock) {
        fec_encoder_.SetParam(kFecParamK, fec_param_t, lost_rate);
        fec_decoder_.SetParam(kFecParamK, fec_param_t, lost_rate);
        fec_param_t_ = fec_param_t;
        fec_data_ = new char[fec_param_t_ + sizeof(transport::TransportHeader)];
        addr_ = *addr;
        socket_ = sock;
        reserve_data_ = new char*[kFecParamK];
        for (uint32_t i = 0; i < kFecParamK; ++i) {
            reserve_data_[i] = new char[fec_param_t];
            memset(reserve_data_[i], 0, fec_param_t);
        }

        loss_rate_ = lost_rate;
    }

    void SendPush(char* data) {
        send_queue_.push(data);
        OutPut(false);
    }

    void ReceiveSet(char* data) {
        transport::TransportHeader* fec_header = (transport::TransportHeader*)data;
        if (fec_header->msg_no < fec_no_) {
            return;
        }

        auto iter = receive_map_.find(fec_header->msg_no);
        if (iter == receive_map_.end()) {
            receive_map_[fec_header->msg_no] = std::map<uint32_t, char*>();
        }

        receive_map_[fec_header->msg_no].insert(std::make_pair(fec_header->msg_index, data));
        if (fec_header->msg_no > max_fec_no_) {
            max_fec_no_ = fec_header->msg_no;
        }

        Callback();
    }

private:
    void OutPut(bool flush) {
        char* data = nullptr;
        if (send_queue_.pop(&data)) {
            fec_data_array_[fec_data_index_++] = data;
            transport::TransportHeader* fec_header = (transport::TransportHeader*)fec_data_;
            fec_header->type = kFecStream;
            if (fec_data_index_ == kFecParamK || flush) {
                fec_header->msg_no = fec_no_++;
                fec_header->frag.frag_sum = fec_data_index_;
                for (uint32_t i = 0; i < fec_data_index_; ++i) {
                    fec_header->msg_index = i;
                    memcpy(fec_data_ + sizeof(transport::TransportHeader), fec_data_array_[i], fec_param_t_);
                    sendto(
                            socket_,
                            fec_data_,
                            fec_param_t_ + sizeof(transport::TransportHeader),
                            0,
                            (const struct sockaddr*)&addr_,
                            sizeof(addr_));
                }

                for (uint32_t i = fec_data_index_; i < kFecParamK; ++i) {
                    fec_data_array_[i] = reserve_data_[i];
                }

                Symbol** res = fec_encoder_.EncodeData(fec_data_array_);
                for (uint32_t i = 0; i < fec_encoder_.overhead(); ++i) {
                    fec_header->msg_index = kFecParamK + i;
                    transport::TransportHeader* fec_header = (transport::TransportHeader*)fec_data_;
                    memcpy(fec_data_ + sizeof(transport::TransportHeader), res[i]->data, fec_param_t_);
                    sendto(
                            socket_,
                            fec_data_,
                            fec_param_t_ + sizeof(transport::TransportHeader),
                            0,
                            (const struct sockaddr*)&addr_,
                            sizeof(addr_));
#ifndef UNIT_TEST
                    delete[] res[i];
#endif
                }

#ifndef UNIT_TEST
                delete[] res;
#else
                res_symbol_ = res;
#endif

                fec_data_index_ = 0;
            }
        }
    }

    void Callback() {
        uint32_t handled_max_fec_no = max_fec_no_ - 2;
        for (uint32_t i = fec_no_; i <= max_fec_no_; ++i) {
            if (receive_map_[fec_no_].size() > kFecParamK * (1 - loss_rate_)) {
                // Callback
                if (i > handled_max_fec_no) {
                    handled_max_fec_no = i;
                }
            }
        }

        for (; fec_no_ <= handled_max_fec_no; ++fec_no_) {
            receive_map_.erase(fec_no_);
        }
    }

    std::unordered_map<uint32_t, std::map<uint32_t, char*>> receive_map_;
    common::ThreadSafeQueue<char*> send_queue_;
    char* fec_data_array_[kFecParamK];
    uint32_t fec_data_index_{ 0 };
    FecRaptorQ fec_encoder_{ true };
    FecRaptorQ fec_decoder_{ false };
    struct sockaddr addr_;
    int socket_;
    int32_t fec_param_t_{ 0 };
    char* fec_data_{ nullptr };
    uint32_t fec_no_{ 0 };
    uint32_t max_fec_no_{ 0 };
    char** reserve_data_{ nullptr };
    double loss_rate_{ 0.3 };

#ifdef UNIT_TEST
    Symbol** res_symbol_{ nullptr };
#endif

    DISSALLOW_COPY_AND_ASSIGN(FecWindow);
};

}  // namespace vpn

}  // namespace tenon
