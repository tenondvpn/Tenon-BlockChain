#pragma once

#include <unordered_map>
#include <map>
#include <deque>
#include <queue>

#ifdef __cplusplus
extern "C" {
#endif

#include "ev.h"

#ifdef __cplusplus
}
#endif

#include "common/utils.h"
#include "common/global_info.h"
#include "common/bitmap.h"
#include "transport/transport_utils.h"
#include "services/vpn_server/ev_loop_manager.h"
#include "services/vpn_server/vpn_svr_utils.h"

namespace tenon {

namespace vpn {

struct NakItem {
    uint32_t epoch;
    uint32_t msg_index;
};

typedef user_ev_io_t*(*GetEvUserIo)();
typedef uint16_t(*GetRemotePort)(const std::string& ip);

class MessageWindow {
public:
    static uint32_t all_sent_msg_count_;
    static uint32_t all_sent_start_msg_index_;
    static uint32_t all_sent_out_start_msg_index_;
    static uint32_t all_recv_msg_count_;
    static uint32_t all_recv_start_msg_index_;
    static uint32_t all_recv_from_start_msg_index_;

    MessageWindow(
            vpn::UdpUserData* udp_user_data,
            uint32_t server_id,
            GetEvUserIo get_socket_func,
            GetRemotePort get_remote_port_func)
            : udp_user_data_(udp_user_data), server_id_(server_id){
        get_socket_func_ = get_socket_func;
        get_remote_port_func_ = get_remote_port_func;
        stream_data_ = new char[common::GlobalInfo::Instance()->udp_mtu() + 100];
        nak_stream_data_ = new char[common::GlobalInfo::Instance()->udp_mtu() + 100];
        fast_nak_stream_data_ = new char[common::GlobalInfo::Instance()->udp_mtu() + 100];
        if (window_size_ / 64 > ack_per_window_) {
            ack_per_window_ = window_size_ / 64;
        }

        max_nak_count_ = (
                common::GlobalInfo::Instance()->udp_mtu() -
                sizeof(transport::TransportHeader)) / sizeof(NakItem);
        nak_header_ = (transport::TransportHeader*)fast_nak_stream_data_;
        nak_header_->type = kStreamNakRequest;
        nak_header_->epoch = 0;
        nak_header_->server_id = server_id_;
    }

    ~MessageWindow() {
        delete[] stream_data_;
        delete[] nak_stream_data_;
        delete[] fast_nak_stream_data_;
    }

    void Push(char* item, uint32_t src_len, uint32_t server_id, uint32_t type) {
        uint8_t frag_count = src_len / common::GlobalInfo::Instance()->udp_mtu();
        if (src_len % common::GlobalInfo::Instance()->udp_mtu() > 0) {
            ++frag_count;
        }

        for (uint32_t i = 0; i < frag_count; ++i) {
            uint32_t len = common::GlobalInfo::Instance()->udp_mtu();
            if (i == (frag_count - 1)) {
                len = src_len % common::GlobalInfo::Instance()->udp_mtu();
                if (len == 0) {
                    len = common::GlobalInfo::Instance()->udp_mtu();
                }
            }

            char* tmp_buf = new char[len + sizeof(transport::TransportHeader)];
            transport::TransportHeader* header = (transport::TransportHeader*)tmp_buf;
            header->server_id = server_id;
            header->type = type;
            header->msg_index = count_;
            header->msg_no = msg_no_;
            header->frag.frag_sum = frag_count;
            header->frag.frag_no = i;
            header->frag.mtu = common::GlobalInfo::Instance()->udp_mtu();
            header->frag_len = len;
            header->size = src_len;
            uint32_t data_offset = (uint32_t)i * common::GlobalInfo::Instance()->udp_mtu();
            memcpy(tmp_buf + sizeof(transport::TransportHeader), item + data_offset, len);
            window_map_[count_++] = std::make_pair(tmp_buf, nullptr);
            all_sent_msg_count_++;
        }

        ++msg_no_;
        UdpOutput();
    }

    void Ack(uint32_t msg_index) {
//         std::cout << "ack: " << msg_index << ", server id: " << server_id_ << ", max index: " << count_ << ", sent index: " << sent_no_ << std::endl;
        for (; start_msg_index_ < msg_index; ++start_msg_index_) {
            delete[] window_map_[start_msg_index_].first;
            if (window_map_[start_msg_index_].second != nullptr) {
                delete window_map_[start_msg_index_].second;
            }

            window_map_.erase(start_msg_index_);
            all_sent_start_msg_index_++;
        }

        if (msg_index == prev_acked_msg_index_) {
            ++same_acked_msg_count_;
        }

        if (same_acked_msg_count_ >= 2) {
            OverloadMoreData();
            same_acked_msg_count_ = 0;
        }

        UdpOutput();
    }

    void Nak(transport::TransportHeader* trans_header) {
        if (trans_header->size <= 0) {
            return;
        }

        struct sockaddr_in des_addr = GetDesAddr();
        NakItem* nak_items = (NakItem*)(trans_header + 1);
        for (uint32_t idx = 0; idx < trans_header->size; ++idx) {
            std::cout << "nak server id: " << server_id_ << ", msg index: " << nak_items[idx].msg_index << ", epoch: " << nak_items[idx].epoch << std::endl;
            auto iter = window_map_.find(nak_items[idx].msg_index);
            if (iter != window_map_.end()) {
                transport::TransportHeader* header = (transport::TransportHeader*)iter->second.first;
                if (trans_header->type == vpn::kStreamNakRequest) {
                    header->type = vpn::kStreamNakResponse;
                } else if (trans_header->type == vpn::kStreamTimeoutNakRequest) {
                    header->type = vpn::kStreamTimeoutNakResponse;
                }

                header->epoch = nak_items[idx].epoch;
                header->server_id = server_id_;
                sendto(
                        GetDesSocket(),
                        iter->second.first,
                        header->frag_len + sizeof(transport::TransportHeader),
                        0,
                        (const struct sockaddr*)&des_addr,
                        sizeof(des_addr));
            }
        }
    }

    void ServerSet(
            char* item,
            uint32_t len,
            const struct sockaddr* addr,
            void(*EvUdpRecvCallback)(
                struct ev_loop* loop,
                const struct sockaddr* addr,
                transport::TransportHeader* header,
                char* data,
                uint32_t len)) {
        HandleDataSet(item, len);
        while (true) {
            uint32_t msg_no = 0;
            uint32_t len = 0;
            char* data = Pop(&msg_no);
            if (data == nullptr) {
                break;
            }

            transport::TransportHeader* header = (transport::TransportHeader*)data;
            EvUdpRecvCallback(
                    vpn::EvLoopManager::Instance()->loop(),
                    addr,
                    header,
                    (char*)(header + 1),
                    header->size);
            delete[] data;
        }

        SendAck();
    }

    void RouteSet(
            char* item,
            uint32_t len,
            struct sockaddr* from_addr,
            void(*UdpServerRecvCallback)(
                struct ev_loop* loop,
                char* data,
                uint32_t len,
                struct sockaddr* from_addr)) {
        transport::TransportHeader* in_header = (transport::TransportHeader*)item;
//         std::cout << "receive msg index: " << in_header->msg_index
//             << ", type: " << (uint32_t)in_header->type
//             << ", epoch: " << in_header->epoch
//             << std::endl;
        HandleDataSet(item, len);
        while (true) {
            uint32_t msg_no = 0;
            char* data = Pop(&msg_no);
            if (data == nullptr) {
                break;
            }

            transport::TransportHeader* header = (transport::TransportHeader*)data;
            UdpServerRecvCallback(
                    vpn::EvLoopManager::Instance()->loop(),
                    data,
                    header->size + sizeof(transport::TransportHeader),
                    from_addr);
            delete[] data;
        }

        SendAck();
    }

    void CheckNak(bool direct) {
        uint64_t cur_timestamp = common::TimeUtils::TimestampMs();
        if (cur_timestamp - prev_check_nak_timestamp_ <= kCheckNakTimeoutMilli) {
            return;
        }

        prev_check_nak_timestamp_ = common::TimeUtils::TimestampMs();
        TimeoutCheckNak();
    }

    void SendAck() {
        uint64_t now_timestamp = common::TimeUtils::TimestampMs();
        if (now_timestamp - prev_check_ack_timestamp_ < 500 &&
                (start_msg_index_ - prev_ack_msg_index_) < window_size_ / ack_per_window_) {
            return;
        }

        prev_check_ack_timestamp_ = now_timestamp;
        if (prev_ack_msg_index_ == start_msg_index_) {
            if (prev_ack_count_ >= 2) {
                return;
            }

            ++prev_ack_count_;
        } else {
            prev_ack_msg_index_ = start_msg_index_;
            prev_ack_count_ = 0;
        }

        transport::TransportHeader header;
        header.type = kStreamAck;
        header.msg_index = start_msg_index_;
        header.server_id = server_id_;
        struct sockaddr_in des_addr = GetDesAddr();
        sendto(
                GetDesSocket(),
                (const char*)&header,
                sizeof(transport::TransportHeader),
                0,
                (const struct sockaddr*)&des_addr,
                sizeof(des_addr));
    }

    void UdpOutput() {
        struct sockaddr_in des_addr = GetDesAddr();
        uint32_t sent_limits = 0;
        for (; sent_no_ < count_ && ++sent_limits < kNakCheckDistance; ++sent_no_) {
            if ((sent_no_ - start_msg_index_) > window_size_) {
                OverloadMoreData();
                break;
            }

            transport::TransportHeader* header =
                    (transport::TransportHeader*)window_map_[sent_no_].first;
            header->server_id = server_id_;
            sendto(
                    GetDesSocket(),
                    window_map_[sent_no_].first,
                    header->frag_len + sizeof(transport::TransportHeader),
                    0,
                    (const struct sockaddr*)&des_addr,
                    sizeof(des_addr));
            ++all_sent_out_start_msg_index_;
        }
    }

private:
    void OverloadMoreData() {
        if (start_msg_index_ >= count_) {
            return;
        }

        struct sockaddr_in des_addr = GetDesAddr();
        uint32_t i = 0;
        for (; i < kNakCheckDistance; ++i) {
            if (start_msg_index_ + i <= prev_fast_output_index_) {
                continue;
            }

            auto iter = window_map_.find(start_msg_index_ + i);
            if (iter == window_map_.end()) {
                break;
            }

            transport::TransportHeader* header =
                (transport::TransportHeader*)window_map_[start_msg_index_ + i].first;
            header->server_id = server_id_;
            sendto(
                    GetDesSocket(),
                    window_map_[start_msg_index_ + i].first,
                    header->frag_len + sizeof(transport::TransportHeader),
                    0,
                    (const struct sockaddr*)&des_addr,
                    sizeof(des_addr));
            ++all_sent_out_start_msg_index_;
        }

        prev_fast_output_index_ = start_msg_index_ + i;
    }

    char* Pop(uint32_t* msg_no) {
        auto iter = window_map_.find(start_msg_no_);
        if (iter != window_map_.end()) {
            transport::TransportHeader* header = (transport::TransportHeader*)iter->second.first;
            if (iter->second.second != nullptr) {
                if (iter->second.second->valid_count() != header->frag.frag_sum) {
                    return nullptr;
                }
            }

            for (uint32_t i = 0; i < header->frag.frag_sum; ++i) {
//                 start_msg_index_++;
                receive_index_set_.erase(start_msg_index_++);
                all_recv_start_msg_index_++;
            }

            char* data = iter->second.first;
            if (iter->second.second != nullptr) {
                delete iter->second.second;
            }

            *msg_no = start_msg_no_;
            window_map_.erase(iter);
            ++start_msg_no_;
            return data;
        }

        return nullptr;
    }

    void HandleDataSet(char* item, uint32_t len) {
        ++all_recv_from_start_msg_index_;

        transport::TransportHeader* in_header = (transport::TransportHeader*)item;
        if (in_header->msg_index < start_msg_index_) {
            return;
        }

        if (receive_index_set_.find(in_header->msg_index) != receive_index_set_.end()) {
            return;
        }

        all_recv_msg_count_++;
        receive_index_set_.insert(in_header->msg_index);
        if (in_header->frag.frag_sum == 1) {
            char* tmp_buf = new char[len];
            memcpy(tmp_buf, item, len);
            window_map_[in_header->msg_no] = std::make_pair(tmp_buf, nullptr);
        } else {
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
                    len - sizeof(transport::TransportHeader));
        }
// 
//         if (in_header->sent_msg_index >= max_msg_index_) {
//             max_msg_index_ = in_header->sent_msg_index + 1;
//         }

        nak_index_map_.erase(in_header->msg_index);
        RemoveNakItem(in_header->msg_index);
        if (in_header->type == kStreamNakResponse) {
            NakDataCheck(in_header->msg_index, in_header->epoch);
        } else {
            SrcDataCheck(in_header->msg_index);
        }

        FastCheckNak(false, 0);
        ++set_index_;
    }

    void SrcDataCheck(uint32_t msg_index) {
        top_latest_index_.push(msg_index);
        if (top_latest_index_.size() < kNakCheckDistance) {
            return;
        }

        uint32_t min_top = top_latest_index_.top();
        for (uint32_t i = prev_src_set_index_; i <= min_top; ++i) {
            if (i < start_msg_index_) {
                continue;
            }

            if (receive_index_set_.find(i) == receive_index_set_.end()) {
                nak_index_map_[i] = set_index_;
            }
        }

        prev_src_set_index_ = min_top;
        while (!top_latest_index_.empty()) {
            if (top_latest_index_.top() <= start_msg_index_) {
                top_latest_index_.pop();
                continue;
            }

            break;
        }

        if (top_latest_index_.size() > kNakCheckDistance) {
            top_latest_index_.pop();
        }
    }

    void NakDataCheck(uint32_t msg_index, uint32_t epoch) {
        uint64_t item = ((uint64_t)epoch) << 32 | (uint64_t)msg_index;
        fast_latest_index_.push(item);
        if (fast_latest_index_.size() <= kNakCheckDistance) {
            return;
        }

        uint64_t min_top = fast_latest_index_.top();
        uint32_t nak_count = 0;
        NakItem* items = (NakItem*)(nak_header_ + 1);
        auto iter = fast_nak_index_set_.begin();
        while (iter != fast_nak_index_set_.end()) {
            if (nak_count >= max_nak_count_) {
                break;
            }

            if (*iter > min_top) {
                break;
            }

            items[nak_count].msg_index = static_cast<uint32_t>(*iter & 0x00000000FFFFFFFFlu);
            std::cout << "NakDataCheck for: " << " server id: " << server_id_ << ", msg index: " << items[nak_count].msg_index << ", epoch: " << nak_epoch_ << std::endl;
            items[nak_count].epoch = nak_epoch_;
            fast_nak_index_set_.erase(iter++);
            ++nak_count;
        }

        while (!fast_latest_index_.empty()) {
            if (fast_latest_index_.top() <= start_msg_index_) {
                fast_latest_index_.pop();
                continue;
            }

            break;
        }

        if (fast_latest_index_.size() >= kNakCheckDistance) {
            fast_latest_index_.pop();
        }

        SendNak(nak_count);
    }

    void RemoveNakItem(uint32_t msg_index) {
        auto iter = fast_nak_index_map_.find(msg_index);
        if (iter == fast_nak_index_map_.end()) {
            return;
        }

        uint64_t item = ((uint64_t)iter->second) << 32 | (uint64_t)iter->first;
        fast_nak_index_set_.erase(item);
        fast_nak_index_map_.erase(iter);
    }

    void SendNak(uint32_t nak_count) {
        if (nak_count == 0) {
            return;
        }

        NakItem* items = (NakItem*)(nak_header_ + 1);
        for (uint32_t i = 0; i < nak_count; ++i) {
            if (items[i].epoch != (std::numeric_limits<uint32_t>::max)()) {
                uint64_t item = ((uint64_t)items[i].epoch) << 32 | (uint64_t)items[i].msg_index;
                fast_nak_index_set_.insert(item);
                fast_nak_index_map_[items[i].msg_index] = items[i].epoch;
            }
        }

        ++nak_epoch_;
        nak_header_->size = nak_count;
        nak_header_->type = kStreamNakRequest;
        nak_header_->server_id = server_id_;
        struct sockaddr_in des_addr = GetDesAddr();
        sendto(
                GetDesSocket(),
                (const char*)nak_header_,
                sizeof(transport::TransportHeader) + sizeof(NakItem) * nak_header_->size,
                0,
                (const struct sockaddr*)&des_addr,
                sizeof(des_addr));
        fast_nak_on_the_way_ = true;
    }

    void TimeoutCheckNak() {
        uint32_t nak_count = 0;
        NakItem* items = (NakItem*)(nak_header_ + 1);
        for (auto iter = fast_nak_index_map_.begin();
                iter != fast_nak_index_map_.end(); ++iter) {
            if (nak_count >= max_nak_count_) {
                break;
            }

            items[nak_count].msg_index = iter->first;
            items[nak_count].epoch = iter->second;
            ++nak_count;
        }

        SendNak(nak_count);
    }

    void FastCheckNak(bool timeout, uint32_t begin_idx) {
        if (fast_nak_index_map_.size() > window_size_ / ack_per_window_) {
            return;
        }

        uint32_t nak_count = begin_idx;
        NakItem* items = (NakItem*)(nak_header_ + 1);
        auto iter = nak_index_map_.begin();
        while (iter != nak_index_map_.end() && nak_count < max_nak_count_) {
            if ((set_index_ > iter->second) &&
                    (set_index_ - iter->second) >= kNakCheckDistance) {
                items[nak_count].msg_index = iter->first;
                items[nak_count].epoch = nak_epoch_;
                std::cout << "FastCheckNak: " << iter->first << std::endl;
                ++nak_count;
                if (!timeout) {
                    nak_index_map_.erase(iter++);
                }

                continue;
            }

            ++iter;
        }

        SendNak(nak_count);
    }

    struct sockaddr_in GetDesAddr() {
        struct sockaddr_in des_addr;
        uint16_t port = udp_user_data_->port;
//         if (get_remote_port_func_ != nullptr) {
//             port = get_remote_port_func_(udp_user_data_->ip);
//         }

        uv_ip4_addr(udp_user_data_->ip, port, &des_addr);
        return des_addr;
    }

    int GetDesSocket() {
        auto sock = udp_user_data_->user_ev_io->sock;
//         if (get_socket_func_ != nullptr) {
//             auto sock_io = get_socket_func_();
//             if (sock_io != nullptr) {
//                 sock = sock_io->sock;
//             }
//         }

        return sock;
    }

    static const uint32_t kNakCheckDistance = 5u;


    std::unordered_map<uint32_t, std::pair<char*, common::Bitmap*>> window_map_;
    uint32_t start_msg_index_{ 0 };
    uint32_t count_{ 0 };
    uint32_t window_size_{ 64 };
    uint32_t ack_per_window_{ 4 };
    uint32_t sent_no_{ 0 };
    uint64_t prev_check_ack_timestamp_{ 0 };
    uint64_t prev_check_nak_timestamp_{ 0 };
    uint32_t max_msg_index_{ 0 };
    vpn::UdpUserData* udp_user_data_{ nullptr };
    uint32_t prev_ack_msg_index_{ 0 };
    uint32_t prev_ack_count_{ 0 };
    char* stream_data_{ nullptr };
    char* nak_stream_data_{ nullptr };
    char* fast_nak_stream_data_{ nullptr };
    uint64_t prev_ack_timestamp_{ 0 };
    uint32_t src_set_index_{ 0 };
    uint32_t prev_src_set_index_{ 0 };
    uint32_t prev_nak_set_index_{ 0 };
    uint32_t set_index_{ 0 };
    uint32_t msg_no_{ 0 };
    std::set<uint32_t> receive_index_set_;
    uint32_t start_msg_no_{ 0 };
    std::map<uint32_t, uint32_t> nak_index_map_;
    bool nak_on_the_way_{ false };
    uint32_t pre_nak_msg_index_{ 0 };
    std::priority_queue<uint32_t, std::vector<uint32_t>, std::greater<uint32_t>> top_latest_index_;
    std::map<uint32_t, uint32_t> fast_nak_index_map_;
    std::set<uint64_t> fast_nak_index_set_;
    std::priority_queue<uint32_t, std::vector<uint32_t>, std::greater<uint32_t>> fast_latest_index_;
    uint32_t fast_prev_nak_set_index_{ 0 };
    uint32_t fast_nak_init_index_{ 0 };
    uint32_t fast_nak_max_index_{ 0 };
    uint32_t max_nak_count_{ 0 };
    transport::TransportHeader* nak_header_;
    uint32_t prev_fast_output_index_{ 0 };
    bool fast_nak_on_the_way_{ false };
    uint32_t nak_epoch_{ 0 };
    uint32_t server_id_{ 0 };
    uint32_t prev_acked_msg_index_{ 0 };
    uint32_t same_acked_msg_count_{ 0 };
    GetEvUserIo get_socket_func_{ nullptr };
    GetRemotePort get_remote_port_func_{ nullptr };
};

class EndPoint {
public:
    EndPoint(
            vpn::UdpUserData* udp_user_data,
            uint32_t server_id,
            GetEvUserIo get_ev_user_io,
            GetRemotePort get_remote_port_func)
            : udp_user_data_(udp_user_data),
              send_window_(udp_user_data, server_id, get_ev_user_io, get_remote_port_func),
              recv_window_(udp_user_data, server_id, get_ev_user_io, get_remote_port_func) {}

    vpn::UdpUserData* udp_user_data_{ nullptr };
    MessageWindow send_window_;
    MessageWindow recv_window_;
};

}  // namespace vpn 

}  // namespace tenon
