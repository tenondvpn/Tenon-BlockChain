#include "stdafx.h"
#include "transport/message_filter.h"

#include "transport/transport_utils.h"

namespace tenon {

namespace transport {

MessageFilter* MessageFilter::Instance() {
    static MessageFilter ins;
    return &ins;
}

bool MessageFilter::CheckUnique(uint64_t msg_hash) {
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = unique_set_.find(msg_hash);
    if (iter != unique_set_.end()) {
        return true;
    }

    unique_set_.insert(msg_hash);
    unique_queue_.push(msg_hash);
    if (unique_queue_.size() >= kUniqueMaxMessageCount) {
        unique_set_.erase(unique_queue_.front());
        unique_queue_.pop();
    }

    return false;
}

int32_t MessageFilter::StopBroadcast(transport::protobuf::Header& header) {
    std::lock_guard<std::mutex> guard(broadcast_stop_queue_mutex_);
    if (!header.has_broadcast()) {
        return 0;
    }

    assert(header.has_hash());
    uint32_t stop_times = header.broadcast().stop_times();
    if (stop_times <= 0) {
        stop_times = kBroadcastMaxRelayTimes;
    }

    auto iter = broadcast_stop_map_.find(header.hash());
    if (iter != broadcast_stop_map_.end()) {
        if (iter->second >= stop_times) {
            return iter->second + 1;
        }

        ++iter->second;
        return iter->second;
    }
        
    broadcast_stop_map_[header.hash()] = 1;
    broadcast_stop_queue_.push(header.hash());
    if (broadcast_stop_queue_.size() >= kBroadcastMaxMessageCount) {
        broadcast_stop_map_.erase(broadcast_stop_queue_.front());
        broadcast_stop_queue_.pop();
    }

    return 1;
}

MessageFilter::MessageFilter()
        : broadcast_stop_map_(4 * kBroadcastMaxMessageCount),
          unique_set_(4 * kUniqueMaxMessageCount) {}

MessageFilter::~MessageFilter() {}

}  // namespace transport

}  // namespace tenon
