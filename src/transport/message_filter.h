#pragma once

#include <queue>
#include <unordered_map>
#include <mutex>

#include "common/utils.h"
#include "transport/proto/transport.pb.h"

namespace tenon {

namespace transport {

// multi thread not safe
class MessageFilter {
public:
    static MessageFilter* Instance();
    bool CheckUnique(uint64_t msg_hash);
    int32_t StopBroadcast(transport::protobuf::Header& header);

private:
    MessageFilter();
    ~MessageFilter();
    std::unordered_map<uint64_t, uint8_t> broadcast_stop_map_;
    std::queue<uint64_t> broadcast_stop_queue_;
    std::mutex broadcast_stop_queue_mutex_;
    std::unordered_set<uint64_t> unique_set_;
    std::queue<uint64_t> unique_queue_;
    std::mutex mutex_;

    DISALLOW_COPY_AND_ASSIGN(MessageFilter);
};

}  // namespace transport

}  // namespace tenon
