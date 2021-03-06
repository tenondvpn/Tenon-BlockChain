#pragma once

#include <chrono>
#include <mutex>
#include <memory>
#include <queue>
#include <string>
#include <unordered_map>

#include "common/utils.h"
#include "common/tick.h"
#include "sync/proto/sync.pb.h"
#include "sync/sync_utils.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace dht {
    class BaseDht;
    typedef std::shared_ptr<BaseDht> BaseDhtPtr;
}  // namespace dht

namespace sync {

struct SyncItem {
    SyncItem(uint32_t net_id, const std::string& in_key, uint32_t pri)
            : network_id(net_id), key(in_key), priority(pri) {}

    SyncItem(uint32_t net_id, uint32_t in_pool_idx, uint64_t in_height, uint32_t pri)
            : network_id(net_id), pool_idx(in_pool_idx), height(in_height), priority(pri) {
        key = std::to_string(network_id) + "_" +
            std::to_string(pool_idx) + "_" +
            std::to_string(height);
    }

    uint32_t network_id{ 0 };
    std::string key;
    uint32_t priority{ 0 };
    uint32_t sync_times{ 0 };
    uint32_t pool_idx{ common::kInvalidUint32 };
    uint64_t height{ common::kInvalidUint64 };
};

typedef std::shared_ptr<SyncItem> SyncItemPtr;

class KeyValueSync {
public:
    static KeyValueSync* Instance();
    int AddSync(uint32_t network_id, const std::string& key, uint32_t priority);
    int AddSyncHeight(uint32_t network_id, uint32_t pool_idx, uint64_t height, uint32_t priority);
    void Init();
    void Destroy();
    void HandleMessage(const transport::TransportMessagePtr& msg);

private:
    struct PrioSyncQueue {
        std::queue<SyncItemPtr> sync_queue;
        std::mutex mutex;
    };

    KeyValueSync();
    ~KeyValueSync();
    void CheckSyncItem();
    void CheckSyncTimeout();
    uint64_t SendSyncRequest(
        uint32_t network_id,
        const sync::protobuf::SyncMessage& sync_msg,
        const std::set<uint64_t>& sended_neigbors);
    void ProcessSyncValueRequest(
        const transport::protobuf::Header& header,
        protobuf::SyncMessage& sync_msg);
    void ProcessSyncValueResponse(
        const transport::protobuf::Header& header,
        protobuf::SyncMessage& sync_msg);
    int HandleExistsBlock(const std::string& key);

    std::unordered_map<std::string, SyncItemPtr> synced_map_;
    std::mutex synced_map_mutex_;
    PrioSyncQueue prio_sync_queue_[kSyncHighest + 1];
    common::Tick tick_;
    common::Tick sync_timeout_tick_;
    std::unordered_set<std::string> added_key_set_;
    std::mutex added_key_set_mutex_;

#ifdef TENON_UNITTEST
    transport::protobuf::Header test_sync_req_msg_;
    transport::protobuf::Header test_sync_res_msg_;
#endif

    DISALLOW_COPY_AND_ASSIGN(KeyValueSync);
};

}  // namespace sync

}  // namespace tenon
