#pragma once

#include <vector>
#include <mutex>
#include <unordered_map>
#include <condition_variable>

#include "common/utils.h"
#include "common/tick.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport.h"
#include "transport/multi_thread.h"
#include "dht/node.h"
#include "dht/proto/dht.pb.h"

namespace tenon {

namespace nat {
    class Detection;
}

namespace dht {

typedef std::vector<NodePtr> Dht;
typedef std::shared_ptr<Dht> DhtPtr;

class BaseDht : public std::enable_shared_from_this<BaseDht> {
public:
    BaseDht(transport::TransportPtr& transport, NodePtr& local_node);
    virtual ~BaseDht();
    virtual int Init();
    virtual int Destroy();
    virtual int Join(NodePtr& node);
    virtual int Drop(NodePtr& node);
    virtual int Bootstrap(
            const std::vector<NodePtr>& boot_nodes,
            int32_t get_init_msg = 0,
            const std::string init_uid = "");
    virtual void HandleMessage(transport::protobuf::Header& msg);
    virtual bool CheckDestination(const std::string& des_dht_key, bool closest);
    virtual void SetFrequently(transport::protobuf::Header& msg);
    virtual bool IsUniversal() { return false; }

    void AddDetectionTarget(NodePtr& node);
    void SendToClosestNode(transport::protobuf::Header& msg);
    int CheckJoin(NodePtr& node);
    DhtPtr readonly_dht() {
        std::lock_guard<std::mutex> guard(dht_mutex_);
        return std::make_shared<Dht>(dht_);
    }

    Dht readonly_hash_sort_dht() {
        std::lock_guard<std::mutex> guard(readonly_hash_sort_dht_mutex_);
        return readonly_hash_sort_dht_;
    }

    void RegisterDhtMessage();
    const NodePtr& local_node() {
        return local_node_;
    }
    transport::TransportPtr transport() {
        return transport::MultiThreadHandler::Instance()->transport();
    }

protected:
    bool NodeValid(NodePtr& node);
    bool NodeJoined(NodePtr& node);
    void DhtDispatchMessage(
            transport::protobuf::Header& header,
            protobuf::DhtMessage& dht_msg);
    void ProcessBootstrapRequest(
            transport::protobuf::Header& header,
            protobuf::DhtMessage& dht_msg);
    void ProcessBootstrapResponse(
            transport::protobuf::Header& header,
            protobuf::DhtMessage& dht_msg);
    void ProcessRefreshNeighborsRequest(
            transport::protobuf::Header& header,
            protobuf::DhtMessage& dht_msg);
    void ProcessRefreshNeighborsResponse(
            transport::protobuf::Header& header,
            protobuf::DhtMessage& dht_msg);
    void ProcessHeartbeatRequest(
            transport::protobuf::Header& header,
            protobuf::DhtMessage& dht_msg);
    void ProcessHeartbeatResponse(
            transport::protobuf::Header& header,
            protobuf::DhtMessage& dht_msg);
    void ProcessConnectRequest(
            transport::protobuf::Header& header,
            protobuf::DhtMessage& dht_msg);
    void RefreshNeighbors();
    void Heartbeat();
    void GetNetIdAndCountry(uint32_t& net_id, uint8_t& country);
    NodePtr FindNodeDirect(transport::protobuf::Header& message);

    static const uint32_t kRefreshNeighborPeriod = 30 * 1000 * 1000;
    static const uint32_t kHeartbeatPeriod = 3 * 1000 * 1000;
    static const uint32_t kHeartbeatMaxSendTimes = 20u;
    static const uint32_t kSendToClosestNodeCount = 3u;

    Dht dht_;
    std::mutex dht_mutex_;
    Dht readonly_hash_sort_dht_;
    std::mutex readonly_hash_sort_dht_mutex_;
    NodePtr local_node_{ nullptr };
    std::unordered_map<uint64_t, NodePtr> node_map_;
    std::mutex node_map_mutex_;
    std::mutex join_res_mutex_;
    std::condition_variable join_res_con_;
    volatile bool joined_{ false };
    bool wait_vpn_res_{ false };
    std::atomic<uint32_t> boot_res_count_{ 0 };
    std::shared_ptr<nat::Detection> nat_detection_{ nullptr };
    common::Tick refresh_neighbors_tick_;
    common::Tick heartbeat_tick_;

    DISALLOW_COPY_AND_ASSIGN(BaseDht);
};

typedef std::shared_ptr<BaseDht> BaseDhtPtr;

}  // namespace dht

}  // namespace tenon
