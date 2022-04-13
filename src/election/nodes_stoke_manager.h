#pragma once

#include "db/db_unique_queue.h"
#include "election/elect_utils.h"
#include "election/proto/elect.pb.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace elect {

class NodesStokeManager {
public:
    static NodesStokeManager* Instance();
    void SyncAddressStoke(const std::vector<std::string>& addrs);
    void GetAddressStoke(const std::string& addr, uint64_t tm_height);
    void HandleSyncAddressStoke(
        const transport::protobuf::Header& header,
        const protobuf::ElectMessage& ec_msg);
    void HandleSyncStokeResponse(
        const transport::protobuf::Header& header,
        const protobuf::ElectMessage& ec_msg);

private:
    NodesStokeManager() {}
    ~NodesStokeManager() {}

    std::unordered_map<std::string, std::pair<uint64_t, uint64_t>> sync_nodes_map_;
    std::mutex sync_nodes_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(NodesStokeManager);
};

}  // namespace elect

}  // namespace tenon
