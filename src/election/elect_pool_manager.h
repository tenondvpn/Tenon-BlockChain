#pragma once

#include "election/elect_pool.h"
#include "bft/proto/bft.pb.h"

namespace tenon {

namespace elect {

class ElectPoolManager {
public:
    ElectPoolManager();
    ~ElectPoolManager();
    void NetworkMemberChange(uint32_t network_id, MembersPtr& members_ptr);
    void UpdateNodeInfoWithBlock(const bft::protobuf::Block& block_info);

private:
    std::unordered_map<uint32_t, ElectPoolPtr> elect_pool_map_;
    std::mutex elect_pool_map_mutex_;
    // one ip just one node
    std::unordered_set<uint32_t> node_ip_set_;
    std::mutex node_ip_set_mutex_;
    std::unordered_map<std::string, NodeDetailPtr> all_node_map_;
    std::mutex all_node_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(ElectPoolManager);
};

};  // namespace elect

};  //  namespace tenon
