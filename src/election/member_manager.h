#pragma once

#include <unordered_map>
#include <mutex>

#include "security/public_key.h"
#include "dht/dht_utils.h"
#include "bft/bft_utils.h"
#include "election/elect_node_detail.h"
#include "election/elect_utils.h"

namespace tenon {

namespace elect {

class MemberManager {
public:
    MemberManager();
    ~MemberManager();
    void SetNetworkMember(
        uint32_t network_id,
        elect::MembersPtr& members_ptr,
        elect::NodeIndexMapPtr& node_index_map,
        int32_t leader_count);
    uint32_t GetMemberIndex(uint32_t network_id, const std::string& node_id);
    elect::MembersPtr GetNetworkMembers(uint32_t network_id);
    elect::BftMemberPtr GetMember(uint32_t network_id, const std::string& node_id);
    elect::BftMemberPtr GetMember(uint32_t network_id, uint32_t index);
    uint32_t GetMemberCount(uint32_t network_id);
    int32_t GetNetworkLeaderCount(uint32_t network_id);

private:
    elect::MembersPtr* network_members_;
    elect::NodeIndexMapPtr* node_index_map_;
    std::unordered_map<uint32_t, int32_t> leader_count_map_;
    std::mutex all_mutex_;

    DISALLOW_COPY_AND_ASSIGN(MemberManager);
};

}  // namespace elect

}  // namespace tenon
