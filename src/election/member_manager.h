#pragma once

#include <unordered_map>
#include <mutex>

#include "security/public_key.h"
#include "security/commit_secret.h"
#include "security/commit_point.h"
#include "dht/dht_utils.h"
#include "bft/bft_utils.h"
#include "election/elect_node_detail.h"
#include "election/elect_utils.h"

namespace tenon {

namespace elect {

class MemberManager {
public:
    static MemberManager* Instance();
    void SetNetworkMember(
            uint32_t network_id,
            elect::MembersPtr& members_ptr,
            elect::NodeIndexMapPtr& node_index_map);
    bool IsLeader(uint32_t network_id, const std::string& node_id, uint64_t rand);
    uint32_t GetMemberIndex(uint32_t network_id, const std::string& node_id);
    elect::MembersPtr GetNetworkMembers(uint32_t network_id);
    elect::BftMemberPtr GetMember(uint32_t network_id, const std::string& node_id);
    elect::BftMemberPtr GetMember(uint32_t network_id, uint32_t index);
    uint32_t GetMemberCount(uint32_t network_id);
    std::set<uint32_t> GetAddressNetworkId(const std::string& address);

private:
    MemberManager();
    ~MemberManager();

    elect::MembersPtr* network_members_;
    elect::NodeIndexMapPtr* node_index_map_;
    std::mutex all_mutex_;

    DISALLOW_COPY_AND_ASSIGN(MemberManager);
};

}  // namespace elect

}  // namespace tenon
