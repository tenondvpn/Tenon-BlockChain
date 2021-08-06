#pragma once

#include <vector>

#include "common/time_utils.h"
#include "election/elect_utils.h"
#include "election/elect_node_detail.h"

#include "bft/bft_utils.h"

namespace tenon {

namespace elect {

class LeaderRotation {
public:
    LeaderRotation();
    ~LeaderRotation();
    void OnElectBlock(const MembersPtr& members);
    void OnNewBlock(const bft::BlockPtr& block_ptr);

private:
    struct RotationItem {
        RotationItem(BftMemberPtr& leader) : leader_ptr(leader) {
            timeout = common::TimeUtils::TimestampMs();
            rotation_times = 0;
        }

        BftMemberPtr leader_ptr;
        uint64_t timeout;
        uint32_t rotation_times;
    };

    typedef std::shared_ptr<RotationItem> RotationItemPtr;

    void CheckRotaition();

    std::vector<BftMemberPtr> backup_nodes_[2];
    RotationItemPtr pool_mod_index_leaders_[2][common::kInvalidPoolIndex];
    uint32_t valid_backup_index_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(LeaderRotation);
};

};  // namespace elect

};  // namespace tenon
