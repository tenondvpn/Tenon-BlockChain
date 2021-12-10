#pragma once

#include <vector>

#include "common/time_utils.h"
#include "common/tick.h"
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
    int32_t GetThisNodeValidPoolModNum();

private:
    struct RotationItem {
        BftMemberPtr pool_leader_map[common::kInvalidPoolIndex];
        std::deque<BftMemberPtr> valid_leaders;
        int32_t max_pool_mod_num;
        int32_t rotation_idx;
    };

    void CheckRotation();
    BftMemberPtr ChooseValidLeader();

    static const int64_t kCheckRotationPeriod{ 300000000l };

    RotationItem rotation_item_[2];
    int32_t valid_idx_{ 0 };
    common::Tick tick_;
    int32_t this_node_pool_mod_num_{ -1 };

    DISALLOW_COPY_AND_ASSIGN(LeaderRotation);
};

};  // namespace elect

};  // namespace tenon
