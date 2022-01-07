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
    void LeaderRotationReq(protobuf::LeaderRotationMessage& leader_rotation, int32_t index);
    BftMemberPtr local_member() {
        return rotation_item_[valid_idx_].local_member;
    }

private:
    struct RotationItem {
        BftMemberPtr pool_leader_map[common::kInvalidPoolIndex];
        std::deque<BftMemberPtr> valid_leaders;
        int32_t max_pool_mod_num;
        int32_t rotation_idx;
        BftMemberPtr local_member{ nullptr };
    };

    void CheckRotation();
    BftMemberPtr ChooseValidLeader();
    void SendRotationReq(const std::string& id, int32_t pool_mod_num);
    void ChangeLeader(const std::string& id, int32_t pool_mod_num);

    static const int64_t kCheckRotationPeriod{ 3000000l };
    std::unordered_map<std::string, std::set<int32_t>> cons_rotation_leaders_;

    RotationItem rotation_item_[2];
    int32_t valid_idx_{ 0 };
    common::Tick tick_;
    std::mutex rotation_mutex_;

    DISALLOW_COPY_AND_ASSIGN(LeaderRotation);
};

};  // namespace elect

};  // namespace tenon
