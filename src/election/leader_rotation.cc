#include "election/leader_rotation.h"

#include "bft/dispatch_pool.h"

namespace tenon {

namespace elect {

LeaderRotation::LeaderRotation() {
    tick_.CutOff(3000000000l, std::bind(&LeaderRotation::CheckRotation, this));
}

LeaderRotation::~LeaderRotation() {}

void LeaderRotation::OnElectBlock(const MembersPtr& members) {
    int32_t invalid_idx = (valid_idx_ + 1) % 2;
    for (auto iter = members->begin(); iter != members->end(); ++iter) {
        if ((*iter)->bls_publick_key == libff::alt_bn128_G2::zero()) {
            // should not to be leader
            (*iter)->valid_leader = false;
            continue;
        }

        (*iter)->valid_leader = true;
        (*iter)->leader_load_count = 0;
        if ((*iter)->pool_index_mod_num >= 0) {
            rotation_item_[invalid_idx].pool_leader_map[(*iter)->pool_index_mod_num] = *iter;
            ++(*iter)->leader_load_count;
            if ((*iter)->pool_index_mod_num > rotation_item_[invalid_idx].max_pool_mod_num) {
                rotation_item_[invalid_idx].max_pool_mod_num = (*iter)->pool_index_mod_num;
            }

            rotation_item_[invalid_idx].valid_leaders.push_front(*iter);
        } else {
            rotation_item_[invalid_idx].valid_leaders.push_back(*iter);
        }
    }

    rotation_item_[invalid_idx].rotation_idx = rotation_item_[invalid_idx].max_pool_mod_num + 1;
    valid_idx_ = invalid_idx;
}

int32_t LeaderRotation::GetThisNodeValidPoolModNum() {
    for (int32_t i = 0; i < rotation_item_[valid_idx_].max_pool_mod_num; ++i) {
        if (rotation_item_[valid_idx_].pool_leader_map[i]->id ==
                common::GlobalInfo::Instance()->id()) {
            return i;
        }
    }

    return -1;
}

void LeaderRotation::CheckRotation() {
    std::vector<int32_t> should_change_leaders;
    for (int32_t i = 0; i <= rotation_item_[valid_idx_].max_pool_mod_num; ++i) {
        bool change_leader = true;
        for (int32_t j = 0; j < common::kInvalidPoolIndex; ++j) {
            if (j % (rotation_item_[valid_idx_].max_pool_mod_num + 1) == i) {
                if (!bft::DispatchPool::Instance()->ShouldChangeLeader(j)) {
                    change_leader = false;
                    break;
                }
            }
        }

        if (!change_leader) {
            continue;
        }

        rotation_item_[valid_idx_].pool_leader_map[i]->valid_leader = false;
        rotation_item_[valid_idx_].pool_leader_map[i]->pool_index_mod_num = -1;
        should_change_leaders.push_back(i);
    }

    for (int32_t i = 0; i < should_change_leaders.size(); ++i) {
        rotation_item_[valid_idx_].pool_leader_map[i] = ChooseValidLeader();
    }

    tick_.CutOff(kCheckRotationPeriod, std::bind(&LeaderRotation::CheckRotation, this));
}

BftMemberPtr LeaderRotation::ChooseValidLeader() {
    int32_t start_idx = rotation_item_[valid_idx_].rotation_idx;
    for (int32_t i = rotation_item_[valid_idx_].rotation_idx;
            i < rotation_item_[valid_idx_].valid_leaders.size(); ++i) {
        if (!rotation_item_[valid_idx_].valid_leaders[i]->valid_leader) {
            continue;
        }

        rotation_item_[valid_idx_].rotation_idx = i + 1;
        if (rotation_item_[valid_idx_].rotation_idx >= rotation_item_[valid_idx_].valid_leaders.size()) {
            rotation_item_[valid_idx_].rotation_idx = 0;
        }

        return rotation_item_[valid_idx_].valid_leaders[i];
    }

    for (int32_t i = 0; i < rotation_item_[valid_idx_].rotation_idx; ++i) {
        if (!rotation_item_[valid_idx_].valid_leaders[i]->valid_leader) {
            continue;
        }

        rotation_item_[valid_idx_].rotation_idx = i + 1;
        if (rotation_item_[valid_idx_].rotation_idx >= rotation_item_[valid_idx_].valid_leaders.size()) {
            rotation_item_[valid_idx_].rotation_idx = 0;
        }

        return rotation_item_[valid_idx_].valid_leaders[i];
    }

    // TODO: no valid leader, then atavism reversion
    return nullptr;
}

};  // namespace elect

};  // namespace tenon
