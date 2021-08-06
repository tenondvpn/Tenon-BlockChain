#include "election/leader_rotation.h"

namespace tenon {

namespace elect {

LeaderRotation::LeaderRotation() {}

LeaderRotation::~LeaderRotation() {}

void LeaderRotation::OnElectBlock(const MembersPtr& members) {
    // just latest members
    uint32_t invalid_index = (valid_backup_index_ + 1) % 2;
    memset(
        pool_mod_index_leaders_[invalid_index],
        0,
        sizeof(pool_mod_index_leaders_[invalid_index]));
    for (auto iter = members->begin(); iter != members->end(); ++iter) {
        if ((*iter)->pool_index_mod_num < 0) {
            backup_nodes_[invalid_index].push_back(*iter);
        } else {
            if ((*iter)->pool_index_mod_num[0] >= common::kInvalidPoolIndex) {
                return;
            }

            pool_mod_index_leaders_[invalid_index][(*iter)->pool_index_mod_num[0]] =
                std::make_shared<RotationItem>(*iter);
        }
    }

    valid_backup_index_ = invalid_index;
}

void LeaderRotation::CheckRotaition() {

}

};  // namespace elect

};  // namespace tenon
