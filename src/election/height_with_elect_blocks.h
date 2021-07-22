#pragma once

#include <mutex>
#include <unordered_map>
#include <memory>
#include <queue>
#include <vector>

#include "bft/proto/bft.pb.h"
#include "common/utils.h"
#include "db/db.h"
#include "election/elect_node_detail.h"
#include "election/proto/elect.pb.h"
#include "election/elect_utils.h"
#include "network/network_utils.h"
#include "security/secp256k1.h"

namespace tenon {

namespace elect {

class HeightWithElectBlock {
    struct HeightMembersItem {
        MembersPtr members_ptr;
        uint64_t height;
    };

    typedef std::shared_ptr<HeightMembersItem> HeightMembersItemPtr;

public:
    HeightWithElectBlock();
    ~HeightWithElectBlock();
    // elect block is always coming in order or one time just one block, so no need to lock it
    void AddNewHeightBlock(uint64_t height, MembersPtr& members_ptr) {
        if (members_ptrs_[0] == nullptr) {
            members_ptrs_[0] = std::make_shared<HeightMembersItem>(members_ptr, height);
            return;                
        }

        if (members_ptrs_[1] == nullptr) {
            members_ptrs_[1] = std::make_shared<HeightMembersItem>(members_ptr, height);
            return;
        }

        if (members_ptrs_[2] == nullptr) {
            members_ptrs_[2] = std::make_shared<HeightMembersItem>(members_ptr, height);
            return;
        }

        uint64_t min_height = common::kInvalidUint64;
        uint64_t min_index = 0;
        if (members_ptrs_[0]->height < min_height) {
            min_height = members_ptrs_[0]->height;
            min_index = 0;
        }

        if (members_ptrs_[1]->height < min_height) {
            min_height = members_ptrs_[1]->height;
            min_index = 1;
        }

        if (members_ptrs_[2]->height < min_height) {
            min_height = members_ptrs_[2]->height;
            min_index = 2;
        }

        members_ptrs_[min_index] = std::make_shared<HeightMembersItem>(members_ptr, height);
    }

    MembersPtr GetMembersPtr(uint64_t height) {
        if (members_ptrs_[0] != nullptr && members_ptrs_[0]->height == height) {
            return members_ptrs_[0]->members_ptr;
        }

        if (members_ptrs_[1] != nullptr && members_ptrs_[1]->height == height) {
            return members_ptrs_[1]->members_ptr;
        }

        if (members_ptrs_[2] != nullptr && members_ptrs_[2]->height == height) {
            return members_ptrs_[2]->members_ptr;
        }

        // get from cache map
        {
            std::lock_guard<std::mutex> guard(height_with_members_mutex_);
            auto iter = height_with_members_.find(height);
            if (iter != height_with_members_.end()) {
                return iter->second;
            }
        }

        // get block from db and cache it
        std::string height_db_key = common::GetHeightDbKey(
            network::kRootCongressNetworkId,
            common::kRootChainPoolIndex,
            height);
        std::string block_str;
        auto st = db::Db::Instance()->Get(height_db_key, &block_str);
        if (!st.ok()) {
            return nullptr;
        }

        bft::protobuf::Block block;
        if (!block.ParseFromString(block_str)) {
            return nullptr;
        }

        if (block.tx_list_size() != 1) {
            return nullptr;
        }

        bool eb_valid = false;
        elect::protobuf::ElectBlock elect_block;
        for (int32_t i = 0; i < block.tx_list(0).attr_size(); ++i) {
            if (block.tx_list(0).attr(i).key() == elect::kElectNodeAttrElectBlock) {
                if (!elect_block.ParseFromString(block.tx_list(0).attr(i).value())) {
                    return nullptr;
                }

                eb_valid = true;
                break;
            }
        }

        if (!eb_valid) {
            return nullptr;
        }

        auto shard_members_ptr = std::make_shared<Members>();
        auto& in = elect_block.in();
        uint32_t member_index = 0;
        for (int32_t i = 0; i < in.size(); ++i) {
            security::CommitSecret secret;
            auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(in[i].pubkey());
            shard_members_ptr->push_back(std::make_shared<BftMember>(
                elect_block.shard_network_id(),
                id,
                in[i].pubkey(),
                member_index++,
                in[i].public_ip(),
                in[i].public_port(),
                in[i].dht_key(),
                in[i].pool_idx_mod_num()));
        }

        {
            std::lock_guard<std::mutex> guard(height_with_members_mutex_);
            height_queue_.push(height);
            height_with_members_[height] = shard_members_ptr;
            if (height_queue_.size() > kMaxCacheElectBlockCount) {
                auto min_height = height_queue_.top();
                auto iter = height_with_members_.find(min_height);
                if (iter != height_with_members_.end()) {
                    height_with_members_.erase(iter);
                }

                height_queue_.pop();
            }
        }

        return shard_members_ptr;
    }

private:
    static const uint32_t kMaxKeepElectBlockCount = 3u;
    static const uint32_t kMaxCacheElectBlockCount = 7u;

    std::map<uint64_t, MembersPtr> height_with_members_;
    std::priority_queue<uint64_t, std::vector<uint64_t>, std::greater<uint64_t> > height_queue_;
    std::mutex height_with_members_mutex_;

    HeightMembersItemPtr members_ptrs_[kMaxKeepElectBlockCount];

    DISALLOW_COPY_AND_ASSIGN(HeightWithElectBlock);
};

}  // namespace elect

}  // namespace tenon
