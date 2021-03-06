#pragma once

#include <mutex>
#include <unordered_map>
#include <memory>
#include <queue>
#include <vector>

#include <libbls/bls/BLSPublicKey.h>

#include "bft/proto/bft.pb.h"
#include "block/block_utils.h"
#include "bls/bls_manager.h"
#include "common/utils.h"
#include "ip/ip_count.h"
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
        HeightMembersItem(MembersPtr& m, uint64_t h) : members_ptr(m), height(h) {
            for (auto iter = m->begin(); iter != m->end(); ++iter) {
                ip_weight.AddIp((*iter)->public_ip);
            }
        }

        MembersPtr members_ptr;
        uint64_t height;
        libff::alt_bn128_G2 common_bls_publick_key;
        libff::alt_bn128_Fr local_sec_key;
        ip::IpWeight ip_weight;
    };

    typedef std::shared_ptr<HeightMembersItem> HeightMembersItemPtr;

public:

    HeightWithElectBlock() {}

    ~HeightWithElectBlock() {}

    // elect block is always coming in order or one time just one block, so no need to lock it
    void AddNewHeightBlock(
            uint64_t height,
            uint32_t network_id,
            MembersPtr& members_ptr,
            const libff::alt_bn128_G2& common_pk) {
        if (network_id >= network::kConsensusShardEndNetworkId) {
            return;
        }

        uint64_t min_height = common::kInvalidUint64;
        uint64_t min_index = 0;
        for (int32_t i = 0; i < 3; ++i) {
            if (members_ptrs_[network_id][i] == nullptr) {
                members_ptrs_[network_id][i] = std::make_shared<HeightMembersItem>(
                    members_ptr,
                    height);
                members_ptrs_[network_id][i]->common_bls_publick_key = common_pk;
                members_ptrs_[network_id][i]->local_sec_key =
                    bls::BlsManager::Instance()->GetSeckFromDb(height, network_id);
                return;
            }

            if (members_ptrs_[network_id][i]->height < min_height) {
                min_height = members_ptrs_[network_id][i]->height;
                min_index = i;
            }
        }

        if (min_height >= height) {
            return;
        }

        members_ptrs_[network_id][min_index] = std::make_shared<HeightMembersItem>(
            members_ptr,
            height);
        members_ptrs_[network_id][min_index]->common_bls_publick_key = common_pk;
        members_ptrs_[network_id][min_index]->local_sec_key =
            bls::BlsManager::Instance()->GetSeckFromDb(height, network_id);
    }

    ip::IpWeight GetIpWeight(uint64_t height, uint32_t network_id) {
        if (network_id >= network::kConsensusShardEndNetworkId) {
            return ip::IpWeight();
        }

        for (int32_t i = 0; i < 3; ++i) {
            if (members_ptrs_[network_id][i] != nullptr &&
                    members_ptrs_[network_id][i]->height == height) {
                return members_ptrs_[network_id][i]->ip_weight;
            }
        }

        auto members = GetMembersPtr(height, network_id, nullptr, nullptr);
        if (members == nullptr) {
            return ip::IpWeight();
        }

        ip::IpWeight weight;
        for (auto iter = members->begin(); iter != members->end(); ++iter) {
            weight.AddIp((*iter)->public_ip);
        }

        return weight;
    }

    libff::alt_bn128_G2 GetCommonPublicKey(uint64_t height, uint32_t network_id) {
        if (network_id >= network::kConsensusShardEndNetworkId) {
            return libff::alt_bn128_G2::zero();
        }

        for (int32_t i = 0; i < 3; ++i) {
            if (members_ptrs_[network_id][i] != nullptr &&
                members_ptrs_[network_id][i]->height == height) {
                return members_ptrs_[network_id][i]->common_bls_publick_key;
            }
        }

        std::lock_guard<std::mutex> guard(height_with_members_mutex_);
        return height_with_common_pks_[network_id][height];
    }

    MembersPtr GetMembersPtr(
            uint64_t height,
            uint32_t network_id,
            libff::alt_bn128_G2* common_pk,
            libff::alt_bn128_Fr* local_sec_key) {
        if (network_id >= network::kConsensusShardEndNetworkId) {
            return nullptr;
        }

        for (int32_t i = 0; i < 3; ++i) {
            if (members_ptrs_[network_id][i] != nullptr &&
                    members_ptrs_[network_id][i]->height == height) {
                if (common_pk != nullptr) {
                    *common_pk = members_ptrs_[network_id][i]->common_bls_publick_key;
                }

                if (local_sec_key != nullptr) {
                    *local_sec_key = members_ptrs_[network_id][i]->local_sec_key;
                }

                return members_ptrs_[network_id][i]->members_ptr;
            }
        }

        // get from cache map
        {
            std::lock_guard<std::mutex> guard(height_with_members_mutex_);
            if (common_pk != nullptr) {
                auto pk_iter = height_with_common_pks_[network_id].find(height);
                if (pk_iter != height_with_common_pks_[network_id].end()) {
                    *common_pk = pk_iter->second;
                }
            }

            if (local_sec_key != nullptr) {
                *local_sec_key = bls::BlsManager::Instance()->GetSeckFromDb(height, network_id);
            }

            auto iter = height_with_members_[network_id].find(height);
            if (iter != height_with_members_[network_id].end()) {
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
            auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(in[i].pubkey());
            shard_members_ptr->push_back(std::make_shared<BftMember>(
                elect_block.shard_network_id(),
                id,
                in[i].pubkey(),
                member_index++,
                in[i].public_ip(),
                in[i].dht_key(),
                in[i].pool_idx_mod_num()));
        }

        std::string bls_key = block::GetElectBlsMembersKey(
            height,
            elect_block.shard_network_id());
        std::string val;
        st = db::Db::Instance()->Get(bls_key, &val);
        libff::alt_bn128_G2 tmp_common_pk = libff::alt_bn128_G2::zero();
        if (st.ok()) {
            elect::protobuf::PrevMembers prev_members;
            if (prev_members.ParseFromString(val)) {
                std::vector<std::string> pkey_str = {
                    prev_members.common_pubkey().x_c0(),
                    prev_members.common_pubkey().x_c1(),
                    prev_members.common_pubkey().y_c0(),
                    prev_members.common_pubkey().y_c1()
                };

                auto n = prev_members.bls_pubkey_size();
                auto t = n * 2 / 3;
                if ((n * 2) % 3 > 0) {
                    t += 1;
                }

                BLSPublicKey pkey(std::make_shared<std::vector<std::string>>(pkey_str));
                tmp_common_pk = *pkey.getPublicKey();
            }
        }

        if (common_pk != nullptr) {
            if (tmp_common_pk == libff::alt_bn128_G2::zero()) {
                return nullptr;
            }

            *common_pk = tmp_common_pk;
        }

        {
            std::lock_guard<std::mutex> guard(height_with_members_mutex_);
            height_queue_.push(height);
            height_with_members_[network_id][height] = shard_members_ptr;
            if (st.ok()) {
                height_with_common_pks_[network_id][height] = tmp_common_pk;
            }

            if (height_queue_.size() > kMaxCacheElectBlockCount) {
                auto min_height = height_queue_.top();
                auto iter = height_with_members_[network_id].find(min_height);
                if (iter != height_with_members_[network_id].end()) {
                    height_with_members_[network_id].erase(iter);
                }

                auto pk_iter = height_with_common_pks_[network_id].find(min_height);
                if (pk_iter != height_with_common_pks_[network_id].end()) {
                    height_with_common_pks_[network_id].erase(pk_iter);
                }

                height_queue_.pop();
            }
        }

        return shard_members_ptr;
    }

private:
    static const uint32_t kMaxKeepElectBlockCount = 3u;
    static const uint32_t kMaxCacheElectBlockCount = 7u;
    std::map<uint64_t, MembersPtr> height_with_members_[network::kConsensusShardEndNetworkId];
    std::map<uint64_t, libff::alt_bn128_G2> height_with_common_pks_[network::kConsensusShardEndNetworkId];
    std::map<uint64_t, libff::alt_bn128_Fr> height_with_local_sec_key_[network::kConsensusShardEndNetworkId];
    std::priority_queue<uint64_t, std::vector<uint64_t>, std::greater<uint64_t>> height_queue_;
    std::mutex height_with_members_mutex_;
    HeightMembersItemPtr members_ptrs_[network::kConsensusShardEndNetworkId][kMaxKeepElectBlockCount];

    DISALLOW_COPY_AND_ASSIGN(HeightWithElectBlock);
};

}  // namespace elect

}  // namespace tenon
