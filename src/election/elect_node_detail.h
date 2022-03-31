#pragma once

#include <memory>
#include <atomic>
#include <set>
#include <mutex>
#include <unordered_map>
#include <cstdint>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "common/utils.h"
#include "common/user_property_key_define.h"
#include "security/public_key.h"

namespace tenon {

namespace elect {

struct ElectNodeDetail {
    std::string id;
    std::string public_key;
    uint32_t public_ip;
    uint16_t public_port;
    std::string dht_key;
    std::atomic<uint64_t> choosed_height;
    std::atomic<uint64_t> choosed_balance;
    uint64_t balance_diff{ 0 };
    std::chrono::steady_clock::time_point join_tm{ std::chrono::steady_clock::now() };
    std::map<uint64_t, uint32_t> heatbeat_succ_count;
    std::map<uint64_t, uint32_t> heatbeat_fail_count;
    std::mutex heartbeat_mutex;
    // for election, give nearest 9 heights for every node consensus balance
    std::map<uint64_t, uint64_t> height_with_balance;
    std::mutex height_with_balance_mutex;
    // for election, last period every node consensus success tx count
    std::atomic<uint32_t> success_tx_count;
    uint64_t fts_value;
    std::unordered_set<std::string> valid_node_set;
    std::mutex valid_node_set_mutex;
    int32_t init_pool_index_mod_num{ -1 };
    int32_t index{ -1 };

    bool operator() (const ElectNodeDetail& left, const ElectNodeDetail& right) {
        return left.id < right.id;
    }
};

typedef std::shared_ptr<ElectNodeDetail> NodeDetailPtr;

struct WaitingList {
    std::vector<NodeDetailPtr> nodes_vec;
    uint64_t nodes_hash;
    std::unordered_set<std::string> added_nodes;
};

typedef std::shared_ptr<WaitingList> WaitingListPtr;

struct BftMember {
    BftMember(
            uint32_t nid,
            const std::string& in_id,
            const std::string& pkey,
            uint32_t idx,
            const std::string& dhtkey,
            int32_t pool_mode_num)
            : net_id(nid),
            id(in_id),
            pubkey(pkey),
            index(idx),
            public_ip(""),
            public_port(0),
            dht_key(dhtkey) {
        assert(pubkey.ec_point());
        pool_index_mod_num = pool_mode_num;
    }

    uint32_t net_id;
    std::string id;
    security::PublicKey pubkey;
    uint32_t index;
    std::string public_ip;
    uint16_t public_port;
    std::string dht_key;
    int32_t pool_index_mod_num;
    std::string backup_ecdh_key;
    std::string leader_ecdh_key;
    libff::alt_bn128_G2 bls_publick_key;
    bool valid_leader{ true };
};

typedef std::shared_ptr<BftMember> BftMemberPtr;
typedef std::vector<BftMemberPtr> Members;
typedef std::shared_ptr<Members> MembersPtr;

typedef std::shared_ptr<std::unordered_map<std::string, uint32_t>> NodeIndexMapPtr;

inline static bool ElectNodeIdCompare(
        const NodeDetailPtr& left,
        const NodeDetailPtr& right) {
    return left->id < right->id;
}

inline static bool ElectNodeBalanceCompare(
    const NodeDetailPtr& left,
    const NodeDetailPtr& right) {
    return left->choosed_balance < right->choosed_balance;
}

inline static bool ElectNodeBalanceDiffCompare(
        const NodeDetailPtr& left,
        const NodeDetailPtr& right) {
    return left->balance_diff < right->balance_diff;
}

inline static bool WaitingNodeCountCompare(
        const WaitingListPtr& left,
        const WaitingListPtr& right) {
    return left->added_nodes.size() > right->added_nodes.size();
}

};  // namespace elect

};  // namespace tenon
