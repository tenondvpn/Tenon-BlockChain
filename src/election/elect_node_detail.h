#pragma once

#include <memory>

#include "common/utils.h"
#include "common/user_property_key_define.h"
#include "security/public_key.h"
#include "security/commit_secret.h"
#include "security/commit_point.h"

namespace tenon {

namespace elect {

struct ElectNodeDetail {
    std::string id;
    std::string public_key;
    std::string public_ip;
    uint16_t public_port;
    std::string dht_key;
    std::atomic <uint64_t> choosed_height;
    std::atomic <uint64_t> choosed_balance;
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

    bool operator() (const ElectNodeDetail& left, const ElectNodeDetail& right) {
        return left.id < right.id;
    }
};

typedef std::shared_ptr<ElectNodeDetail> NodeDetailPtr;

struct BftMember {
    BftMember(
            uint32_t nid,
            const std::string& in_id,
            const std::string& pkey,
            uint32_t idx,
            const std::string& pubip,
            uint16_t pubport,
            const std::string& dhtkey)
            : net_id(nid),
            id(in_id),
            pubkey(pkey),
            index(idx),
            public_ip(pubip),
            public_port(pubport),
            dht_key(dhtkey) {
    }

    uint32_t net_id;
    std::string id;
    security::PublicKey pubkey;
    uint32_t index;
    std::string public_ip;
    uint16_t public_port;
    std::string dht_key;
    security::CommitSecret secret;
    security::CommitPoint commit_point;
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

};  // namespace elect

};  // namespace tenon