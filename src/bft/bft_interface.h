#pragma once

#include <memory>
#include <string>
#include <mutex>
#include <unordered_map>

#include <bls/BLSutils.h>

#include "bft/bft_utils.h"
#include "bft/proto/bft.pb.h"
#include "bft/proto/bft.pb.h"
#include "common/utils.h"
#include "common/bitmap.h"
#include "security/signature.h"
#include "security/commit_secret.h"
#include "security/schnorr.h"
#include "security/commit_point.h"
#include "security/challenge.h"
#include "security/multi_sign.h"
#include "security/response.h"
#include "transport/transport_utils.h"
#include "election/elect_node_detail.h"
#include "election/member_manager.h"

namespace tenon {

namespace bft {

struct BackupResponse {
    uint32_t index;
    security::Response response;
    security::CommitSecret secret;
};
typedef std::shared_ptr<BackupResponse> BackupResponsePtr;

class BftInterface {
public:
    virtual int Init(bool leader) = 0;
    virtual int Prepare(
        bool leader,
        int32_t pool_mod_idx,
        const bft::protobuf::BftMessage& leaser_bft_msg,
        std::string* prepare) = 0;
    virtual int PreCommit(bool leader, std::string& pre_commit) = 0;
    virtual int Commit(bool leader, std::string& commit) = 0;

public:
    bool CheckLeaderPrepare(const bft::protobuf::BftMessage& bft_msg);
    int LeaderPrecommitOk(
        uint32_t index,
        const std::string& bft_gid,
        uint32_t msg_id,
        bool agree,
        const libff::alt_bn128_G1& backup_sign,
        const std::string& id);
    int LeaderCommitOk(
        uint32_t index,
        bool agree,
        const libff::alt_bn128_G1& backup_sign,
        const std::string& id);
    int CheckTimeout();
    bool BackupCheckLeaderValid(const bft::protobuf::BftMessage& bft_msg);
    bool ThisNodeIsLeader(const bft::protobuf::BftMessage& bft_msg);

    void set_pool_index(uint32_t pool_idx) {
        pool_index_ = pool_idx;
    }

    uint32_t pool_index() {
        return pool_index_;
    }

    void set_gid(const std::string& gid) {
        gid_ = gid;
    }

    const std::string& gid() {
        return gid_;
    }

    void set_network_id(uint32_t net_id) {
        network_id_ = net_id;
    }

    uint32_t network_id() {
        return network_id_;
    }

    void set_randm_num(uint64_t rnum) {
        rand_num_ = rnum;
    }

    uint64_t rand_num() {
        return rand_num_;
    }

    uint32_t min_aggree_member_count() {
        return min_aggree_member_count_;
    }

    uint32_t min_oppose_member_count() {
        return min_oppose_member_count_;
    }

    uint32_t min_prepare_member_count() {
        return min_prepare_member_count_;
    }

    uint32_t precommit_aggree_count() {
        std::lock_guard<std::mutex> guard(mutex_);
        return precommit_aggree_set_.size();
    }

    uint32_t commit_aggree_count() {
        std::lock_guard<std::mutex> guard(mutex_);
        return commit_aggree_set_.size();
    }

    void set_member_count(uint32_t mem_cnt) {
        member_count_ = mem_cnt;
        min_aggree_member_count_ = member_count_ * 2 / 3;
        if ((member_count_ * 2) % 3 > 0) {
            min_aggree_member_count_ += 1;
        }

        min_oppose_member_count_ = member_count_ / 3;
        if (member_count_ % 3 > 0) {
            min_oppose_member_count_ += 1;
        }

        min_prepare_member_count_ = member_count_ * 9 / 10;
//         if ((member_count_ * 9) % 10 > 0) {
//             min_prepare_member_count_ += 1;
//         }
    }

    const common::Bitmap& precommit_bitmap() const {
        return precommit_bitmap_;
    }

    void set_status(uint32_t status) {
        status_ = status;
    }

    uint32_t status() {
        return status_;
    }

    std::vector<uint64_t> item_index_vec() {
        std::lock_guard<std::mutex> guard(item_index_vec_mutex_);
        return item_index_vec_;
    }

    void add_item_index_vec(uint64_t index) {
        std::lock_guard<std::mutex> guard(item_index_vec_mutex_);
        item_index_vec_.push_back(index);
    }

    void clear_item_index_vec() {
        std::lock_guard<std::mutex> guard(item_index_vec_mutex_);
        item_index_vec_.clear();
    }

    void reset_timeout() {
        timeout_ = (std::chrono::steady_clock::now() +
                std::chrono::microseconds(kBftTimeout));
    }

    uint32_t member_count() {
        return member_count_;
    }

    uint32_t min_agree_member_count() {
        return min_aggree_member_count_;
    }

    const std::string& prepare_hash() const {
        return prepare_hash_;
    }

    void set_prepare_hash(const std::string& prepare_hash) {
        prepare_hash_ = prepare_hash;
    }

    void set_precoimmit_hash(const std::string& precommit_hash) {
        precommit_hash_ = precommit_hash;
    }

    uint32_t leader_index() const {
        return leader_index_;
    }

    const common::Bitmap& prepare_bitmap() const {
        return prepare_bitmap_;
    }

    const std::string& precommit_hash() const {
        return precommit_hash_;
    }

    const std::shared_ptr<libff::alt_bn128_G1>& bls_precommit_agg_sign() const {
        assert(bls_precommit_agg_sign_ != nullptr);
        return bls_precommit_agg_sign_;
    }

    const std::shared_ptr<libff::alt_bn128_G1>& bls_commit_agg_sign() const {
        assert(bls_commit_agg_sign_ != nullptr);
        return bls_commit_agg_sign_;
    }

    void init_prepare_timeout() {
        prepare_timeout_ = (std::chrono::steady_clock::now() +
                std::chrono::microseconds(kBftLeaderPrepareWaitPeriod));
    }

    void init_precommit_timeout() {
        precommit_timeout_ = (std::chrono::steady_clock::now() +
                std::chrono::microseconds(kBftLeaderPrepareWaitPeriod));
    }

    std::vector<std::string> bft_item_vec() {
        std::lock_guard<std::mutex> guard(bft_item_vec_mutex_);
        return bft_item_vec_;
    }

    void push_bft_item_vec(const std::string& gid) {
        std::lock_guard<std::mutex> guard(bft_item_vec_mutex_);
        bft_item_vec_.push_back(gid);
    }

    uint32_t bft_item_count() {
        return bft_item_vec_.size();
    }

    std::shared_ptr<bft::protobuf::Block>& prpare_block() {
        return prpare_block_;
    }

    void AddInvalidTxIndex(int32_t tx_index) {
        std::lock_guard<std::mutex> guard(invalid_tx_index_count_mutex_);
        auto iter = invalid_tx_index_count_.find(tx_index);
        if (iter == invalid_tx_index_count_.end()) {
            invalid_tx_index_count_[tx_index] = 1;
        } else {
            ++iter->second;
        }
    }

    int32_t GetInvalidTxIndex() {
        std::lock_guard<std::mutex> guard(invalid_tx_index_count_mutex_);
        for (auto iter = invalid_tx_index_count_.begin();
                iter != invalid_tx_index_count_.end(); ++iter) {
            if (iter->second >= min_oppose_member_count_) {
                return iter->first;
            }
        }

        return -1;
    }

    void ClearInvalidTxIndex() {
        std::lock_guard<std::mutex> guard(invalid_tx_index_count_mutex_);
        invalid_tx_index_count_.clear();
    }

    bool aggree() {
        return aggree_;
    }

    void not_aggree() {
        aggree_ = false;
    }

    void AddBftEpoch() {
        ++bft_epoch_;
    }

    uint32_t GetEpoch() {
        return bft_epoch_;
    }

    void SetEpoch(uint32_t epoch) {
        bft_epoch_ = epoch;
    }

    int Init();
    elect::BftMemberPtr& leader_mem_ptr() {
        return leader_mem_ptr_;
    }

    elect::MembersPtr& members_ptr() {
        return members_ptr_;
    }

    std::shared_ptr<elect::MemberManager>& mem_manager_ptr() {
        return mem_manager_ptr_;
    }

    void add_prepair_failed_node_index(uint32_t index) {
        std::lock_guard<std::mutex> guard(prepare_enc_failed_nodes_mutex_);
        prepare_enc_failed_nodes_.insert(index);
    }

    uint64_t elect_height() {
        return elect_height_;
    }

    bool this_node_is_leader() {
        return this_node_is_leader_;
    }

    uint32_t add_prepare_verify_failed_count() {
        return ++prepare_verify_failed_count_;
    }

    const libff::alt_bn128_Fr& local_sec_key() const {
        return local_sec_key_;
    }

protected:
    BftInterface();
    virtual ~BftInterface() {}

    void SetBlock(std::shared_ptr<bft::protobuf::Block>& prpare_block) {
        prpare_block_ = prpare_block;
    }

    int LeaderCreatePreCommitAggChallenge();
    int LeaderCreateCommitAggSign();
    void RechallengePrecommitClear();

    elect::MembersPtr members_ptr_{ nullptr };
    std::shared_ptr<elect::MemberManager> mem_manager_ptr_{ nullptr };
    uint32_t pool_index_{ (std::numeric_limits<uint32_t>::max)() };
    std::string gid_;
    uint32_t network_id_{ 0 };
    uint32_t leader_index_{ 0 };
    uint64_t rand_num_{ 0 };
    bool leader_handled_precommit_{ false };
    bool leader_handled_commit_{ false };
    std::mutex mutex_;
    uint32_t member_count_{ 0 };
    uint32_t min_aggree_member_count_{ 0 };
    uint32_t min_oppose_member_count_{ 0 };
    uint32_t min_prepare_member_count_{ 0 };
    common::Bitmap prepare_bitmap_{ common::kEachShardMaxNodeCount };
    common::Bitmap precommit_bitmap_{ common::kEachShardMaxNodeCount };
    uint32_t status_{ kBftInit };
    std::vector<uint64_t> item_index_vec_;
    std::mutex item_index_vec_mutex_;
    std::chrono::steady_clock::time_point timeout_;
    std::string prepare_hash_;
    std::chrono::steady_clock::time_point prepare_timeout_;
    std::chrono::steady_clock::time_point precommit_timeout_;
    std::vector<std::string> bft_item_vec_;
    std::mutex bft_item_vec_mutex_;
    std::shared_ptr<bft::protobuf::Block> prpare_block_{ nullptr };
    std::unordered_set<std::string> precommit_aggree_set_;
    std::unordered_set<std::string> precommit_oppose_set_;
    std::unordered_set<std::string> commit_aggree_set_;
    std::unordered_set<std::string> commit_oppose_set_;
    std::unordered_map<int32_t, uint32_t> invalid_tx_index_count_;
    std::mutex invalid_tx_index_count_mutex_;
    std::mutex msg_step_ptr_mutex_;
    std::atomic<bool> aggree_{ true };
    std::atomic<uint32_t> bft_epoch_{ 0 };
    elect::BftMemberPtr leader_mem_ptr_{ nullptr };
    std::set<uint32_t> prepare_enc_failed_nodes_;
    std::mutex prepare_enc_failed_nodes_mutex_;
    bool this_node_is_leader_{ false };
    uint64_t elect_height_{ 0 };
    libff::alt_bn128_G1 backup_precommit_signs_[common::kEachShardMaxNodeCount];
    libff::alt_bn128_G1 backup_commit_signs_[common::kEachShardMaxNodeCount];
    std::shared_ptr<libff::alt_bn128_G1> bls_precommit_agg_sign_{ nullptr };
    std::shared_ptr<libff::alt_bn128_G1> bls_commit_agg_sign_{ nullptr };
    std::string precommit_hash_;
    std::string commit_hash_;
    std::atomic<uint32_t> prepare_verify_failed_count_{ 0 };
    libff::alt_bn128_Fr local_sec_key_;
    DISALLOW_COPY_AND_ASSIGN(BftInterface);
};

typedef std::shared_ptr<BftInterface> BftInterfacePtr;

}  // namespace bft

}  // namespace tenon
