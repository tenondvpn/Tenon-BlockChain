#include "stdafx.h"
#include "bft/bft_interface.h"

#include "common/encode.h"
#include "common/global_info.h"
#include "vss/vss_manager.h"
#include "election/member_manager.h"

namespace tenon {

namespace bft {

bool BftInterface::CheckLeaderPrepare(const bft::protobuf::BftMessage& bft_msg) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!BackupCheckLeaderValid(bft_msg)) {
        return false;
    }

    if (!bft_msg.has_node_id()) {
        BFT_ERROR("bft message has no node_id.");
        return false;
    }

    if (!bft_msg.has_net_id()) {
        BFT_ERROR("bft message has no net id.");
        return false;
    }

    auto leader_count = elect::ElectManager::Instance()->GetNetworkLeaderCount(
        common::GlobalInfo::Instance()->network_id());
    if (leader_count <= 0) {
        BFT_ERROR("leader_count invalid[%d].", leader_count);
        return false;
    }

    int32_t leader_pool_mod_idx = elect::ElectManager::Instance()->IsLeader(
        common::GlobalInfo::Instance()->network_id(),
        bft_msg.node_id());
    if ((int32_t)pool_index() % leader_count != leader_pool_mod_idx) {
        BFT_ERROR("pool index invalid[%u] leader_count[%d] pool_mod_idx[%d][%u].",
            pool_index(), leader_count, leader_pool_mod_idx, (int32_t)pool_index() % leader_count);
        return false;
    }

    if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
        BFT_ERROR("bft message has no sign challenge or sign response.");
        return false;
    }

    auto leader_mem_ptr = elect::ElectManager::Instance()->GetMember(
        common::GlobalInfo::Instance()->network_id(),
        bft_msg.node_id());
    if (leader_mem_ptr == nullptr) {
        BFT_ERROR("get leader bft member failed!");
        return false;
    }

    bft::protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        return false;
    }

    set_prepare_hash(GetBlockHash(tx_bft.ltx_prepare().block()));
    security::Signature sign(bft_msg.sign_challenge(), bft_msg.sign_response());
    if (!security::Schnorr::Instance()->Verify(prepare_hash(), sign, leader_mem_ptr->pubkey)) {
        BFT_ERROR("leader signature verify failed!");
        return false;
    }

    auto local_mem_ptr = elect::ElectManager::Instance()->GetMember(
            bft_msg.net_id(),
            common::GlobalInfo::Instance()->id());
    if (local_mem_ptr == nullptr) {
        BFT_ERROR("get local bft member failed!");
        return false;
    }

    leader_index_ = leader_mem_ptr->index;
    secret_ = local_mem_ptr->secret;
    return true;
}

bool BftInterface::BackupCheckLeaderValid(const bft::protobuf::BftMessage& bft_msg) {
    int32_t leader_pool_mod_idx = elect::ElectManager::Instance()->IsLeader(
        common::GlobalInfo::Instance()->network_id(),
        bft_msg.node_id());
    if (leader_pool_mod_idx < 0) {
        BFT_ERROR("prepare message not leader.[%u][%s][%u]",
            common::GlobalInfo::Instance()->network_id(),
            common::Encode::HexEncode(bft_msg.node_id()).c_str(),
            leader_pool_mod_idx);
        return false;
    }

    int32_t local_pool_mod_idx = elect::ElectManager::Instance()->IsLeader(
        common::GlobalInfo::Instance()->network_id(),
        common::GlobalInfo::Instance()->id());
    if (local_pool_mod_idx == leader_pool_mod_idx) {
        BFT_ERROR("this node is not backup.[%d][%d]", local_pool_mod_idx, leader_pool_mod_idx);
        return false;
    }

    return true;
}

bool BftInterface::LeaderCheckLeaderValid(const bft::protobuf::BftMessage& bft_msg) {
    int32_t local_pool_mod_idx = elect::ElectManager::Instance()->IsLeader(
        common::GlobalInfo::Instance()->network_id(),
        common::GlobalInfo::Instance()->id());
    int32_t leader_count = elect::ElectManager::Instance()->GetNetworkLeaderCount(
        common::GlobalInfo::Instance()->network_id());
    if ((int32_t)pool_index() % leader_count != local_pool_mod_idx) {
        BFT_ERROR("prepare message pool index invalid.[%u][%s][%d][%u]",
            common::GlobalInfo::Instance()->network_id(),
            common::Encode::HexEncode(bft_msg.node_id()).c_str(),
            local_pool_mod_idx,
            (int32_t)pool_index() % leader_count);
        return false;
    }

    return true;
}

int BftInterface::LeaderPrecommitOk(
        uint32_t index,
        bool agree,
        const security::CommitSecret& secret,
        const std::string& id) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (leader_handled_precommit_) {
        return kBftHandled;
    }

    if (agree) {
        precommit_aggree_set_.insert(id);
        auto backup_res = std::make_shared<BackupResponse>();
        backup_res->index = index;
        backup_res->secret = secret;
        backup_prepare_response_.insert(std::make_pair(index, backup_res));
        std::string sec_str;
        secret.Serialize(sec_str);
        prepare_bitmap_.Set(index);
    } else {
        precommit_oppose_set_.insert(id);
    }

    auto now_timestamp = std::chrono::steady_clock::now();
    if (precommit_aggree_set_.size() >= min_prepare_member_count_ ||
            (precommit_aggree_set_.size() > min_aggree_member_count_ &&
            now_timestamp >= prepare_timeout_)) {
        LeaderCreatePreCommitAggChallenge();
        leader_handled_precommit_ = true;
        return kBftAgree;
    }

    if (precommit_oppose_set_.size() >= min_oppose_member_count_) {
        leader_handled_precommit_ = true;
        return kBftOppose;
    }
    return kBftWaitingBackup;
}

int BftInterface::LeaderCommitOk(
        uint32_t index,
        bool agree,
        const security::Response& res,
        const std::string& id) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (leader_handled_commit_) {
        return kBftHandled;
    }

    if (!prepare_bitmap_.Valid(index)) {
        return kBftWaitingBackup;
    }

    if (agree) {
        auto mem_ptr = elect::ElectManager::Instance()->GetMember(network_id_, index);
        if (!security::MultiSign::Instance()->VerifyResponse(
                res,
                challenge_,
                mem_ptr->pubkey,
                mem_ptr->commit_point)) {
            BFT_ERROR("invalid backup response.");
            return kBftWaitingBackup;
        }

        commit_aggree_set_.insert(id);
        precommit_bitmap_.Set(index);
        auto backup_res = std::make_shared<BackupResponse>();
        backup_res->response = res;
        backup_res->index = index;
        backup_precommit_response_[index] = backup_res;  // just cover with rechallenge
    } else {
        commit_oppose_set_.insert(id);
    }

    if (precommit_bitmap_ == prepare_bitmap_) {
        leader_handled_commit_ = true;
        if (LeaderCreateCommitAggSign() != kBftSuccess) {
            BFT_ERROR("leader create commit agg sign failed!");
            return kBftOppose;
        }

        return kBftAgree;
    }

    std::string res_str;
    res.Serialize(res_str);

    auto now_timestamp = std::chrono::steady_clock::now();
    if (now_timestamp >= precommit_timeout_) {
        // todo re-challenge
        if (precommit_bitmap_.valid_count() < min_aggree_member_count_) {
            BFT_ERROR("precommit_bitmap_.valid_count() failed!");
            return kBftOppose;
        }

        prepare_bitmap_ = precommit_bitmap_;
        LeaderCreatePreCommitAggChallenge();
        RechallengePrecommitClear();
        return kBftReChallenge;
    }

    if (commit_oppose_set_.size() >= min_oppose_member_count_) {
        leader_handled_commit_ = true;
        BFT_ERROR("oppose count limited!");
        return kBftOppose;
    }

    return kBftWaitingBackup;
}

int BftInterface::CheckTimeout() {
    if (timeout_ <= std::chrono::steady_clock::now()) {
        return kTimeout;
    }

    if (GetLeaderPoolIndex() < 0) {
        return kBftSuccess;
    }

    std::lock_guard<std::mutex> guard(mutex_);
    if (!leader_handled_precommit_) {
        auto now_timestamp = std::chrono::steady_clock::now();
        if (precommit_aggree_set_.size() >= min_prepare_member_count_ ||
                (precommit_aggree_set_.size() > min_aggree_member_count_ &&
                now_timestamp >= prepare_timeout_)) {
            LeaderCreatePreCommitAggChallenge();
            leader_handled_precommit_ = true;
            return kTimeoutCallPrecommit;
        }

        return kTimeoutWaitingBackup;
    }

    if (!leader_handled_commit_) {
        auto now_timestamp = std::chrono::steady_clock::now();
        if (now_timestamp >= precommit_timeout_) {
            if (precommit_bitmap_.valid_count() < min_aggree_member_count_) {
                BFT_ERROR("precommit_bitmap_.valid_count() failed!");
                return kTimeout;
            }

            prepare_bitmap_ = precommit_bitmap_;
            LeaderCreatePreCommitAggChallenge();
            RechallengePrecommitClear();
            return kTimeoutCallReChallenge;
        }

        return kTimeoutWaitingBackup;
    }

    return kTimeoutNormal;
}

void BftInterface::RechallengePrecommitClear() {
    leader_handled_commit_ = false;
    init_precommit_timeout();
    precommit_bitmap_.clear();
    commit_aggree_set_.clear();
    backup_precommit_response_.clear();
    precommit_aggree_set_.clear();
    precommit_oppose_set_.clear();
    commit_oppose_set_.clear();

}

int BftInterface::LeaderCreatePreCommitAggChallenge() {
    std::vector<security::PublicKey> pubkeys;
    uint32_t bit_size = prepare_bitmap_.data().size() * 64;
    std::vector<security::CommitPoint> points;
    for (uint32_t i = 0; i < bit_size; ++i) {
        if (!prepare_bitmap_.Valid(i)) {
            continue;
        }

        elect::BftMemberPtr mem_ptr = elect::ElectManager::Instance()->GetMember(network_id(), i);
        pubkeys.push_back(mem_ptr->pubkey);
        auto iter = backup_prepare_response_.find(i);
        assert(iter != backup_prepare_response_.end());
        mem_ptr->commit_point = security::CommitPoint(iter->second->secret);
        points.push_back(mem_ptr->commit_point);
    }

    auto agg_pubkey = security::MultiSign::AggregatePubKeys(pubkeys);
    assert(agg_pubkey != nullptr);
    auto agg_commit = security::MultiSign::AggregateCommits(points);
    assert(agg_commit != nullptr);
    challenge_ = security::Challenge(*agg_commit, *agg_pubkey, prepare_hash());
    assert(challenge_.inited());
    return kBftSuccess;
}

int BftInterface::LeaderCreateCommitAggSign() {
    assert(precommit_bitmap_ == prepare_bitmap_);
    std::vector<security::Response> responses;
    std::vector<security::PublicKey> pubkeys;
    uint32_t bit_size = precommit_bitmap_.data().size() * 64;
    for (uint32_t i = 0; i < bit_size; ++i) {
        if (!precommit_bitmap_.Valid(i)) {
            continue;
        }

        auto mem_ptr = elect::ElectManager::Instance()->GetMember(network_id(), i);
        auto iter = backup_precommit_response_.find(i);
        assert(iter != backup_precommit_response_.end());
        responses.push_back(iter->second->response);
        pubkeys.push_back(mem_ptr->pubkey);
    }

    auto agg_response = security::MultiSign::AggregateResponses(responses);
    assert(agg_response != nullptr);
    agg_sign_ = security::MultiSign::AggregateSign(challenge_, *agg_response);
    assert(agg_sign_ != nullptr);
    auto agg_pubkey = security::MultiSign::AggregatePubKeys(pubkeys);
    assert(agg_pubkey != nullptr);
    if (!security::MultiSign::Instance()->MultiSigVerify(
            prepare_hash(),
            *agg_sign_,
            *agg_pubkey)) {
        BFT_ERROR("leader agg sign and check it failed!");
        return kBftError;
    }

    return kBftSuccess;
}

int BftInterface::BackupCheckAggSign(const bft::protobuf::BftMessage& bft_msg) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!bft_msg.has_agg_sign_challenge() ||
            !bft_msg.has_agg_sign_response() ||
            bft_msg.bitmap_size() <= 0) {
        BFT_ERROR("commit must have agg sign.");
        return kBftError;
    }

    auto sign = security::Signature(
        bft_msg.agg_sign_challenge(),
        bft_msg.agg_sign_response());
    std::vector<uint64_t> data;
    for (int32_t i = 0; i < bft_msg.bitmap_size(); ++i) {
        data.push_back(bft_msg.bitmap(i));
    }

    common::Bitmap leader_agg_bitmap(data);
    std::vector<security::PublicKey> pubkeys;
    uint32_t bit_size = leader_agg_bitmap.data().size() * 64;
    for (uint32_t i = 0; i < bit_size; ++i) {
        if (!leader_agg_bitmap.Valid(i)) {
            continue;
        }

        auto mem_ptr = elect::ElectManager::Instance()->GetMember(network_id(), i);
        pubkeys.push_back(mem_ptr->pubkey);
    }

    auto agg_pubkey = security::MultiSign::AggregatePubKeys(pubkeys);
    assert(agg_pubkey != nullptr);
    if (!security::MultiSign::Instance()->MultiSigVerify(
            prepare_hash(),
            sign,
            *agg_pubkey)) {
        return kBftError;
    }

    return kBftSuccess;
}

}  // namespace bft

}  // namespace tenon
