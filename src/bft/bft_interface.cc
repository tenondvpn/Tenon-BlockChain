#include "stdafx.h"
#include "bft/bft_interface.h"

#include "common/encode.h"
#include "common/global_info.h"
#include "vss/vss_manager.h"
#include "election/elect_manager.h"

namespace tenon {

namespace bft {

BftInterface::BftInterface() {
    reset_timeout();
    bft_item_vec_.reserve(kBftOneConsensusMaxCount);
}

int BftInterface::Init() {
    leader_mem_ptr_ = elect::ElectManager::Instance()->local_mem_ptr(
        common::GlobalInfo::Instance()->network_id());
    if (leader_mem_ptr_ == nullptr) {
        BFT_ERROR("get leader bft member failed!");
        return kBftError;
    }

    leader_index_ = leader_mem_ptr_->index;
    secret_ = leader_mem_ptr_->secret;
    // just leader call init
    this_node_is_leader_ = true;
    return kBftSuccess;
}

bool BftInterface::ThisNodeIsLeader(const bft::protobuf::BftMessage& bft_msg) {
    std::lock_guard<std::mutex> guard(mutex_);
    auto local_mem_ptr = elect::ElectManager::Instance()->local_mem_ptr(bft_msg.net_id());
    if (local_mem_ptr == nullptr) {
        BFT_ERROR("get local bft member failed!");
        return false;
    }

    if (local_mem_ptr->pool_index_mod_num == leader_mem_ptr_->pool_index_mod_num) {
        return true;
    }

    return false;
}

bool BftInterface::CheckLeaderPrepare(const bft::protobuf::BftMessage& bft_msg) {
    std::lock_guard<std::mutex> guard(mutex_);
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

    if ((int32_t)pool_index() % leader_count != leader_mem_ptr_->pool_index_mod_num) {
        BFT_ERROR("pool index invalid[%u] leader_count[%d] pool_mod_idx[%d][%u]. network id[%d]",
            pool_index(), leader_count, leader_mem_ptr_->pool_index_mod_num, (int32_t)pool_index() % leader_count,
            common::GlobalInfo::Instance()->network_id());
        return false;
    }

    if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
        BFT_ERROR("bft message has no sign challenge or sign response.");
        return false;
    }

    bft::protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        return false;
    }

    set_prepare_hash(GetBlockHash(tx_bft.ltx_prepare().block()));
    security::Signature sign(bft_msg.sign_challenge(), bft_msg.sign_response());
    std::string str_pubkey;
    leader_mem_ptr_->pubkey.Serialize(str_pubkey);
    if (!security::Schnorr::Instance()->Verify(prepare_hash(), sign, leader_mem_ptr_->pubkey)) {
        BFT_ERROR("leader signature verify failed!");
        return false;
    }

    leader_index_ = leader_mem_ptr_->index;
    auto local_mem_ptr = elect::ElectManager::Instance()->local_mem_ptr(bft_msg.net_id());
    if (local_mem_ptr == nullptr) {
        BFT_ERROR("get local bft member failed!");
        return false;
    }

    secret_ = local_mem_ptr->secret;
    return true;
}

bool BftInterface::BackupCheckLeaderValid(const bft::protobuf::BftMessage& bft_msg) {
    std::lock_guard<std::mutex> guard(mutex_);
    leader_mem_ptr_ = elect::ElectManager::Instance()->GetMember(
        common::GlobalInfo::Instance()->network_id(),
        bft_msg.member_index());
    if (!leader_mem_ptr_) {
        return false;
    }

    if (leader_mem_ptr_->pool_index_mod_num < 0) {
        BFT_ERROR("prepare message not leader.[%u][%d][%u]",
            common::GlobalInfo::Instance()->network_id(),
            bft_msg.member_index(),
            leader_mem_ptr_->pool_index_mod_num);
        return false;
    }

    return true;
}

bool BftInterface::LeaderCheckLeaderValid(const bft::protobuf::BftMessage& bft_msg) {
    std::lock_guard<std::mutex> guard(mutex_);
    int32_t leader_count = elect::ElectManager::Instance()->GetNetworkLeaderCount(
        common::GlobalInfo::Instance()->network_id());
    if ((int32_t)pool_index() % leader_count != leader_mem_ptr_->pool_index_mod_num) {
        BFT_ERROR("prepare message pool index invalid.[%u][%s][%d][%u]",
            common::GlobalInfo::Instance()->network_id(),
            common::Encode::HexEncode(common::GlobalInfo::Instance()->id()).c_str(),
            leader_mem_ptr_->pool_index_mod_num,
            (int32_t)pool_index() % leader_count);
        return false;
    }

    return true;
}

int BftInterface::LeaderPrecommitOk(
        uint32_t index,
        const std::string& bft_gid,
        uint32_t msg_id,
        bool agree,
        const security::CommitSecret& secret,
        const std::string& id) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (leader_handled_precommit_) {
//         BFT_DEBUG("leader_handled_precommit_: %d", leader_handled_precommit_);
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

//     BFT_DEBUG("precommit_aggree_set_.size: %u, min_prepare_member_count_: %u, min_aggree_member_count_: %u",
//         precommit_aggree_set_.size(), min_prepare_member_count_, min_aggree_member_count_);
    auto now_timestamp = std::chrono::steady_clock::now();
    if (precommit_aggree_set_.size() >= min_prepare_member_count_ ||
            (precommit_aggree_set_.size() >= min_aggree_member_count_ &&
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

    std::string sec_str;
    secret_.Serialize(sec_str);
    if (agree) {
        auto mem_ptr = elect::ElectManager::Instance()->GetMember(network_id_, index);
        if (!security::MultiSign::Instance()->VerifyResponse(
                res,
                challenge_,
                mem_ptr->pubkey,
                mem_ptr->commit_point)) {
            BFT_ERROR("verify response failed!");
            commit_oppose_set_.insert(id);
        } else {
            commit_aggree_set_.insert(id);
            precommit_bitmap_.Set(index);
            auto backup_res = std::make_shared<BackupResponse>();
            backup_res->response = res;
            backup_res->index = index;
            backup_precommit_response_[index] = backup_res;  // just cover with rechallenge
        }
    } else {
        prepare_bitmap_.UnSet(index);
        if (prepare_bitmap_.valid_count() < min_aggree_member_count_) {
            BFT_ERROR("precommit_bitmap_.valid_count() failed!");
            return kBftOppose;
        }

        LeaderCreatePreCommitAggChallenge();
        RechallengePrecommitClear();
        return kBftReChallenge;
        
    }

    if (precommit_bitmap_ == prepare_bitmap_) {
        leader_handled_commit_ = true;
        if (LeaderCreateCommitAggSign() != kBftSuccess) {
            BFT_ERROR("leader create commit agg sign failed!");
            return kBftOppose;
        }

        return kBftAgree;
    }

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

    return kBftWaitingBackup;
}

int BftInterface::CheckTimeout() {
    auto now_timestamp = std::chrono::steady_clock::now();
    if (timeout_ <= now_timestamp) {
//         BFT_ERROR("Timeout %s,", common::Encode::HexEncode(gid()).c_str());
        return kTimeout;
    }

    if (!this_node_is_leader_) {
        return kBftSuccess;
    }

    std::lock_guard<std::mutex> guard(mutex_);
    if (!leader_handled_precommit_) {
        if (precommit_aggree_set_.size() >= min_prepare_member_count_ ||
                (precommit_aggree_set_.size() >= min_aggree_member_count_ &&
                now_timestamp >= prepare_timeout_)) {
            LeaderCreatePreCommitAggChallenge();
            leader_handled_precommit_ = true;
            BFT_ERROR("kTimeoutCallPrecommit %s,", common::Encode::HexEncode(gid()).c_str());
            return kTimeoutCallPrecommit;
        }

        return kTimeoutWaitingBackup;
    }

    if (!leader_handled_commit_) {
        if (now_timestamp >= precommit_timeout_) {
            if (precommit_bitmap_.valid_count() < min_aggree_member_count_) {
                BFT_ERROR("precommit_bitmap_.valid_count() failed!");
                return kTimeoutWaitingBackup;
            }

            prepare_bitmap_ = precommit_bitmap_;
            LeaderCreatePreCommitAggChallenge();
            RechallengePrecommitClear();
            BFT_ERROR("kTimeoutCallReChallenge %s,", common::Encode::HexEncode(gid()).c_str());
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

void BftInterface::CheckCommitRecallBackup() {
    if (!this_node_is_leader_) {
        return;
    }

    if (status_ != kBftCommit) {
        return;
    }

    if (leader_precommit_msg_ == nullptr) {
        return;
    }

    auto now_timestamp = std::chrono::steady_clock::now();
    if (now_timestamp < (precommit_timeout_ -
            std::chrono::microseconds(kBftLeaderPrepareWaitPeriod / 2)) ||
            now_timestamp >= (precommit_timeout_ - std::chrono::microseconds(50000))) {
        return;
    }

    if (precommit_bitmap_.valid_count() <= prepare_bitmap_.valid_count() * 9 / 10) {
        uint32_t bit_size = prepare_bitmap_.data().size() * 64;
        for (uint32_t i = 0; i < bit_size; ++i) {
            if (!prepare_bitmap_.Valid(i)) {
                continue;
            }

            if (precommit_bitmap_.Valid(i)) {
                continue;
            }

            auto mem_ptr = elect::ElectManager::Instance()->GetMember(network_id(), i);
            if (mem_ptr->public_ip == 0) {
                assert(false);
                continue;
            }

            // send precommit to backup and get response again
            std::string ip = common::IpUint32ToString(mem_ptr->public_ip);
            transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                ip, mem_ptr->public_port, 0, *leader_precommit_msg_);
        }
    }
}

}  // namespace bft

}  // namespace tenon
