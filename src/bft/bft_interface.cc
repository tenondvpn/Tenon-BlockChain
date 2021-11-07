#include "stdafx.h"
#include "bft/bft_interface.h"

#include <bls/bls_sign.h>

#include "bls/bls_manager.h"
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
    elect_height_ = elect::ElectManager::Instance()->latest_height(
            common::GlobalInfo::Instance()->network_id());
    leader_mem_ptr_ = elect::ElectManager::Instance()->local_mem_ptr(
        common::GlobalInfo::Instance()->network_id());
    if (leader_mem_ptr_ == nullptr) {
        BFT_ERROR("get leader bft member failed! network_id: %d",
            common::GlobalInfo::Instance()->network_id());
        return kBftError;
    }

    local_sec_key_ = bls::BlsManager::Instance()->local_sec_key();
    if (local_sec_key_ == libff::alt_bn128_Fr::zero()) {
        BFT_ERROR("local sec key is zero!");
        return kBftError;
    }

    leader_index_ = leader_mem_ptr_->index;
    // just leader call init
    this_node_is_leader_ = true;
    if (elect_height_ != elect::ElectManager::Instance()->latest_height(
        common::GlobalInfo::Instance()->network_id())) {
        BFT_ERROR("elect_height_ %lu not equal to latest election height: %lu!",
            elect_height_,
            elect::ElectManager::Instance()->latest_height(
            common::GlobalInfo::Instance()->network_id()));
        return kBftError;
    }

    return kBftSuccess;
}

bool BftInterface::ThisNodeIsLeader(const bft::protobuf::BftMessage& bft_msg) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!leader_mem_ptr_) {
        BFT_ERROR("get leader failed!.");
        return false;
    }

    auto local_mem_ptr = elect::ElectManager::Instance()->local_mem_ptr(bft_msg.net_id());
    if (local_mem_ptr == nullptr) {
        BFT_ERROR("get local bft member failed!");
        return false;
    }

    if (local_mem_ptr == leader_mem_ptr_) {
        return true;
    }

    return false;
}

bool BftInterface::CheckLeaderPrepare(const bft::protobuf::BftMessage& bft_msg) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (leader_mem_ptr_ == nullptr) {
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

    local_sec_key_ = bls::BlsManager::Instance()->local_sec_key();
    if (local_sec_key_ == libff::alt_bn128_Fr::zero()) {
        return false;
    }

    bool leader_valid = false;
    auto need_mod_index = (int32_t)pool_index() % leader_count;
    for (uint32_t i = 0; i < common::kNodeModIndexMaxCount; ++i) {
        if (leader_mem_ptr_->pool_index_mod_num[i] < 0) {
            return false;
        }

        if (need_mod_index == leader_mem_ptr_->pool_index_mod_num[i]) {
            leader_valid = true;
            break;
        }
    }

    if (!leader_valid) {
        BFT_ERROR("pool index invalid[%u] leader_count[%d] pool_mod_idx[%d][%u]. network id[%d]",
            pool_index(), leader_count,
            leader_mem_ptr_->pool_index_mod_num[0],
            (int32_t)pool_index() % leader_count,
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
//     security::Signature sign(bft_msg.sign_challenge(), bft_msg.sign_response());
//     std::string str_pubkey;
//     leader_mem_ptr_->pubkey.Serialize(str_pubkey);
//     if (!security::Schnorr::Instance()->Verify(prepare_hash(), sign, leader_mem_ptr_->pubkey)) {
//         BFT_ERROR("leader signature verify failed!");
//         return false;
//     }

    leader_index_ = leader_mem_ptr_->index;
    auto local_mem_ptr = elect::ElectManager::Instance()->local_mem_ptr(bft_msg.net_id());
    if (local_mem_ptr == nullptr) {
        BFT_ERROR("get local bft member failed!");
        return false;
    }

    if (elect_height_ != elect::ElectManager::Instance()->latest_height(
            common::GlobalInfo::Instance()->network_id())) {
        BFT_ERROR("elect_height_ %lu not equal to latest election height: %lu!",
            elect_height_,
            elect::ElectManager::Instance()->latest_height(
                common::GlobalInfo::Instance()->network_id()));
        return false;
    }

    // keep the latest election
    if (elect::ElectManager::Instance()->latest_height(
            common::GlobalInfo::Instance()->network_id()) != bft_msg.elect_height()) {
        BFT_ERROR("leader elect height not equal to local. "
            "local elect height: %lu, leader elect height: %lu",
            elect_height_, bft_msg.elect_height());
        return false;
    }

    return true;
}

bool BftInterface::BackupCheckLeaderValid(const bft::protobuf::BftMessage& bft_msg) {
    auto local_elect_height = elect::ElectManager::Instance()->latest_height(
        common::GlobalInfo::Instance()->network_id());
    std::lock_guard<std::mutex> guard(mutex_);
    if (local_elect_height < bft_msg.elect_height()) {
        BFT_ERROR("leader elect height not equal to local. "
            "local elect height: %lu, leader elect height: %lu",
            local_elect_height, bft_msg.elect_height());
        return false;
    }

    auto members = elect::ElectManager::Instance()->GetNetworkMembersWithHeight(
        bft_msg.elect_height(),
        common::GlobalInfo::Instance()->network_id());
    if (members == nullptr || bft_msg.member_index() >= members->size()) {
        BFT_ERROR("get members failed!.");
        return false;
    }

    leader_mem_ptr_ = (*members)[bft_msg.member_index()];
    if (!leader_mem_ptr_) {
        BFT_ERROR("get leader failed!.");
        return false;
    }

    if (local_elect_height != bft_msg.elect_height()) {
        BFT_ERROR("leader elect height not equal to local. local_elect_height: %lu, leader: %lu",
            local_elect_height, bft_msg.elect_height());
        return false;
    }

    elect_height_ = local_elect_height;
    members_ptr_ = members;
    return true;
}

int BftInterface::LeaderPrecommitOk(
        uint32_t index,
        const std::string& bft_gid,
        uint32_t msg_id,
        const libff::alt_bn128_G1& backup_sign,
        const std::string& id) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (leader_handled_precommit_) {
//         BFT_DEBUG("leader_handled_precommit_: %d", leader_handled_precommit_);
        return kBftHandled;
    }

    precommit_aggree_set_.insert(id);
    prepare_bitmap_.Set(index);
    backup_precommit_signs_[index] = backup_sign;
    BFT_DEBUG("precommit_aggree_set_.size: %u, index: %d, min_prepare_member_count_: %u, min_aggree_member_count_: %u, id: %s, bft_gid: %s",
        precommit_aggree_set_.size(), index, min_prepare_member_count_, min_aggree_member_count_, common::Encode::HexEncode(id).c_str(), common::Encode::HexEncode(bft_gid).c_str());
    if (precommit_aggree_set_.size() >= min_aggree_member_count_) {
        if (LeaderCreatePreCommitAggChallenge() != kBftSuccess) {
            BFT_ERROR("create bls precommit agg sign failed!");
            return kBftOppose;
        }

        leader_handled_precommit_ = true;
        BFT_DEBUG("precommit_aggree_set_ bft_gid: %s", common::Encode::HexEncode(bft_gid).c_str());
        return kBftAgree;
    }

    return kBftWaitingBackup;
}

int BftInterface::LeaderCommitOk(
        uint32_t index,
        const libff::alt_bn128_G1& backup_sign,
        const std::string& id) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (leader_handled_commit_) {
        return kBftHandled;
    }

    if (!prepare_bitmap_.Valid(index)) {
        return kBftWaitingBackup;
    }

    auto mem_ptr = elect::ElectManager::Instance()->GetMember(network_id_, index);
    commit_aggree_set_.insert(id);
    precommit_bitmap_.Set(index);
    backup_commit_signs_[index] = backup_sign;
    BFT_DEBUG("LeaderCommitOk.size: %u, index: %d, min_prepare_member_count_: %u, min_aggree_member_count_: %u, id: %s, bft_gid: %s",
        commit_aggree_set_.size(), index, min_prepare_member_count_, min_aggree_member_count_, common::Encode::HexEncode(id).c_str(),
        common::Encode::HexEncode(gid_).c_str());
    if (commit_aggree_set_.size() >= min_aggree_member_count_) {
        leader_handled_commit_ = true;
        if (LeaderCreateCommitAggSign() != kBftSuccess) {
            BFT_ERROR("leader create commit agg sign failed!");
            return kBftOppose;
        }

        return kBftAgree;
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
    precommit_aggree_set_.clear();
    precommit_oppose_set_.clear();
    commit_oppose_set_.clear();
}

int BftInterface::LeaderCreatePreCommitAggChallenge() {
    std::vector<libff::alt_bn128_G1> all_signs;
    std::vector<security::PublicKey> pubkeys;
    uint32_t bit_size = prepare_bitmap_.data().size() * 64;
    uint32_t t = min_aggree_member_count_;
    uint32_t n = members_ptr_->size();
    std::vector<size_t> idx_vec;
    for (uint32_t i = 0; i < n; ++i) {
        if (!prepare_bitmap_.Valid(i)) {
            continue;
        }

        assert(backup_precommit_signs_[i] != libff::alt_bn128_G1::zero());
        all_signs.push_back(backup_precommit_signs_[i]);
        idx_vec.push_back(i + 1);
        BFT_INFO("valid index: %d", i);
        if (idx_vec.size() >= t) {
            break;
        }
    }

    try {
        crypto::Bls bls_instance = crypto::Bls(t, n);
        auto lagrange_coeffs = crypto::ThresholdUtils::LagrangeCoeffs(idx_vec, t);
        bls_precommit_agg_sign_ = std::make_shared<libff::alt_bn128_G1>(
            bls_instance.SignatureRecover(
            all_signs,
            lagrange_coeffs));
        std::string msg_hash_src = prepare_hash();
        for (uint32_t i = 0; i < prepare_bitmap_.data().size(); ++i) {
            msg_hash_src += std::to_string(prepare_bitmap_.data()[i]);
        }

        auto common_pk = elect::ElectManager::Instance()->GetCommonPublicKey(
            elect_height_,
            network_id_);
        if (common_pk == libff::alt_bn128_G2::zero()) {
            assert(false);
        }

        precommit_hash_ = common::Hash::Hash256(msg_hash_src);        if (bls::BlsManager::Instance()->Verify(
                t,
                n,
                common_pk,
                *bls_precommit_agg_sign_,
                prepare_hash_) != bls::kBlsSuccess) {
            common_pk.to_affine_coordinates();
            auto cpk = std::make_shared<BLSPublicKey>(common_pk);
            auto cpk_strs = cpk->toString();
            BFT_ERROR("leader verify leader precommit agg sign failed! t: %u, n: %u,"
                "common public key: %s, %s, %s, %s, elect height: %lu, network id: %u, prepare hash: %s",
                t, n, cpk_strs->at(0).c_str(), cpk_strs->at(1).c_str(), cpk_strs->at(2).c_str(), cpk_strs->at(3).c_str(),
                elect_height_, network_id_, common::Encode::HexEncode(prepare_hash_).c_str());
            assert(false);
            return kBftError;
        } else {            common_pk.to_affine_coordinates();
            auto cpk = std::make_shared<BLSPublicKey>(common_pk);
            auto cpk_strs = cpk->toString();
            BFT_DEBUG("leader verify leader precommit agg sign success! t: %u, n: %u,"
                "common public key: %s, %s, %s, %s, elect height: %lu, network id: %u, prepare hash: %s",
                t, n, cpk_strs->at(0).c_str(), cpk_strs->at(1).c_str(), cpk_strs->at(2).c_str(), cpk_strs->at(3).c_str(),
                elect_height_, network_id_, common::Encode::HexEncode(prepare_hash_).c_str());
        }
        bls_precommit_agg_sign_->to_affine_coordinates();
    } catch (std::exception& e) {
        BFT_ERROR("catch bls exception: %s", e.what());
        return kBftError;
    }

    return kBftSuccess;
}

int BftInterface::LeaderCreateCommitAggSign() {
    std::vector<libff::alt_bn128_G1> all_signs;
    std::vector<security::Response> responses;
    std::vector<security::PublicKey> pubkeys;
    uint32_t bit_size = precommit_bitmap_.data().size() * 64;
//     for (uint32_t i = 0; i < bit_size; ++i) {
//         if (!precommit_bitmap_.Valid(i)) {
//             continue;
//         }
// 
//         all_signs.push_back(backup_commit_signs_[i]);
//     }

    uint32_t t = min_aggree_member_count_;
    uint32_t n = members_ptr_->size();
    std::vector<size_t> idx_vec;
    for (uint32_t i = 0; i < bit_size; ++i) {
        if (!precommit_bitmap_.Valid(i)) {
            continue;
        }

        all_signs.push_back(backup_commit_signs_[i]);
        idx_vec.push_back(i + 1);
        if (idx_vec.size() >= min_aggree_member_count_) {
            break;
        }
    }

    try {
        crypto::Bls bls_instance = crypto::Bls(t, n);
        auto lagrange_coeffs = crypto::ThresholdUtils::LagrangeCoeffs(idx_vec, t);
        bls_commit_agg_sign_ = std::make_shared<libff::alt_bn128_G1>(bls_instance.SignatureRecover(
            all_signs,
            lagrange_coeffs));
        std::string msg_hash_src = precommit_hash();
        for (uint32_t i = 0; i < precommit_bitmap_.data().size(); ++i) {
            msg_hash_src += std::to_string(precommit_bitmap_.data()[i]);
        }

        commit_hash_ = common::Hash::Hash256(msg_hash_src);
        if (bls::BlsManager::Instance()->Verify(
                t,
                n,
                elect::ElectManager::Instance()->GetCommonPublicKey(
                elect_height_,
                network_id_),
                *bls_commit_agg_sign_,
                precommit_hash_) != bls::kBlsSuccess) {
            BFT_ERROR("leader verify leader commit agg sign failed!");
            return kBftError;
        }
//         if (bls::BlsSign::Verify(
//                 t,
//                 n,
//                 *bls_commit_agg_sign_,
//                 precommit_hash_,
//                 elect::ElectManager::Instance()->GetCommonPublicKey(
//                 elect_height_,
//                 network_id_)) != bls::kBlsSuccess) {
//             BFT_ERROR("leader verify leader commit agg sign failed!");
//             return kBftError;
//         }

        bls_commit_agg_sign_->to_affine_coordinates();
    } catch (...) {
        return kBftError;
    }

    return kBftSuccess;
}

}  // namespace bft

}  // namespace tenon
