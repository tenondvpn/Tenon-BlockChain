#include "stdafx.h"
#include "vss/vss_manager.h"

#include "common/time_utils.h"
#include "election/elect_utils.h"
#include "election/elect_manager.h"
#include "network/route.h"
#include "security/secp256k1.h"
#include "security/aes.h"
#include "security/crypto.h"
#include "vss/proto/vss_proto.h"

namespace tenon {

namespace vss {

VssManager* VssManager::Instance() {
    static VssManager ins;
    return &ins;
}

uint64_t VssManager::EpochRandom() {
    return epoch_random_;
}

void VssManager::OnTimeBlock(
        uint64_t tm_block_tm,
        uint64_t tm_height,
        uint64_t elect_height,
        uint64_t epoch_random) {
    auto root_members = elect::ElectManager::Instance()->GetNetworkMembers(
        elect_height,
        network::kRootCongressNetworkId);
    if (root_members == nullptr || root_members->empty()) {
        VSS_ERROR("invalid root members.");
        return;
    }

    std::lock_guard<std::mutex> guard(mutex_);
    if (prev_tm_height_ != common::kInvalidUint64 && prev_tm_height_ >= tm_height) {
        VSS_ERROR("prev_tm_height_ >= tm_height[%lu][%lu].", prev_tm_height_, tm_height);
        return;
    }

    ClearAll();
    local_index_ = elect::ElectManager::Instance()->GetMemberIndex(
        elect_height,
        network::kRootCongressNetworkId,
        common::GlobalInfo::Instance()->id());
    if (local_index_ == elect::kInvalidMemberIndex) {
        VSS_ERROR("local_index_ == elect::kInvalidMemberIndex.");
        return;
    }

    local_random_.OnTimeBlock(tm_block_tm);
    latest_tm_block_tm_ = tm_block_tm;
    prev_tm_height_ = tm_height;
    prev_elect_height_ = elect_height;
    member_count_ = elect::ElectManager::Instance()->GetMemberCount(
        elect_height,
        network::kRootCongressNetworkId);
    epoch_random_ = epoch_random;
}

void VssManager::ClearAll() {
    local_random_.ResetStatus();
    for (uint32_t i = 0; i < common::kEachShardMaxNodeCount; ++i) {
        other_randoms_[i].ResetStatus();
    }

    first_period_cheched_ = false;
    second_period_cheched_ = false;
    third_period_cheched_ = false;
}

void VssManager::CheckVssPeriods() {
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId &&
            local_index_ != elect::kInvalidMemberIndex) {
        // Joined root and continue
        std::lock_guard<std::mutex> guard(mutex_);
        CheckVssFirstPeriods();
        CheckVssSecondPeriods();
        CheckVssThirdPeriods();
    }

    vss_tick_.CutOff(kVssCheckPeriodTimeout, std::bind(&VssManager::CheckVssPeriods, this));
}

void VssManager::CheckVssFirstPeriods() {
    if (first_period_cheched_) {
        return;
    }

    if (IsVssFirstPeriods()) {
        BroadcastFirstPeriodHash();
        BroadcastFirstPeriodSplitRandom();
        first_period_cheched_ = true;
    }
}

void VssManager::CheckVssSecondPeriods() {
    if (second_period_cheched_) {
        return;
    }

    if (IsVssSecondPeriods()) {
        BroadcastSecondPeriodRandom();
        second_period_cheched_ = true;
    }
}

void VssManager::CheckVssThirdPeriods() {
    if (third_period_cheched_) {
        return;
    }

    if (IsVssThirdPeriods()) {
        BroadcastThirdPeriodSplitRandom();
        third_period_cheched_ = true;
    }
}

uint64_t VssManager::GetAllVssValid() {
    uint64_t final_random = 0;
    for (uint32_t i = 0; i < member_count_; ++i) {
        if (i == local_index_) {
            continue;
        }

        if (other_randoms_[i].IsRandomValid()) {
            final_random ^= other_randoms_[i].GetFinalRandomNum();
            continue;
        }
    }

    return final_random;
}

bool VssManager::IsVssFirstPeriods() {
    auto now_seconds = common::TimeUtils::TimestampSeconds();
    if (latest_tm_block_tm_ <= now_seconds &&
            latest_tm_block_tm_ + kVssFirstPeriodTimeout > now_seconds) {
        return true;
    }

    return false;
}

bool VssManager::IsVssSecondPeriods() {
    auto now_seconds = common::TimeUtils::TimestampSeconds();
    if (latest_tm_block_tm_ + kVssFirstPeriodTimeout <= now_seconds &&
            latest_tm_block_tm_ + kVssSecondPeriodTimeout > now_seconds) {
        return true;
    }

    return false;
}

bool VssManager::IsVssThirdPeriods() {
    auto now_seconds = common::TimeUtils::TimestampSeconds();
    if (latest_tm_block_tm_ + kVssSecondPeriodTimeout <= now_seconds &&
            latest_tm_block_tm_ + kVssThirdPeriodTimeout > now_seconds) {
        return true;
    }

    return false;
}

void VssManager::BroadcastFirstPeriodHash() {
    transport::protobuf::Header msg;
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        VSS_ERROR("not join network[%u]", common::GlobalInfo::Instance()->network_id());
        return;
    }

    VssProto::CreateHashMessage(
        dht->local_node(),
        local_random_.GetHash(),
        prev_tm_height_,
        prev_elect_height_,
        msg);
    if (msg.has_data()) {
        network::Route::Instance()->Send(msg);
#ifdef TENON_UNITTEST
        first_msg_ = msg;
#endif
    }
}

void VssManager::BroadcastSecondPeriodRandom() {
    transport::protobuf::Header msg;
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }

    VssProto::CreateRandomMessage(
        dht->local_node(),
        local_random_.GetFinalRandomNum(),
        prev_tm_height_,
        prev_elect_height_,
        msg);
    if (msg.has_data()) {
        network::Route::Instance()->Send(msg);
#ifdef TENON_UNITTEST
        second_msg_ = msg;
#endif
    }
}

void VssManager::BroadcastFirstPeriodSplitRandom() {
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }

    uint64_t random_nums[kVssRandomSplitCount] = { 0 };
    local_random_.GetRandomNum(random_nums);
    auto mem_count = elect::ElectManager::Instance()->GetMemberCount(
        prev_elect_height_,
        network::kRootCongressNetworkId);
    if (mem_count < common::kEachShardMinNodeCount) {
        return;
    }

    auto split_mem_count = mem_count / 3;
    if (split_mem_count < 1) {
        return;
    }

    std::vector<std::string> all_root_nodes;
    elect::ElectManager::Instance()->GetAllNodes(
        prev_elect_height_,
        network::kRootCongressNetworkId,
        &all_root_nodes);
    if (all_root_nodes.empty()) {
        return;
    }

    int32_t src_begin_idx = (prev_epoch_final_random_ ^
        common::Hash::Hash64(common::GlobalInfo::Instance()->id())) %
        all_root_nodes.size();
    for (uint32_t i = 0; i < kVssRandomSplitCount; ++i) {
        int32_t begin_idx = src_begin_idx + i;
        for (int32_t node_idx = begin_idx;
                node_idx < (int32_t)all_root_nodes.size(); node_idx += kVssRandomSplitCount) {
            if (node_idx == local_index_) {
                continue;
            }

            transport::protobuf::Header msg;
            std::cout << "node_idx: " << node_idx << ", ";
            VssProto::CreateFirstSplitRandomMessage(
                dht->local_node(),
                i,
                random_nums[i],
                prev_tm_height_,
                prev_elect_height_,
                all_root_nodes[node_idx],
                msg);
            if (msg.has_data()) {
                network::Route::Instance()->Send(msg);
#ifdef TENON_UNITTEST
                first_split_msgs_.push_back(msg);
#endif
            }
        }

        if (begin_idx >= kVssRandomSplitCount) {
            for (int32_t node_idx = begin_idx - kVssRandomSplitCount;
                    node_idx >= 0; node_idx -= kVssRandomSplitCount) {
                if (node_idx == local_index_) {
                    continue;
                }

                transport::protobuf::Header msg;
                std::cout << "node_idx: " << node_idx << ", ";
                VssProto::CreateFirstSplitRandomMessage(
                    dht->local_node(),
                    i,
                    random_nums[i],
                    prev_tm_height_,
                    prev_elect_height_,
                    all_root_nodes[node_idx],
                    msg);
                if (msg.has_data()) {
                    network::Route::Instance()->Send(msg);
#ifdef TENON_UNITTEST
                    first_split_msgs_.push_back(msg);
#endif
                }
            }
        }
    }
}

void VssManager::BroadcastThirdPeriodSplitRandom() {
    protobuf::VssMessage vss_msg;
    for (uint32_t i = 0; i < member_count_; ++i) {
        if (i == local_index_) {
            continue;
        }

        if (other_randoms_[i].IsRandomValid()) {
            continue;
        }

        other_randoms_[i].GetFirstSplitRandomNum(vss_msg);
    }

    if (vss_msg.all_split_random_size() <= 0) {
        return;
    }

    transport::protobuf::Header msg;
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }

    VssProto::CreateThirdSplitRandomMessage(
        dht->local_node(),
        vss_msg,
        prev_tm_height_,
        prev_elect_height_,
        msg);
    if (msg.has_data()) {
        network::Route::Instance()->Send(msg);
#ifdef TENON_UNITTEST
        third_msg_ = msg;
#endif
    }
}

void VssManager::HandleMessage(transport::protobuf::Header& header) {
    assert(header.type() == common::kVssMessage);
    if (local_index_ == elect::kInvalidMemberIndex) {
        return;
    }

    // must verify message signature, to avoid evil node
    protobuf::VssMessage vss_msg;
    if (!vss_msg.ParseFromString(header.data())) {
        ELECT_ERROR("protobuf::ElectMessage ParseFromString failed!");
        return;
    }

    if (!security::IsValidPublicKey(vss_msg.pubkey())) {
        ELECT_ERROR("invalid public key: %s!", common::Encode::HexEncode(vss_msg.pubkey()));
        return;
    }

    if (!security::IsValidSignature(vss_msg.sign_ch(), vss_msg.sign_res())) {
        ELECT_ERROR("invalid sign: %s, %s!",
            common::Encode::HexEncode(vss_msg.sign_ch()),
            common::Encode::HexEncode(vss_msg.sign_res()));
        return;
    }

    switch (vss_msg.type()) {
    case kVssRandomHash:
        HandleFirstPeriodHash(vss_msg);
        break;
    case kVssRandom:
        HandleSecondPeriodRandom(vss_msg);
        break;
    case kVssFirstRandomSplit:
        HandleFirstPeriodSplitRandom(vss_msg);
        break;
    case kVssThirdRandomSplit:
        HandleThirdPeriodSplitRandom(vss_msg);
        break;
    default:
        break;
    }
}

void VssManager::HandleFirstPeriodHash( const protobuf::VssMessage& vss_msg) {
    auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(vss_msg.pubkey());
    auto mem_index = elect::ElectManager::Instance()->GetMemberIndex(
        vss_msg.elect_height(),
        network::kRootCongressNetworkId,
        id);
    if (mem_index == elect::kInvalidMemberIndex) {
        VSS_ERROR("mem_index == elect::kInvalidMemberIndex");
        return;
    }

    std::string hash_str = std::to_string(vss_msg.random_hash()) + "_" +
        std::to_string(vss_msg.tm_height()) + "_" +
        std::to_string(vss_msg.elect_height()) + "_" +
        id;
    auto message_hash = common::Hash::keccak256(hash_str);
    auto pubkey = security::PublicKey(vss_msg.pubkey());
    auto sign = security::Signature(vss_msg.sign_ch(), vss_msg.sign_res());
    if (!security::Schnorr::Instance()->Verify(message_hash, sign, pubkey)) {
        VSS_ERROR("security::Schnorr::Instance()->Verify failed");
        return;
    }

    other_randoms_[mem_index].SetHash(id, vss_msg.random_hash());
}

void VssManager::HandleFirstPeriodSplitRandom(const protobuf::VssMessage& vss_msg) {
    auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(vss_msg.pubkey());
    auto mem_index = elect::ElectManager::Instance()->GetMemberIndex(
        vss_msg.elect_height(),
        network::kRootCongressNetworkId,
        id);
    if (mem_index == elect::kInvalidMemberIndex) {
        VSS_ERROR("mem_index == elect::kInvalidMemberIndex");
        return;
    }

    std::string hash_str = std::to_string(vss_msg.split_index()) + "_" +
        std::to_string(vss_msg.split_random()) + "_" +
        std::to_string(vss_msg.tm_height()) + "_" +
        std::to_string(vss_msg.elect_height()) + "_" +
        id;
    auto message_hash = common::Hash::keccak256(hash_str);
    auto pubkey = security::PublicKey(vss_msg.pubkey());
    auto sign = security::Signature(vss_msg.sign_ch(), vss_msg.sign_res());
    if (!security::Schnorr::Instance()->Verify(message_hash, sign, pubkey)) {
        VSS_ERROR("security::Schnorr::Instance()->Verify failed");
        return;
    }

    std::string dec_data = security::Crypto::Instance()->GetDecryptData(
        vss_msg.pubkey(),
        vss_msg.crypt_data());
    std::cout << "src message: " << common::Encode::HexEncode(message_hash)
        << ", crypt message: " << common::Encode::HexEncode(vss_msg.crypt_data())
        << ", dec message: " << common::Encode::HexEncode(dec_data)
        << std::endl;
    if (memcmp(message_hash.c_str(), dec_data.c_str(), message_hash.size()) != 0) {
        VSS_ERROR("message_hash decrypt error failed[%s: %s]",
            common::Encode::HexEncode(message_hash).c_str(),
            common::Encode::HexEncode(dec_data).c_str());
        return;
    }

    other_randoms_[mem_index].SetFirstSplitRandomNum(
        vss_msg.tm_height(),
        vss_msg.split_index(),
        vss_msg.split_random());
}

void VssManager::HandleSecondPeriodRandom(const protobuf::VssMessage& vss_msg) {
    auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(vss_msg.pubkey());
    auto mem_index = elect::ElectManager::Instance()->GetMemberIndex(
        vss_msg.elect_height(),
        network::kRootCongressNetworkId,
        id);
    if (mem_index == elect::kInvalidMemberIndex) {
        return;
    }

    std::string hash_str = std::to_string(vss_msg.random()) + "_" +
        std::to_string(vss_msg.tm_height()) + "_" +
        std::to_string(vss_msg.elect_height()) + "_" +
        id;
    auto message_hash = common::Hash::keccak256(hash_str);
    auto pubkey = security::PublicKey(vss_msg.pubkey());
    auto sign = security::Signature(vss_msg.sign_ch(), vss_msg.sign_res());
    if (!security::Schnorr::Instance()->Verify(message_hash, sign, pubkey)) {
        return;
    }

    other_randoms_[mem_index].SetFinalRandomNum(id, vss_msg.random());
}

void VssManager::HandleThirdPeriodSplitRandom(const protobuf::VssMessage& vss_msg) {
    auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(vss_msg.pubkey());
    int32_t mem_index = elect::ElectManager::Instance()->GetMemberIndex(
        vss_msg.elect_height(),
        network::kRootCongressNetworkId,
        id);
    if (mem_index == (int32_t)elect::kInvalidMemberIndex) {
        return;  
    }

    std::string hash_str = std::to_string(vss_msg.tm_height()) + "_" +
        std::to_string(vss_msg.elect_height()) + "_";
    for (int32_t i = 0; i < vss_msg.all_split_random_size(); ++i) {
        hash_str += vss_msg.all_split_random(i).id() + "_" +
            std::to_string(vss_msg.all_split_random(i).split_index()) + "_" +
            std::to_string(vss_msg.all_split_random(i).split_random()) + "_";
    }

    auto message_hash = common::Hash::keccak256(hash_str);
    auto pubkey = security::PublicKey(vss_msg.pubkey());
    auto sign = security::Signature(vss_msg.sign_ch(), vss_msg.sign_res());
    if (!security::Schnorr::Instance()->Verify(message_hash, sign, pubkey)) {
        return;
    }

    for (int32_t i = 0; i < vss_msg.all_split_random_size(); ++i) {
        int32_t valid_member_begin_idx = (prev_epoch_final_random_ ^
            common::Hash::Hash64(vss_msg.all_split_random(i).id())) % member_count_ +
            vss_msg.all_split_random(i).split_index();
        // must valid reserve split random number node
        if (abs(mem_index - valid_member_begin_idx) % kVssRandomSplitCount == 0) {
            int32_t des_member_idx = elect::ElectManager::Instance()->GetMemberIndex(
                vss_msg.elect_height(),
                network::kRootCongressNetworkId,
                vss_msg.all_split_random(i).id());
            other_randoms_[des_member_idx].SetThirdSplitRandomNum(
                vss_msg.tm_height(),
                id,
                vss_msg.all_split_random(i).split_index(),
                vss_msg.all_split_random(i).split_random());
        }
    }
}

}  // namespace vss

}  // namespace tenon
