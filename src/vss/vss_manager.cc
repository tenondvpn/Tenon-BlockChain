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

VssManager::VssManager() {
    network::Route::Instance()->RegisterMessage(
        common::kVssMessage,
        std::bind(&VssManager::HandleMessage, this, std::placeholders::_1));
}

uint64_t VssManager::EpochRandom() {
    return epoch_random_;
}

void VssManager::OnTimeBlock(
        uint64_t tm_block_tm,
        uint64_t tm_height,
        uint64_t elect_height,
        uint64_t epoch_random) {
    {
        std::lock_guard<std::mutex> guard(mutex_);
        ClearAll();
        epoch_random_ = epoch_random;
        latest_tm_block_tm_ = tm_block_tm;
        prev_elect_height_ = elect_height;
        if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
            if (prev_tm_height_ != common::kInvalidUint64 && prev_tm_height_ >= tm_height) {
                VSS_ERROR("prev_tm_height_ >= tm_height[%lu][%lu].", prev_tm_height_, tm_height);
                return;
            }

            local_index_ = elect::ElectManager::Instance()->local_node_member_index();
            if (local_index_ == elect::kInvalidMemberIndex) {
                VSS_ERROR("local_index_ == elect::kInvalidMemberIndex.");
                return;
            }

            local_random_.OnTimeBlock(tm_block_tm);
        }

        prev_tm_height_ = tm_height;
        int64_t local_offset_us = 0;
        if (member_count_ > 0 && local_index_ < member_count_) {
            // waiting elect block coming.
            auto each_member_offset_us = kVssWorkPeriodUs / member_count_;
            local_offset_us = each_member_offset_us * local_index_;
            vss_first_tick_.CutOff(
                kVssFirstBeginUs + local_offset_us,
                std::bind(&VssManager::BroadcastFirstPeriodHash, this));
            vss_second_tick_.CutOff(
                kVssSecondBeginUs + local_offset_us,
                std::bind(&VssManager::BroadcastSecondPeriodRandom, this));
            vss_third_tick_.CutOff(
                kVssFinishBeginUs + local_offset_us,
                std::bind(&VssManager::BroadcastThirdPeriodRandom, this));
        }

        VSS_DEBUG("new time block latest_tm_block_tm_: %lu, prev_tm_height_: %lu,"
            "prev_elect_height_: %lu, member_count_: %u, epoch_random_: %lu, "
            "first begin us: %ld, second begin us: %ld, third begin us: %ld",
            (uint64_t)latest_tm_block_tm_, (uint64_t)prev_tm_height_,
            (uint64_t)prev_elect_height_, member_count_, (uint64_t)epoch_random_,
            kVssFirstBeginUs + local_offset_us,
            kVssSecondBeginUs + local_offset_us,
            kVssFinishBeginUs + local_offset_us);
        printf("new time block latest_tm_block_tm_: %lu, prev_tm_height_: %lu,"
            "prev_elect_height_: %lu, member_count_: %u, epoch_random_: %lu, "
            "first begin us: %ld, second begin us: %ld, third begin us: %ld.\n",
            (uint64_t)latest_tm_block_tm_, (uint64_t)prev_tm_height_,
            (uint64_t)prev_elect_height_, member_count_, (uint64_t)epoch_random_,
            kVssFirstBeginUs + local_offset_us,
            kVssSecondBeginUs + local_offset_us,
            kVssFinishBeginUs + local_offset_us);
    }
}

void VssManager::OnElectBlock(uint32_t network_id, uint64_t elect_height) {
    if (network_id == network::kRootCongressNetworkId &&
            common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        std::lock_guard<std::mutex> guard(mutex_);
        local_index_ = elect::ElectManager::Instance()->local_node_member_index();
        prev_elect_height_ = elect_height;
        member_count_ = elect::ElectManager::Instance()->GetMemberCount(
            network::kRootCongressNetworkId);
    }
}

uint64_t VssManager::GetConsensusFinalRandom() {
    std::lock_guard<std::mutex> guard(final_consensus_nodes_mutex_);
    if ((max_count_ * 3 / 2 + 1) < member_count_ || max_count_random_ == 0) {
        return epoch_random_;
    }

    return max_count_random_;
}

void VssManager::ClearAll() {
    local_random_.ResetStatus();
    for (uint32_t i = 0; i < common::kEachShardMaxNodeCount; ++i) {
        other_randoms_[i].ResetStatus();
    }

    first_period_cheched_ = false;
    second_period_cheched_ = false;
    third_period_cheched_ = false;
    std::lock_guard<std::mutex> guard(final_consensus_nodes_mutex_);
    final_consensus_nodes_.clear();
    final_consensus_random_count_.clear();
    max_count_ = 0;
    max_count_random_ = 0;
    vss_first_tick_.Destroy();
    vss_second_tick_.Destroy();
    vss_third_tick_.Destroy();
}

void VssManager::CheckVssFirstPeriods() {
    if (first_period_cheched_) {
        return;
    }

    if (IsVssFirstPeriods()) {
        BroadcastFirstPeriodHash();
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
        BroadcastThirdPeriodRandom();
        third_period_cheched_ = true;
    }
}

uint64_t VssManager::GetAllVssValid() {
    uint64_t final_random = 0;
    for (uint32_t i = 0; i < member_count_; ++i) {
        if (other_randoms_[i].IsRandomValid()) {
            final_random ^= other_randoms_[i].GetFinalRandomNum();
        }
    }

    return final_random;
}

bool VssManager::IsVssFirstPeriods() {
#ifdef TENON_UNITTEST
    return true;
#endif
    auto now_seconds = common::TimeUtils::TimestampSeconds();
    if (latest_tm_block_tm_ + kVssTimePeriodOffsetSeconds <= now_seconds &&
            latest_tm_block_tm_ + kVssFirstPeriodTimeout - kVssTimePeriodOffsetSeconds >
            now_seconds) {
        return true;
    }

    return false;
}

bool VssManager::IsVssSecondPeriods() {
#ifdef TENON_UNITTEST
    return true;
#endif
    auto now_seconds = common::TimeUtils::TimestampSeconds();
    if (latest_tm_block_tm_ + kVssFirstPeriodTimeout <= now_seconds &&
            latest_tm_block_tm_ + kVssSecondPeriodTimeout - kVssTimePeriodOffsetSeconds >
            now_seconds) {
        return true;
    }

    return false;
}

bool VssManager::IsVssThirdPeriods() {
#ifdef TENON_UNITTEST
    return true;
#endif
    auto now_seconds = common::TimeUtils::TimestampSeconds();
    if (latest_tm_block_tm_ + kVssSecondPeriodTimeout <= now_seconds &&
        latest_tm_block_tm_ + kVssThirdPeriodTimeout > now_seconds) {
        return true;
    }

    return false;
}

bool VssManager::IsVssFirstPeriodsHandleMessage() {
#ifdef TENON_UNITTEST
    return true;
#endif
    auto now_seconds = common::TimeUtils::TimestampSeconds();
    if (latest_tm_block_tm_ + kHandleMessageVssTimePeriodOffsetSeconds <= now_seconds &&
        latest_tm_block_tm_ + kVssFirstPeriodTimeout - kHandleMessageVssTimePeriodOffsetSeconds > now_seconds) {
        return true;
    }

    return false;
}

bool VssManager::IsVssSecondPeriodsHandleMessage() {
#ifdef TENON_UNITTEST
    return true;
#endif
    auto now_seconds = common::TimeUtils::TimestampSeconds();
    if (latest_tm_block_tm_ + kVssFirstPeriodTimeout - kHandleMessageVssTimePeriodOffsetSeconds <= now_seconds &&
        latest_tm_block_tm_ + kVssSecondPeriodTimeout > now_seconds) {
        return true;
    }

    return false;
}

bool VssManager::IsVssThirdPeriodsHandleMessage() {
#ifdef TENON_UNITTEST
    return true;
#endif
    auto now_seconds = common::TimeUtils::TimestampSeconds();
    if (latest_tm_block_tm_ + kVssSecondPeriodTimeout - kHandleMessageVssTimePeriodOffsetSeconds <= now_seconds &&
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
        network::Route::Instance()->SendToLocal(msg);
//         VSS_DEBUG("BroadcastFirstPeriodHash: %lu", local_random_.GetHash());
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
        kVssRandom,
        local_random_.GetFinalRandomNum(),
        prev_tm_height_,
        prev_elect_height_,
        msg);
    if (msg.has_data()) {
        network::Route::Instance()->Send(msg);
        network::Route::Instance()->SendToLocal(msg);
//         VSS_DEBUG("BroadcastSecondPeriodRandom: %lu", local_random_.GetFinalRandomNum());
#ifdef TENON_UNITTEST
        second_msg_ = msg;
#endif
    }
}

void VssManager::BroadcastThirdPeriodRandom() {
    transport::protobuf::Header msg;
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }

    VssProto::CreateRandomMessage(
        dht->local_node(),
        kVssFinalRandom,
        GetAllVssValid(),
        prev_tm_height_,
        prev_elect_height_,
        msg);
    if (msg.has_data()) {
        network::Route::Instance()->Send(msg);
        network::Route::Instance()->SendToLocal(msg);
//         VSS_DEBUG("BroadcastThirdPeriodRandom: %lu", GetAllVssValid());
#ifdef TENON_UNITTEST
        third_msg_ = msg;
#endif
    }
}

void VssManager::HandleMessage(const transport::TransportMessagePtr& header_ptr) {
    auto& header = *header_ptr;
    assert(header.type() == common::kVssMessage);
    if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId) {
        return;
    }

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
    case kVssFinalRandom:
        HandleThirdPeriodRandom(vss_msg);
        break;
    default:
        break;
    }
}

void VssManager::HandleFirstPeriodHash(const protobuf::VssMessage& vss_msg) {
    if (!IsVssFirstPeriodsHandleMessage()) {
        return;
    }

    auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(vss_msg.pubkey());
    auto mem_index = elect::ElectManager::Instance()->GetMemberIndex(
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
//     VSS_DEBUG("HandleFirstPeriodHash: %s, %llu",
//         common::Encode::HexEncode(id).c_str(), vss_msg.random_hash());
}

void VssManager::HandleSecondPeriodRandom(const protobuf::VssMessage& vss_msg) {
    if (!IsVssSecondPeriodsHandleMessage()) {
        return;
    }

    auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(vss_msg.pubkey());
    auto mem_index = elect::ElectManager::Instance()->GetMemberIndex(
        network::kRootCongressNetworkId,
        id);
    if (mem_index == elect::kInvalidMemberIndex) {
        VSS_ERROR("mem_index == elect::kInvalidMemberIndex");
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
        VSS_ERROR("security::Schnorr::Instance()->Verify failed!");
        return;
    }

    other_randoms_[mem_index].SetFinalRandomNum(id, vss_msg.random());
//     VSS_DEBUG("HandleSecondPeriodRandom: %s, %llu",
//         common::Encode::HexEncode(id).c_str(), vss_msg.random());
}

void VssManager::SetConsensusFinalRandomNum(const std::string& id, uint64_t final_random_num) {
    std::lock_guard<std::mutex> guard(final_consensus_nodes_mutex_);
    // random hash must coming
    auto iter = final_consensus_nodes_.find(id);
    if (iter != final_consensus_nodes_.end()) {
        return;
    }

    final_consensus_nodes_.insert(id);
    auto count_iter = final_consensus_random_count_.find(final_random_num);
    if (count_iter == final_consensus_random_count_.end()) {
        final_consensus_random_count_[final_random_num] = 1;
        return;
    }

    ++count_iter->second;
    if (max_count_ < count_iter->second) {
        max_count_ = count_iter->second;
        max_count_random_ = final_random_num;
    }
}

void VssManager::HandleThirdPeriodRandom(const protobuf::VssMessage& vss_msg) {
    if (!IsVssThirdPeriodsHandleMessage()) {
        return;
    }

    auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(vss_msg.pubkey());
    auto mem_index = elect::ElectManager::Instance()->GetMemberIndex(
        network::kRootCongressNetworkId,
        id);
    if (mem_index == elect::kInvalidMemberIndex) {
        VSS_ERROR("mem_index == elect::kInvalidMemberIndex");
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
        VSS_ERROR("security::Schnorr::Instance()->Verify error.");
        return;
    }

    SetConsensusFinalRandomNum(id, vss_msg.random());
//     VSS_DEBUG("HandleThirdPeriodRandom: %s, %llu",
//         common::Encode::HexEncode(id).c_str(), vss_msg.random());
}

}  // namespace vss

}  // namespace tenon
