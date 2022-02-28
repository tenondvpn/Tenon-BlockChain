#include "stdafx.h"
#include "vss/vss_manager.h"

#include "common/time_utils.h"
#include "election/elect_utils.h"
#include "election/elect_manager.h"
#include "network/route.h"
#include "security/secp256k1.h"
#include "security/aes.h"
#include "security/crypto.h"
#include "timeblock/time_block_manager.h"
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
    if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId &&
            common::GlobalInfo::Instance()->network_id() !=
            (network::kRootCongressNetworkId + network::kConsensusWaitingShardOffset)) {
        return;
    }

    VSS_DEBUG("OnTimeBlock comming tm_block_tm: %lu, tm_height: %lu, elect_height: %lu, epoch_random: %lu",
        tm_block_tm, tm_height, elect_height, epoch_random);
    {
        std::lock_guard<std::mutex> guard(final_consensus_nodes_mutex_);
        if ((max_count_ * 3 / 2 + 1) < member_count_ || max_count_random_ == 0) {
            BLS_ERROR("use old random: %lu, max_count_: %d, expect: %d, member_count_: %d, max_count_random_: %lu", epoch_random_, max_count_, (max_count_ * 3 / 2 + 1), member_count_, max_count_random_);
            prev_valid_vss_ = epoch_random_;
        } else {
            prev_valid_vss_ = max_count_random_;
        }
    }

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

            if (elect::ElectManager::Instance()->local_node_member_index() == elect::kInvalidMemberIndex &&
                    elect::ElectManager::Instance()->local_waiting_node_member_index() == elect::kInvalidMemberIndex) {
                VSS_ERROR("not elected.");
                return;
            }

            local_random_.OnTimeBlock(tm_block_tm);
        }

        prev_tm_height_ = tm_height;
        int64_t local_offset_us = 0;
        auto tmblock_tm = tmblock::TimeBlockManager::Instance()->LatestTimestamp() * 1000l * 1000l;
        begin_time_us_ = common::TimeUtils::TimestampUs();
        kDkgPeriodUs = common::kTimeBlockCreatePeriodSeconds / 10 * 1000u * 1000u;
        auto first_offset = kDkgPeriodUs;
        auto second_offset = kDkgPeriodUs * 4;
        auto third_offset = kDkgPeriodUs * 8;
        auto offset_tm = 30l * 1000l * 1000l;
        if (begin_time_us_ < tmblock_tm + offset_tm) {
            kDkgPeriodUs = (common::kTimeBlockCreatePeriodSeconds - 20) * 1000l * 1000l / 10l;
            first_offset = tmblock_tm + offset_tm - begin_time_us_;
            begin_time_us_ = tmblock_tm + offset_tm - kDkgPeriodUs;
            second_offset = first_offset + kDkgPeriodUs * 3;
            third_offset = first_offset + kDkgPeriodUs * 7;
        }

        // waiting elect block coming.
        vss_first_tick_.CutOff(
            first_offset + std::rand() % 10,
            std::bind(&VssManager::BroadcastFirstPeriodHash, this));
        vss_second_tick_.CutOff(
            second_offset + std::rand() % 10,
            std::bind(&VssManager::BroadcastSecondPeriodRandom, this));
        vss_third_tick_.CutOff(
            third_offset + std::rand() % 10,
            std::bind(&VssManager::BroadcastThirdPeriodRandom, this));
        VSS_DEBUG("tmblock_tm: %lu, begin_time_us_: %lu, first_offset: %lu, second_offset: %lu, third_offset: %lu, kDkgPeriodUs: %lu",
            tmblock_tm, begin_time_us_, first_offset, second_offset, third_offset, kDkgPeriodUs);
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
    return prev_valid_vss_;
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

uint64_t VssManager::GetAllVssValid() {
    uint64_t final_random = 0;
    for (uint32_t i = 0; i < member_count_; ++i) {
        if (other_randoms_[i].IsRandomValid()) {
            final_random ^= other_randoms_[i].GetFinalRandomNum();
        }
    }

    return final_random;
}

bool VssManager::IsVssFirstPeriodsHandleMessage() {
#ifdef TENON_UNITTEST
    return true;
#endif
    auto now_tm_us = common::TimeUtils::TimestampUs();
    if (now_tm_us < (begin_time_us_ + kDkgPeriodUs * 4)) {
        return true;
    }

    VSS_DEBUG("IsVssFirstPeriodsHandleMessage now_tm_us: %lu, (begin_time_us_ + kDkgPeriodUs * 4): %lu",
        now_tm_us, (begin_time_us_ + kDkgPeriodUs * 4));
    return false;
}

bool VssManager::IsVssSecondPeriodsHandleMessage() {
#ifdef TENON_UNITTEST
    return true;
#endif
    auto now_tm_us = common::TimeUtils::TimestampUs();
    if (now_tm_us < (begin_time_us_ + kDkgPeriodUs * 8) &&
            now_tm_us >= (begin_time_us_ + kDkgPeriodUs * 4)) {
        return true;
    }

    VSS_DEBUG("IsVssSecondPeriodsHandleMessage now_tm_us: %lu, (begin_time_us_ + kDkgPeriodUs * 8): %lu, (begin_time_us_ + kDkgPeriodUs * 4): %lu",
        now_tm_us, (begin_time_us_ + kDkgPeriodUs * 8), (begin_time_us_ + kDkgPeriodUs * 4));
    return false;
}

bool VssManager::IsVssThirdPeriodsHandleMessage() {
#ifdef TENON_UNITTEST
    return true;
#endif
    auto now_tm_us = common::TimeUtils::TimestampUs();
    if (now_tm_us >= (begin_time_us_ + kDkgPeriodUs * 8)) {
        return true;
    }

    VSS_DEBUG("IsVssThirdPeriodsHandleMessage now_tm_us: %lu, (begin_time_us_ + kDkgPeriodUs * 8): %lu",
        now_tm_us, (begin_time_us_ + kDkgPeriodUs * 8));
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
        VSS_DEBUG("BroadcastFirstPeriodHash: %lu，prev_elect_height_: %lu", local_random_.GetHash(), prev_elect_height_);
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
        dht::DhtKeyManager dht_key(network::kRootCongressNetworkId, 0);
        msg.set_des_dht_key(dht_key.StrKey());
        network::Route::Instance()->Send(msg);
        network::Route::Instance()->SendToLocal(msg);
        VSS_DEBUG("BroadcastSecondPeriodRandom: %lu，prev_elect_height_: %lu", local_random_.GetFinalRandomNum(), prev_elect_height_);
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
        dht::DhtKeyManager dht_key(network::kRootCongressNetworkId, 0);
        msg.set_des_dht_key(dht_key.StrKey());
        network::Route::Instance()->Send(msg);
        network::Route::Instance()->SendToLocal(msg);
        dht::DhtKeyManager wait_dht_key(network::kNodeNetworkId, 0);
        msg.set_des_dht_key(wait_dht_key.StrKey());
        auto broad_param = msg.mutable_broadcast();
        transport::SetDefaultBroadcastParam(broad_param);
        msg.clear_hash();
        msg.set_handled(false);
        msg.set_universal(true);
        network::Route::Instance()->Send(msg);
        VSS_DEBUG("BroadcastThirdPeriodRandom: %lu，prev_elect_height_: %lu", GetAllVssValid(), prev_elect_height_);
#ifdef TENON_UNITTEST
        third_msg_ = msg;
#endif
    }
}

void VssManager::HandleMessage(const transport::TransportMessagePtr& header_ptr) {
    auto& header = *header_ptr;
    assert(header.type() == common::kVssMessage);
    if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId &&
            common::GlobalInfo::Instance()->network_id() !=
            (network::kRootCongressNetworkId + network::kConsensusWaitingShardOffset)) {
        //VSS_DEBUG("invalid vss message network_id: %d", common::GlobalInfo::Instance()->network_id());
        return;
    }

    if (elect::ElectManager::Instance()->local_node_member_index() == elect::kInvalidMemberIndex &&
            elect::ElectManager::Instance()->local_waiting_node_member_index() == elect::kInvalidMemberIndex) {
        VSS_ERROR("not elected.");
        return;
    }

    // must verify message signature, to avoid evil node
    protobuf::VssMessage vss_msg;
    if (!vss_msg.ParseFromString(header.data())) {
        ELECT_ERROR("protobuf::ElectMessage ParseFromString failed!");
        return;
    }

//     if (vss_msg.type() != kVssFinalRandom/* && local_index_ == elect::kInvalidMemberIndex*/) {
//         VSS_DEBUG("invalid vss message: %d, %d", vss_msg.type());
//         return;
//     }

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
        VSS_DEBUG("invalid first period message.");
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
    if (!security::Security::Instance()->Verify(message_hash, sign, pubkey)) {
        VSS_ERROR("security::Security::Instance()->Verify failed");
        return;
    }

    other_randoms_[mem_index].SetHash(id, vss_msg.random_hash());
    VSS_DEBUG("HandleFirstPeriodHash: %s, %llu",
        common::Encode::HexEncode(id).c_str(), vss_msg.random_hash());
}

void VssManager::HandleSecondPeriodRandom(const protobuf::VssMessage& vss_msg) {
    if (!IsVssSecondPeriodsHandleMessage()) {
        VSS_DEBUG("invalid second period message.");
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
    if (!security::Security::Instance()->Verify(message_hash, sign, pubkey)) {
        VSS_ERROR("security::Security::Instance()->Verify failed!");
        return;
    }

    other_randoms_[mem_index].SetFinalRandomNum(id, vss_msg.random());
    VSS_DEBUG("HandleSecondPeriodRandom: %s, %llu",
        common::Encode::HexEncode(id).c_str(), vss_msg.random());
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

    VSS_DEBUG("HandleThirdPeriodRandom: %s, %llu, max_count_: %d, count_iter->second: %d",
        common::Encode::HexEncode(id).c_str(), final_random_num, max_count_, count_iter->second);
}

void VssManager::HandleThirdPeriodRandom(const protobuf::VssMessage& vss_msg) {
    auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(vss_msg.pubkey());
    auto mem_index = elect::ElectManager::Instance()->GetMemberIndex(
        network::kRootCongressNetworkId,
        id);
    if (!IsVssThirdPeriodsHandleMessage()) {
        VSS_ERROR("not IsVssThirdPeriodsHandleMessage, id: %s, pk: %s",
            common::Encode::HexEncode(id).c_str(),
            common::Encode::HexEncode(vss_msg.pubkey()).c_str());
        return;
    }

//     if (mem_index == elect::kInvalidMemberIndex) {
//         VSS_ERROR("mem_index == elect::kInvalidMemberIndex, id: %s, pk: %s",
//             common::Encode::HexEncode(id).c_str(),
//             common::Encode::HexEncode(vss_msg.pubkey()).c_str());
//         return;
//     }

    std::string hash_str = std::to_string(vss_msg.random()) + "_" +
        std::to_string(vss_msg.tm_height()) + "_" +
        std::to_string(vss_msg.elect_height()) + "_" +
        id;
    auto message_hash = common::Hash::keccak256(hash_str);
    auto pubkey = security::PublicKey(vss_msg.pubkey());
    auto sign = security::Signature(vss_msg.sign_ch(), vss_msg.sign_res());
    if (!security::Security::Instance()->Verify(message_hash, sign, pubkey)) {
        VSS_ERROR("security::Security::Instance()->Verify error.");
        return;
    }

    SetConsensusFinalRandomNum(id, vss_msg.random());
}

}  // namespace vss

}  // namespace tenon
