#include "stdafx.h"
#include "vss/vss_manager.h"

#include "common/time_utils.h"
#include "election/elect_utils.h"
#include "election/elect_manager.h"
#include "network/route.h"
#include "security/secp256k1.h"
#include "vss/proto/vss_proto.h"

namespace tenon {

namespace vss {

VssManager* VssManager::Instance() {
    static VssManager ins;
    return &ins;
}

uint64_t VssManager::EpochRandom() {
    return 0llu;
}

void VssManager::OnTimeBlock(
        uint64_t tm_block_tm,
        uint64_t tm_height,
        uint64_t elect_height) {
    auto root_members = elect::ElectManager::Instance()->GetNetworkMembers(
        elect_height,
        network::kRootCongressNetworkId);
    if (root_members == nullptr || root_members->empty()) {
        return;
    }

    std::lock_guard<std::mutex> guard(mutex_);
    if (prev_tm_height_ >= tm_height) {
        return;
    }

    ClearAll();
    local_random_.OnTimeBlock(tm_block_tm);
    latest_tm_block_tm_ = tm_block_tm;
    prev_tm_height_ = tm_height;
    prev_elect_height_ = elect_height;
}

void VssManager::ClearAll() {
    local_random_.ResetStatus();
    for (uint32_t i = 0; i < common::kEachShardMaxNodeCount; ++i) {
        other_randoms_[i].ResetStatus();
    }
}

void VssManager::CheckVssPeriods() {
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        // Joined root and continue
    }

    vss_tick_.CutOff(1000000ll, std::bind(&VssManager::CheckVssPeriods, this));
}

void VssManager::CheckVssFirstPeriods() {

}

void VssManager::CheckVssSecondPeriods() {

}

void VssManager::CheckVssThirdPeriods() {

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
    }
}

void VssManager::BroadcastThirdPeriodSplitRandom() {
    transport::protobuf::Header msg;
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }

    uint64_t random_nums[kVssRandomSplitCount] = { 0 };
    local_random_.GetRandomNum(random_nums);
    for (uint32_t i = 0; i < kVssRandomSplitCount; ++i) {
        VssProto::CreateSplitRandomMessage(
            dht->local_node(),
            i,
            random_nums[i],
            prev_tm_height_,
            prev_elect_height_,
            msg);
        if (msg.has_data()) {
            network::Route::Instance()->Send(msg);
        }
    }
}

void VssManager::HandleMessage(transport::protobuf::Header& header) {
    assert(header.type() == common::kVssMessage);
    // TODO: verify message signature
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
    case kVssRandomSplit:
        HandleThirdPeriodSplitRandom(vss_msg);
        break;
    default:
        break;
    }
}

void VssManager::HandleFirstPeriodHash(const protobuf::VssMessage& vss_msg) {
    auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(vss_msg.pubkey());
    auto mem_index = elect::ElectManager::Instance()->GetMemberIndex(
        vss_msg.elect_height(),
        network::kRootCongressNetworkId,
        id);
    if (mem_index == elect::kInvalidMemberIndex) {
        return;
    }

    other_randoms_[mem_index].SetHash(vss_msg.random_hash());
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

    other_randoms_[mem_index].SetFinalRandomNum(vss_msg.random());
}

void VssManager::HandleThirdPeriodSplitRandom(const protobuf::VssMessage& vss_msg) {
    auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(vss_msg.pubkey());
    auto mem_index = elect::ElectManager::Instance()->GetMemberIndex(
        vss_msg.elect_height(),
        network::kRootCongressNetworkId,
        id);
    if (mem_index == elect::kInvalidMemberIndex) {
        return;  
    }

    // Check id is valid period member
    // 
    other_randoms_[mem_index].SetFinalRandomNum(vss_msg.random());
}

}  // namespace vss

}  // namespace tenon
