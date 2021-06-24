#include "stdafx.h"
#include "vss/vss_manager.h"

#include "common/time_utils.h"
#include "election/elect_utils.h"
#include "election/elect_manager.h"
#include "vss/proto/vss.pb.h"

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
}

void VssManager::ClearAll() {
    local_random_.ResetStatus();
    for (uint32_t i = 0; i < common::kEachShardMaxNodeCount; ++i) {
        other_randoms_[i].ResetStatus();
    }
}

void VssManager::CheckVssPeriods() {

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

}

void VssManager::BroadcastSecondPeriodRandom() {

}

void VssManager::BroadcastThirdPeriodSplitRandom() {

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
}

}  // namespace vss

}  // namespace tenon
