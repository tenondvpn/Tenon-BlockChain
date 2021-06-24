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

void VssManager::BroadcastFirstPeriodSplitRandom() {
    transport::protobuf::Header msg;
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

    uint32_t begin_idx = prev_epoch_final_random_ % all_root_nodes.size();
    for (uint32_t i = 0; i < kVssRandomSplitCount; ++i) {
        begin_idx += i;
        for (int32_t node_idx = begin_idx;
                node_idx < (int32_t)all_root_nodes.size(); node_idx += kVssRandomSplitCount) {
            VssProto::CreateFirstSplitRandomMessage(
                dht->local_node(),
                node_idx,
                random_nums[i],
                prev_tm_height_,
                prev_elect_height_,
                all_root_nodes[node_idx],
                msg);
            if (msg.has_data()) {
                network::Route::Instance()->Send(msg);
            }
        }

        if (begin_idx >= kVssRandomSplitCount) {
            for (int32_t node_idx = begin_idx - kVssRandomSplitCount;
                    node_idx >= 0; node_idx -= kVssRandomSplitCount) {
                VssProto::CreateFirstSplitRandomMessage(
                    dht->local_node(),
                    node_idx,
                    random_nums[i],
                    prev_tm_height_,
                    prev_elect_height_,
                    all_root_nodes[node_idx],
                    msg);
                if (msg.has_data()) {
                    network::Route::Instance()->Send(msg);
                }
            }
        }
    }
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

    auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(vss_msg.pubkey());
    std::string hash_str = std::to_string(vss_msg.split_index()) + "_" +
        std::to_string(vss_msg.split_random()) + "_" +
        std::to_string(vss_msg.tm_height()) + "_" +
        std::to_string(vss_msg.elect_height()) + "_" +
        id;
    auto message_hash = common::Hash::keccak256(hash_str);
    auto pubkey = security::PublicKey(vss_msg.pubkey());
    auto sign = security::Signature(vss_msg.sign_ch(), vss_msg.sign_res());
    if (!security::Schnorr::Instance()->Verify(message_hash, sign, pubkey)) {
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
        HandleFirstPeriodSplitRandom(message_hash, vss_msg);
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
        return;
    }

    other_randoms_[mem_index].SetHash(id, vss_msg.random_hash());
}

void VssManager::HandleFirstPeriodSplitRandom(
        const std::string& msg_hash,
        const protobuf::VssMessage& vss_msg) {
    auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(vss_msg.pubkey());
    auto mem_index = elect::ElectManager::Instance()->GetMemberIndex(
        vss_msg.elect_height(),
        network::kRootCongressNetworkId,
        id);
    if (mem_index == elect::kInvalidMemberIndex) {
        return;
    }

    std::string dec_data = security::Crypto::Instance()->GetDecryptData(
        vss_msg.pubkey(),
        vss_msg.crypt_data());
    if (memcmp(msg_hash.c_str(), dec_data.c_str(), msg_hash.size()) != 0) {
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

    other_randoms_[mem_index].SetFinalRandomNum(id, vss_msg.random());
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
    other_randoms_[mem_index].SetFinalRandomNum(id, vss_msg.random());
}

}  // namespace vss

}  // namespace tenon
