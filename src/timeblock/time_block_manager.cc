#include "timeblock/time_block_manager.h"

#include <cstdlib>

#include "bft/bft_utils.h"
#include "bft/bft_manager.h"
#include "bft/gid_manager.h"
#include "common/user_property_key_define.h"
#include "common/string_utils.h"
#include "dht/dht_key.h"
#include "election/proto/elect_proto.h"
#include "election/elect_manager.h"
#include "network/network_utils.h"
#include "network/route.h"
#include "security/schnorr.h"
#include "security/secp256k1.h"
#include "transport/transport_utils.h"
#include "timeblock/time_block_utils.h"
#include "vss/vss_manager.h"

namespace tenon {

namespace tmblock {

static const std::string kTimeBlockGidPrefix = common::Encode::HexDecode("c575ff0d3eea61205e3433495431e312056d0d51a64c6badfd4ad8cc092b7daa");
TimeBlockManager* TimeBlockManager::Instance() {
    static TimeBlockManager ins;
    return &ins;
}

uint64_t TimeBlockManager::LatestTimestamp() {
    return latest_time_block_tm_;
}

uint64_t TimeBlockManager::LatestTimestampHeight() {
    return latest_time_block_height_;
}

TimeBlockManager::TimeBlockManager() {
    create_tm_block_tick_.CutOff(
        30 * kCheckTimeBlockPeriodUs,
        std::bind(&TimeBlockManager::CreateTimeBlockTx, this));
    check_bft_tick_.CutOff(
        30 * kCheckTimeBlockPeriodUs,
        std::bind(&TimeBlockManager::CheckBft, this));
}

TimeBlockManager::~TimeBlockManager() {}

int TimeBlockManager::LeaderCreateTimeBlockTx(transport::protobuf::Header* msg) {
    auto gid = common::Hash::Hash256(kTimeBlockGidPrefix +
        std::to_string(elect::ElectManager::Instance()->latest_height(
            common::GlobalInfo::Instance()->network_id())) +
        std::to_string(latest_time_block_tm_));
    uint32_t des_net_id = common::GlobalInfo::Instance()->network_id();
    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg->set_src_dht_key(dht_key.StrKey());
    msg->set_des_dht_key(dht_key.StrKey());
    msg->set_priority(transport::kTransportPriorityHighest);
    msg->set_id(common::GlobalInfo::Instance()->MessageId());
    msg->set_type(common::kBftMessage);
    msg->set_client(false);
    msg->set_hop_count(0);
    auto broad_param = msg->mutable_broadcast();
    elect::ElectProto::SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    uint64_t new_time_block_tm = 0;
    if (!LeaderNewTimeBlockValid(&new_time_block_tm)) {
        return kTimeBlockError;
    }

    bft::protobuf::TxBft tx_bft;
    auto tx_info = tx_bft.mutable_new_tx();
    tx_info->set_type(common::kConsensusRootTimeBlock);
    tx_info->set_from(common::kRootChainSingleBlockTxAddress);
    tx_info->set_gid(gid);

    tx_info->set_gas_limit(0llu);
    tx_info->set_amount(0);
    tx_info->set_network_id(network::kRootCongressNetworkId);
    if (!bft::GidManager::Instance()->NewGidTxValid(gid, *tx_info)) {
        BFT_ERROR("LeaderCreateTimeBlockTx error gid exists[%s] %lu"
            "latest_time_block_tm_[%lu] new_time_block_tm[%lu]",
            common::Encode::HexEncode(gid).c_str(),
            (uint64_t)latest_time_block_height_, (uint64_t)latest_time_block_tm_, new_time_block_tm);

        return kTimeBlockError;
    }

    BFT_ERROR("LeaderCreateTimeBlockTx success gid exists[%s] %lu"
        "latest_time_block_tm_[%lu] new_time_block_tm[%lu]",
        common::Encode::HexEncode(gid).c_str(),
        (uint64_t)latest_time_block_height_, (uint64_t)latest_time_block_tm_, new_time_block_tm);

    auto all_exits_attr = tx_info->add_attr();
    all_exits_attr->set_key(kAttrTimerBlock);
    all_exits_attr->set_value(std::to_string(new_time_block_tm));
    auto final_random_attr = tx_info->add_attr();
    final_random_attr->set_key(kVssRandomAttr);
    final_random_attr->set_value(
        std::to_string(vss::VssManager::Instance()->GetConsensusFinalRandom()));
    bft_msg.set_net_id(network::kRootCongressNetworkId);
    bft_msg.set_data(tx_bft.SerializeAsString());
    bft_msg.set_gid("");
    bft_msg.set_rand(0);
    bft_msg.set_bft_step(bft::kBftInit);
    bft_msg.set_leader(false);
    bft_msg.set_node_id(common::GlobalInfo::Instance()->id());
    bft_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    auto hash128 = bft::GetTxMessageHash(*tx_info);
    auto tx_data = tx_bft.SerializeAsString();
    bft_msg.set_data(tx_data);
    security::Signature sign;
    if (!security::Schnorr::Instance()->Sign(
            hash128,
            *(security::Schnorr::Instance()->prikey()),
            *(security::Schnorr::Instance()->pubkey()),
            sign)) {
        return kTimeBlockError;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg->set_data(bft_msg.SerializeAsString());
    TMBLOCK_ERROR("leader create new time block transaction: %lu", new_time_block_tm);
    return kTimeBlockSuccess;
}

int TimeBlockManager::BackupCheckTimeBlockTx(const bft::protobuf::TxInfo& tx_info) {
    if (tx_info.attr_size() != 2) {
        TMBLOCK_ERROR("tx_info.attr_size() error: %d", tx_info.attr_size());
        return kTimeBlockError;
    }

    if (tx_info.attr(1).key() != kVssRandomAttr) {
        TMBLOCK_ERROR("tx_info.attr(1).key() error: %s", tx_info.attr(1).key().c_str());
        return kTimeBlockError;
    }

    uint64_t leader_final_cons_random = 0;
    if (!common::StringUtil::ToUint64(tx_info.attr(1).value(), &leader_final_cons_random)) {
        return kTimeBlockError;
    }

    if (leader_final_cons_random != vss::VssManager::Instance()->GetConsensusFinalRandom()) {
        TMBLOCK_ERROR("leader_final_cons_random: %lu, GetConsensusFinalRandom(): %lu",
            leader_final_cons_random,
            vss::VssManager::Instance()->GetConsensusFinalRandom());
        return kTimeBlockError;
    }

    if (tx_info.attr(0).key() != kAttrTimerBlock) {
        TMBLOCK_ERROR("tx_info.attr(0).key() error: %s", tx_info.attr(0).key().c_str());
        return kTimeBlockError;
    }

    uint64_t leader_tm = 0;
    if (!common::StringUtil::ToUint64(tx_info.attr(0).value(), &leader_tm)) {
        return kTimeBlockError;
    }

    if (!BackupheckNewTimeBlockValid(leader_tm)) {
        TMBLOCK_ERROR("BackupheckNewTimeBlockValid error: %llu", leader_tm);
        return kTimeBlockError;
    }

    return kTimeBlockSuccess;
}

void TimeBlockManager::UpdateTimeBlock(
        uint64_t latest_time_block_height,
        uint64_t latest_time_block_tm,
        uint64_t vss_random) {
    {
        std::lock_guard<std::mutex> guard(latest_time_blocks_mutex_);
        if (latest_time_block_height_ >= latest_time_block_height) {
            return;
        }

        latest_time_block_height_ = latest_time_block_height;
        latest_time_block_tm_ = latest_time_block_tm;
        latest_time_blocks_.push_back(latest_time_block_tm_);
        if (latest_time_blocks_.size() >= kTimeBlockAvgCount) {
            latest_time_blocks_.pop_front();
        }
    }

    BFT_ERROR("LeaderNewTimeBlockValid offset_tm final[%lu], prev[%lu]",
        (uint64_t)latest_time_block_height_, (uint64_t)latest_time_block_tm_);
    vss::VssManager::Instance()->OnTimeBlock(
        latest_time_block_tm,
        latest_time_block_height,
        elect::ElectManager::Instance()->latest_height(
            common::GlobalInfo::Instance()->network_id()),
        vss_random);
    elect::ElectManager::Instance()->OnTimeBlock(latest_time_block_tm);
}

bool TimeBlockManager::LeaderNewTimeBlockValid(uint64_t* new_time_block_tm) {
//     auto now_tm = common::TimeUtils::TimestampSeconds();
//     if (now_tm >= latest_time_block_tm_ + common::kTimeBlockCreatePeriodSeconds) {
//         std::lock_guard<std::mutex> guard(latest_time_blocks_mutex_);
//         *new_time_block_tm = latest_time_block_tm_ + common::kTimeBlockCreatePeriodSeconds;
//         return true;
//     }

    auto now_tm = common::TimeUtils::TimestampSeconds();
    if (now_tm >= latest_time_block_tm_ + common::kTimeBlockCreatePeriodSeconds) {
        *new_time_block_tm = latest_time_block_tm_ + common::kTimeBlockCreatePeriodSeconds;
        if (now_tm - *new_time_block_tm > kTimeBlockMaxOffsetSeconds) {
            *new_time_block_tm += kTimeBlockMaxOffsetSeconds;
        } else {
            *new_time_block_tm += now_tm - *new_time_block_tm;
        }

        return true;
    }
    return false;
}

bool TimeBlockManager::BackupheckNewTimeBlockValid(uint64_t new_time_block_tm) {
//     uint64_t backup_latest_time_block_tm = latest_time_block_tm_;
//     backup_latest_time_block_tm += common::kTimeBlockCreatePeriodSeconds;
//     if (new_time_block_tm == backup_latest_time_block_tm) {
//         return true;
//     }
// 
//     BFT_ERROR("BackupheckNewTimeBlockValid error[%llu][%llu] latest_time_block_tm_[%lu]",
//         new_time_block_tm, (uint64_t)backup_latest_time_block_tm, (uint64_t)latest_time_block_tm_);
//     return false;

    uint64_t backup_latest_time_block_tm = latest_time_block_tm_;
    backup_latest_time_block_tm += common::kTimeBlockCreatePeriodSeconds;
    if (new_time_block_tm < (backup_latest_time_block_tm + kTimeBlockTolerateSeconds) &&
            new_time_block_tm >(backup_latest_time_block_tm - kTimeBlockTolerateSeconds)) {
        return true;
    }

    BFT_ERROR("BackupheckNewTimeBlockValid error[%llu][%llu] latest_time_block_tm_[%lu]",
        new_time_block_tm, (uint64_t)backup_latest_time_block_tm, (uint64_t)latest_time_block_tm_);
    return false;
}

bool TimeBlockManager::ThisNodeIsLeader(int32_t* pool_mod_num) {
    auto leader_count = elect::ElectManager::Instance()->GetNetworkLeaderCount(
        network::kRootCongressNetworkId);
    int32_t mem_index = elect::ElectManager::Instance()->GetMemberIndex(
        common::GlobalInfo::Instance()->network_id(),
        common::GlobalInfo::Instance()->id());
    auto mem_ptr = elect::ElectManager::Instance()->GetMember(
        common::GlobalInfo::Instance()->network_id(),
        common::GlobalInfo::Instance()->id());
    if (mem_ptr != nullptr && mem_ptr->pool_index_mod_num >= 0) {
        *pool_mod_num = mem_ptr->pool_index_mod_num;
        return true;
    }
    
    return false;
}

void TimeBlockManager::CreateTimeBlockTx() {
    {
        std::lock_guard<std::mutex> guard(latest_time_blocks_mutex_);
        auto now_tm_sec = common::TimeUtils::TimestampSeconds();
        if (now_tm_sec >= latest_time_block_tm_ + common::kTimeBlockCreatePeriodSeconds) {
            if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
                int32_t pool_mod_num = -1;
                if (elect::ElectManager::Instance()->IsSuperLeader(
                    common::GlobalInfo::Instance()->network_id(),
                    common::GlobalInfo::Instance()->id())) {
                    transport::protobuf::Header msg;
                    if (LeaderCreateTimeBlockTx(&msg) == kTimeBlockSuccess) {
                        network::Route::Instance()->Send(msg);
                        network::Route::Instance()->SendToLocal(msg);
                    }
                }
            }
        }
    }

    create_tm_block_tick_.CutOff(
        kCheckTimeBlockPeriodUs,
        std::bind(&TimeBlockManager::CreateTimeBlockTx, this));
}

void TimeBlockManager::CheckBft() {
    int32_t pool_mod_num = -1;
    if (ThisNodeIsLeader(&pool_mod_num)) {
        bft::BftManager::Instance()->StartBft("", pool_mod_num);
    }

    check_bft_tick_.CutOff(
        kCheckBftPeriodUs,
        std::bind(&TimeBlockManager::CheckBft, this));
}

void TimeBlockManager::BroadcastTimeBlock() {
    transport::protobuf::Header msg;
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        TMBLOCK_ERROR("not join network[%u]", common::GlobalInfo::Instance()->network_id());
        return;
    }

    CreateTmBroadcastMessage(
        dht->local_node(),
        msg);
    if (msg.has_data()) {
        network::Route::Instance()->Send(msg);
        network::Route::Instance()->SendToLocal(msg);
    }
}

void TimeBlockManager::CreateTmBroadcastMessage(
        const dht::NodePtr& local_node,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(network::kRootCongressNetworkId, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kTtimeBlockMessage);
    msg.set_client(local_node->client_mode);
    msg.set_universal(false);
    msg.set_hop_count(0);
    std::string hash_str;
    auto message_hash = common::Hash::keccak256(hash_str);
    security::Signature sign;
    bool sign_res = security::Schnorr::Instance()->Sign(
        message_hash,
        *(security::Schnorr::Instance()->prikey()),
        *(security::Schnorr::Instance()->pubkey()),
        sign);
    if (!sign_res) {
        VSS_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    auto broad_param = msg.mutable_broadcast();
//     msg.set_data(vss_msg.SerializeAsString());
}
}  // namespace tmblock

}  // namespace tenon
 