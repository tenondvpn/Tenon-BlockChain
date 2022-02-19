#include "timeblock/time_block_manager.h"

#include <cstdlib>

#include "bft/bft_utils.h"
#include "bft/bft_manager.h"
#include "bft/gid_manager.h"
#include "bft/dispatch_pool.h"
#include "common/user_property_key_define.h"
#include "common/string_utils.h"
#include "common/global_info.h"
#include "dht/dht_key.h"
#include "election/proto/elect_proto.h"
#include "election/elect_manager.h"
#include "network/network_utils.h"
#include "network/route.h"
#include "security/security.h"
#include "security/secp256k1.h"
#include "transport/transport_utils.h"
#include "timeblock/time_block_utils.h"
#include "vss/vss_manager.h"

namespace tenon {

namespace tmblock {

static const std::string kTimeBlockGidPrefix = common::Encode::HexDecode(
    "c575ff0d3eea61205e3433495431e312056d0d51a64c6badfd4ad8cc092b7daa");
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
    check_bft_tick_.CutOff(
        35 * kCheckTimeBlockPeriodUs,
        std::bind(&TimeBlockManager::CheckBft, this));
}

TimeBlockManager::~TimeBlockManager() {}

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
        return kTimeBlockVssError;
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

bool TimeBlockManager::LeaderCanCallTimeBlockTx(uint64_t tm_sec) {
    uint64_t now_sec = common::TimeUtils::TimestampSeconds();
    if (now_sec >= latest_time_block_tm_ + common::kTimeBlockCreatePeriodSeconds) {
        return true;
    }

    if (now_sec  >= latest_tm_block_local_sec_ + common::kTimeBlockCreatePeriodSeconds) {
        return true;
    }

    return false;
}

void TimeBlockManager::CreateTimeBlockTx() {
    if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId &&
            common::GlobalInfo::Instance()->network_id() !=
            (network::kRootCongressNetworkId + network::kConsensusWaitingShardOffset)) {
        return;
    }

    auto gid = common::Hash::Hash256(kTimeBlockGidPrefix +
        std::to_string(latest_time_block_tm_));
    uint64_t new_time_block_tm = latest_time_block_tm_ + common::kTimeBlockCreatePeriodSeconds;
    bft::protobuf::TxInfo tx_info;
    tx_info.set_type(common::kConsensusRootTimeBlock);
    tx_info.set_from(common::kRootChainTimeBlockTxAddress);
    tx_info.set_gid(gid);
    tx_info.set_gas_limit(0llu);
    tx_info.set_amount(0);
    tx_info.set_network_id(network::kRootCongressNetworkId);
    tx_info.set_gas_price(common::kBuildinTransactionGasPrice);
    if (!bft::GidManager::Instance()->NewGidTxValid(gid, tx_info, false)) {
        BFT_ERROR("LeaderCreateTimeBlockTx error gid exists[%s] %lu, "
            "latest_time_block_tm_[%lu] new_time_block_tm[%lu]",
            common::Encode::HexEncode(gid).c_str(),
            (uint64_t)latest_time_block_height_,
            (uint64_t)latest_time_block_tm_,
            new_time_block_tm);
        return;
    }

    BFT_ERROR("LeaderCreateTimeBlockTx success gid not exists[%s] %lu, "
        "latest_time_block_tm_[%lu] new_time_block_tm[%lu], vss[%lu]",
        common::Encode::HexEncode(gid).c_str(),
        (uint64_t)latest_time_block_height_,
        (uint64_t)latest_time_block_tm_,
        new_time_block_tm,
        vss::VssManager::Instance()->GetConsensusFinalRandom());

    auto all_exits_attr = tx_info.add_attr();
    all_exits_attr->set_key(kAttrTimerBlock);
    all_exits_attr->set_value(std::to_string(new_time_block_tm));
    auto final_random_attr = tx_info.add_attr();
    final_random_attr->set_key(kVssRandomAttr);
    final_random_attr->set_value(
        std::to_string(vss::VssManager::Instance()->GetConsensusFinalRandom()));
    if (bft::DispatchPool::Instance()->Dispatch(tx_info) != bft::kBftSuccess) {
        TMBLOCK_ERROR("dispatch timeblock tx info failed!");
    }

    TMBLOCK_INFO("dispatch timeblock tx info success: %lu, vss: %s, real: %s!",
        new_time_block_tm, final_random_attr->value().c_str(), tx_info.attr(1).value().c_str());
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
        latest_tm_block_local_sec_ = common::TimeUtils::TimestampSeconds();
    }

    CreateTimeBlockTx();
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

bool TimeBlockManager::BackupheckNewTimeBlockValid(uint64_t new_time_block_tm) {
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

void TimeBlockManager::CheckBft() {
    int32_t pool_mod_num = elect::ElectManager::Instance()->local_node_pool_mod_num();
    if (pool_mod_num >= 0) {
        bft::BftManager::Instance()->StartBft("", pool_mod_num);
    }

    check_bft_tick_.CutOff(
        kCheckBftPeriodUs,
        std::bind(&TimeBlockManager::CheckBft, this));
}

}  // namespace tmblock

}  // namespace tenon
 