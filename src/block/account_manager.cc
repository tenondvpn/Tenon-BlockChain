#include "stdafx.h"
#include "block/account_manager.h"

#include <algorithm>

#include "bft/dispatch_pool.h"
#include "bft/gid_manager.h"
#include "block/shard_statistic.h"
#include "contract/contract_manager.h"
#include "common/encode.h"
#include "db/db.h"
#include "election/member_manager.h"
#include "election/proto/elect.pb.h"
#include "election/elect_manager.h"
#include "statistics/statistics.h"
#include "sync/key_value_sync.h"
#include "timeblock/time_block_utils.h"
#include "timeblock/time_block_manager.h"
#include "vss/vss_manager.h"


namespace tenon {

namespace common {

template<>
uint64_t MinHeapUniqueVal(const block::DbAccountInfoPtr& val) {
    return 0;
}

}  // namespace common

}  // namespace tenon

namespace tenon {

namespace block {

static const std::string kPoolGidPrefixStr = common::Encode::HexDecode(
    "cdcd41af3b1af1f402107969536664d3e249075843f635961041592ce83823b9");

AccountManager* AccountManager::Instance() {
    static AccountManager ins;
    return &ins;
}

AccountManager::AccountManager() {
}

AccountManager::~AccountManager() {
    {
        for (uint32_t i = 0; i < common::kImmutablePoolSize + 1; ++i) {
            if (block_pools_[i] != nullptr) {
                delete block_pools_[i];
            }
        }
    }

    {
        std::lock_guard<std::mutex> guard(acc_map_mutex_);
        acc_map_.clear();
    }
}

int AccountManager::Init(uint32_t network_id) {
    for (uint32_t i = 0; i < common::kImmutablePoolSize + 1; ++i) {
        block_pools_[i] = new block::DbPoolInfo(i, network_id);
    }

    srand(time(NULL));
    prev_refresh_heights_tm_ = common::TimeUtils::TimestampSeconds() + rand() % 30;
    check_missing_height_tick_.CutOff(
        kCheckMissingHeightPeriod,
        std::bind(&AccountManager::CheckMissingHeight, this));
    flush_db_tick_.CutOff(
        kFushTreeToDbPeriod,
        std::bind(&AccountManager::FlushPoolHeightTreeToDb, this));
    refresh_pool_max_height_tick_.CutOff(
        kRefreshPoolMaxHeightPeriod,
        std::bind(&AccountManager::RefreshPoolMaxHeight, this));
    return kBlockSuccess;
}

bool AccountManager::AccountExists(const std::string& acc_id) {
    {
        std::lock_guard<std::mutex> guard(acc_map_mutex_);
        auto iter = acc_map_.find(acc_id);
        if (iter != acc_map_.end()) {
            iter->second->set_added_timeout(common::TimeUtils::TimestampMs());
            acc_limit_heap_.AdjustDown(iter->second->heap_index());
            return true;
        }
    }

    if (DbAccountInfo::AccountExists(acc_id)) {
        auto account_info = std::make_shared<block::DbAccountInfo>(acc_id);
        std::lock_guard<std::mutex> guard(acc_map_mutex_);
        acc_map_[acc_id] = account_info;
        account_info->set_added_timeout(common::TimeUtils::TimestampMs());
        account_info->set_heap_index(acc_limit_heap_.push(account_info));
//         BLOCK_DEBUG("now account size: %u", acc_map_.size());
        return true;
    }

    return false;
}

DbAccountInfoPtr AccountManager::GetAcountInfo(const std::string& acc_id) {
    if (acc_id.size() != security::kTenonAddressSize) {
        return nullptr;
    }

    {
        std::lock_guard<std::mutex> guard(acc_map_mutex_);
        auto iter = acc_map_.find(acc_id);
        if (iter != acc_map_.end()) {
            iter->second->set_added_timeout(common::TimeUtils::TimestampMs());
            acc_limit_heap_.AdjustDown(iter->second->heap_index());
            return iter->second;
        }
    }

    if (DbAccountInfo::AccountExists(acc_id)) {
        auto account_info = std::make_shared<block::DbAccountInfo>(acc_id);
        std::lock_guard<std::mutex> guard(acc_map_mutex_);
        acc_map_[acc_id] = account_info;
        account_info->set_added_timeout(common::TimeUtils::TimestampMs());
        account_info->set_heap_index(acc_limit_heap_.push(account_info));
        return account_info;
    }

    return nullptr;
}

DbAccountInfoPtr AccountManager::GetContractInfoByAddress(const std::string& address) {
    auto account_info = GetAcountInfo(address);
    if (account_info == nullptr) {
        BLOCK_ERROR("get account failed[%s]", common::Encode::HexEncode(address).c_str());
        return nullptr;
    }

    uint32_t address_type = kNormalAddress;
    if (account_info->GetAddressType(&address_type) != kBlockSuccess) {
        BLOCK_ERROR("get account address_type failed[%s]",
            common::Encode::HexEncode(address).c_str());
        return nullptr;
    }

    if (address_type != kContractAddress) {
        BLOCK_ERROR("get account address_type[%d] invalid failed[%s]",
            address_type, common::Encode::HexEncode(address).c_str());
        return nullptr;
    }

    return account_info;
}

int AccountManager::GetAddressConsensusNetworkId(
        const std::string& address,
        uint32_t* network_id) {
    auto account_ptr = GetAcountInfo(address);
    if (account_ptr == nullptr) {
        return kBlockAddressNotExists;
    }

    account_ptr->GetConsensuseNetId(network_id);
    return kBlockSuccess;
}

int AccountManager::HandleElectBlock(
        uint64_t height,
        const bft::protobuf::TxInfo& tx_info,
        db::DbWriteBach& db_batch) {
    elect::protobuf::ElectBlock elect_block;
    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        if (tx_info.attr(i).key() == elect::kElectNodeAttrElectBlock) {
            elect_block.ParseFromString(tx_info.attr(i).value());
        }
    }

    if (!elect_block.IsInitialized()) {
        return kBlockSuccess;
    }

    elect::ElectManager::Instance()->OnNewElectBlock(height, elect_block);
    vss::VssManager::Instance()->OnElectBlock(elect_block.shard_network_id(), height);
    if (elect_block.prev_members().bls_pubkey_size() > 0) {
        std::string key = GetElectBlsMembersKey(
            elect_block.prev_members().prev_elect_height(),
            elect_block.shard_network_id());
        db_batch.Put(key, elect_block.prev_members().SerializeAsString());
    }

    return kBlockSuccess;
}

int AccountManager::HandleTimeBlock(uint64_t height, const bft::protobuf::TxInfo& tx_info) {
    uint64_t tmblock_timestamp = 0;
    uint64_t vss_random = 0;
    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        if (tx_info.attr(i).key() == tmblock::kAttrTimerBlock) {
            common::StringUtil::ToUint64(tx_info.attr(i).value(), &tmblock_timestamp);
        }

        if (tx_info.attr(i).key() == tmblock::kVssRandomAttr) {
            common::StringUtil::ToUint64(tx_info.attr(i).value(), &vss_random);
        }
    }

    tmblock::TimeBlockManager::Instance()->UpdateTimeBlock(
        height,
        tmblock_timestamp,
        vss_random);
    return kBlockSuccess;
}

int AccountManager::HandleRootSingleBlockTx(
        uint64_t height,
        const bft::protobuf::TxInfo& tx_info,
        db::DbWriteBach& db_batch) {
    switch (tx_info.type()) {
    case common::kConsensusRootElectShard:
        return HandleElectBlock(height, tx_info, db_batch);
    case common::kConsensusRootTimeBlock:
        return HandleTimeBlock(height, tx_info);
    default:
        break;
    }

    return kBlockSuccess;
}

int AccountManager::HandleFinalStatisticBlock(
        uint64_t height,
        const bft::protobuf::TxInfo& tx_info) {
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        // add elect root transaction
        bft::protobuf::TxInfo elect_tx;
        if (elect::ElectManager::Instance()->CreateElectTransaction(
                tx_info.network_id(),
                height,
                tx_info,
                elect_tx) != elect::kElectSuccess) {
            BFT_ERROR("create elect transaction error!");
        }

        if (bft::DispatchPool::Instance()->Dispatch(elect_tx) != bft::kBftSuccess) {
            BFT_ERROR("dispatch pool failed!");
        }
    }

    return kBlockSuccess;
}

int AccountManager::AddBlockItemToDb(
        const std::shared_ptr<bft::protobuf::Block>& block_item,
        db::DbWriteBach& db_batch,
        bool is_kv_sync) {
    const auto& tx_list = block_item->tx_list();
    if (tx_list.empty()) {
        BLOCK_ERROR("tx block tx list is empty.");
        return kBlockError;
    }
    
    // one block must be one consensus pool
    uint32_t consistent_pool_index = common::kInvalidPoolIndex;
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        std::string account_id;
        if (tx_list[i].to_add()) {
            account_id = tx_list[i].to();
        } else {
            account_id = tx_list[i].from();
        }

        if (tx_list[i].type() == common::kConsensusCallContract ||
            tx_list[i].type() == common::kConsensusCreateContract) {
            switch (tx_list[i].call_contract_step()) {
            case contract::kCallStepCallerInited:
                account_id = tx_list[i].from();
                break;
            case contract::kCallStepContractCalled:
                account_id = tx_list[i].to();
                break;
            case contract::kCallStepContractFinal:
                account_id = tx_list[i].from();
                break;
            default:
                break;
            }
        }

        uint32_t pool_idx = common::GetPoolIndex(account_id);
        bft::GidManager::Instance()->NewGidTxValid(tx_list[i].gid(), tx_list[i], true);
        bft::DispatchPool::Instance()->RemoveTx(
            pool_idx,
            tx_list[i].to_add(),
            tx_list[i].type(),
            tx_list[i].call_contract_step(),
            tx_list[i].gid());
        if (bft::IsRootSingleBlockTx(tx_list[i].type())) {
            if (HandleRootSingleBlockTx(
                    block_item->height(),
                    tx_list[i],
                    db_batch) != kBlockSuccess) {
                BLOCK_ERROR("HandleRootSingleBlockTx failed!");
                return kBlockError;
            }
        }

        if (tx_list[i].type() == common::kConsensusFinalStatistic &&
                common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
            if (HandleFinalStatisticBlock(block_item->height(), tx_list[i]) != kBlockSuccess) {
                BLOCK_ERROR("HandleFinalStatisticBlock failed!");
                return kBlockError;
            }
        }

        if (consistent_pool_index == common::kInvalidPoolIndex) {
            consistent_pool_index = pool_idx;
        }

        if (consistent_pool_index != pool_idx) {
            BLOCK_ERROR("block pool index not consistent[%u][%u][%s]",
                consistent_pool_index, pool_idx,
                common::Encode::HexEncode(account_id).c_str());
            assert(false);
            exit(0);
        }

        if (tx_list[i].attr_size() > 0 || tx_list[i].storages_size() > 0) {
            block::DbAccountInfoPtr account_info = nullptr;
            {
                std::lock_guard<std::mutex> guard(acc_map_mutex_);
                auto iter = acc_map_.find(account_id);
                if (iter != acc_map_.end()) {
                    account_info = iter->second;
                }
            }
            
            if (account_info == nullptr) {
                return kBlockError;
            }

            for (int32_t attr_idx = 0; attr_idx < tx_list[i].attr_size(); ++attr_idx) {
                account_info->ClearAttr(tx_list[i].attr(attr_idx).key());
            }

            for (int32_t attr_idx = 0; attr_idx < tx_list[i].storages_size(); ++attr_idx) {
                account_info->ClearAttr(tx_list[i].storages(attr_idx).key());
            }
        }
    }

    block_pools_[consistent_pool_index]->SetHeightTree(block_item->height());
    return kBlockSuccess;
}

void AccountManager::SetMaxHeight(uint32_t pool_idx, uint64_t height) {
    block_pools_[pool_idx]->SetMaxHeight(height);
    BLOCK_DEBUG("pool: %d set max height: %lu", pool_idx, height);
}

int AccountManager::AddBlockItemToCache(
        const std::shared_ptr<bft::protobuf::Block>& block_item,
        db::DbWriteBach& db_batch) {
    if (!block_hash_limit_set_.Push(block_item->hash())) {
        return kBlockSuccess;
    }

    const auto& tx_list = block_item->tx_list();
    if (tx_list.empty()) {
        BLOCK_ERROR("tx block tx list is empty.");
        return kBlockError;
    }
    
    // one block must be one consensus pool
    uint32_t consistent_pool_index = common::kInvalidPoolIndex;
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        std::string account_id;
        if (tx_list[i].to_add()) {
            account_id = tx_list[i].to();
        } else {
            account_id = tx_list[i].from();
        }

        if (tx_list[i].type() == common::kConsensusCallContract ||
                tx_list[i].type() == common::kConsensusCreateContract) {
            switch (tx_list[i].call_contract_step()) {
            case contract::kCallStepCallerInited:
                account_id = tx_list[i].from();
                break;
            case contract::kCallStepContractCalled:
                account_id = tx_list[i].to();
                break;
            case contract::kCallStepContractFinal:
                account_id = tx_list[i].from();
                break;
            default:
                break;
            }
        }

        if (UpdateAccountInfo(
                account_id,
                tx_list[i],
                block_item,
                db_batch) != kBlockSuccess) {
            BLOCK_ERROR("to add account failed: %s, %llu",
                common::Encode::HexEncode(block_item->hash()).c_str(),
                block_item->height());
            assert(false);
            continue;
        }

        uint32_t pool_idx = common::GetPoolIndex(account_id);
        if (consistent_pool_index == common::kInvalidPoolIndex) {
            consistent_pool_index = pool_idx;
        }

        if (consistent_pool_index != pool_idx) {
            BLOCK_ERROR("block pool index not consistent[%u][%u][%s]",
                consistent_pool_index, pool_idx,
                common::Encode::HexEncode(account_id).c_str());
            assert(false);
            exit(0);
        }
    }

    if (block_item->network_id() == common::GlobalInfo::Instance()->network_id() ||
            consistent_pool_index == common::kRootChainPoolIndex ||
            (block_item->network_id() >= network::kRootCongressNetworkId &&
            block_item->network_id() < network::kConsensusShardEndNetworkId &&
            block_item->network_id() + network::kConsensusWaitingShardOffset ==
            common::GlobalInfo::Instance()->network_id())) {
        assert(consistent_pool_index < common::kInvalidPoolIndex);
        SetPool(
            consistent_pool_index,
            block_item,
            db_batch);
    }

    return kBlockSuccess;
}

int AccountManager::AddNewAccount(
        const bft::protobuf::TxInfo& tx_info,
        uint64_t tmp_now_height,
        const std::string& create_hash,
        db::DbWriteBach& db_batch) {
    if (!tx_info.to_add()) {
        BFT_ERROR("direct add new account must transfer to.");
        return kBlockError;
    }

    std::string account_id = tx_info.to();
    std::lock_guard<std::mutex> guard(acc_map_mutex_);
    auto iter = acc_map_.find(account_id);
    if (iter != acc_map_.end()) {
        iter->second->set_added_timeout(common::TimeUtils::TimestampMs());
        acc_limit_heap_.AdjustDown(iter->second->heap_index());
        return kBlockSuccess;
    }

    if (block::DbAccountInfo::AccountExists(account_id)) {
        return kBlockSuccess;
    }

    if (tx_info.amount() == 0 && tx_info.type() != common::kConsensusCreateContract) {
        return kBlockSuccess;
    }

    auto account_info = std::make_shared<block::DbAccountInfo>(account_id);
    int res = kBlockSuccess;
    do 
    {
        if (!block::DbAccountInfo::AddNewAccountToDb(account_id, db_batch)) {
            BLOCK_ERROR("fromAddNewAccountToDb failed: %s, %llu",
                    common::Encode::HexEncode(account_id).c_str());
            res = kBlockError;
            break;
        }

        account_info->SetMaxHeightHash(tmp_now_height, create_hash, db_batch);
        BLOCK_ERROR("DDDDDDDDDDDDDD NewHeight: %s, %lu, type: %d", common::Encode::HexEncode(account_id).c_str(), tmp_now_height, tx_info.type());
        account_info->NewHeight(tmp_now_height, db_batch);
        int res = account_info->SetBalance(0, db_batch);
//         res += account_info->SetCreateAccountHeight(tmp_now_height, db_batch);
//         if (res != 0) {
//             BLOCK_ERROR("SetCreateAccountHeight failed: %s, %llu",
//                 common::Encode::HexEncode(account_id).c_str());
//             res = kBlockError;
//             break;
//         }

        if (tx_info.type() == common::kConsensusCreateContract) {
            res += account_info->SetAddressType(kContractAddress, db_batch);
            for (int32_t i = 0; i < tx_info.storages_size(); ++i) {
                if (tx_info.storages(i).key() == bft::kContractCreatedBytesCode) {
                    res += account_info->SetBytesCode(tx_info.storages(i).value(), db_batch);
                }
            }

            res += account_info->SetAttrValue(kFieldContractOwner, tx_info.from(), db_batch);
        } else {
            res += account_info->SetAddressType(kNormalAddress, db_batch);
        }

        res += account_info->SetConsensuseNetid(tx_info.network_id(), db_batch);
        if (res != kBlockSuccess) {
            BLOCK_ERROR("SetConsensuseNetid failed: %s, %llu",
                common::Encode::HexEncode(account_id).c_str());
            res = kBlockError;
            break;
        }
    } while (0);

    if (res != kBlockSuccess) {
        return kBlockError;
    }

    acc_map_[account_id] = account_info;
    account_info->set_added_timeout(common::TimeUtils::TimestampMs());
    account_info->set_heap_index(acc_limit_heap_.push(account_info));

//     BLOCK_DEBUG("now account size: %u", acc_map_.size());
    uint64_t exist_height = 0;
    if (account_info->GetMaxHeight(&exist_height) != block::kBlockSuccess) {
        BLOCK_ERROR("GetMaxHeight failed!");
        return kBlockError;
    }

//     uint64_t create_height = 0;
//     if (account_info->GetCreateAccountHeight(&create_height) != block::kBlockSuccess) {
//         BLOCK_ERROR("GetCreateAccountHeight failed!");
//         return kBlockError;
//     }

    if (SetAccountAttrs(
            account_id,
            tx_info,
            exist_height,
            tmp_now_height,
            account_info.get(),
            db_batch) != kBlockSuccess) {
        return kBlockError;
    }

    if (exist_height <= tmp_now_height) {
        res += account_info->SetMaxHeightHash(tmp_now_height, create_hash, db_batch);
//     } else {
//         if (create_height > tmp_now_height) {
//             res += account_info->SetCreateAccountHeight(tmp_now_height, db_batch);
//         }
    }

    if (res != 0) {
        BLOCK_ERROR("SetCreateAccountHeight failed!");
        return kBlockError;
    }

    return kBlockSuccess;
}

int AccountManager::UpdateAccountInfo(
        const std::string& account_id,
        const bft::protobuf::TxInfo& tx_info,
        const std::shared_ptr<bft::protobuf::Block>& block_item,
        db::DbWriteBach& db_batch) {
    if (tx_info.status() != bft::kBftSuccess && tx_info.to_add()) {
        if (tx_info.type() != common::kConsensusCallContract &&
            tx_info.type() != common::kConsensusCreateContract) {
            return kBlockSuccess;
        }
    }

    block::DbAccountInfoPtr account_info = nullptr;
    uint64_t exist_height = 0;
    {
        std::lock_guard<std::mutex> guard(acc_map_mutex_);
        auto iter = acc_map_.find(account_id);
        if (iter == acc_map_.end()) {
            account_info = std::make_shared<block::DbAccountInfo>(account_id);
            if (!block::DbAccountInfo::AccountExists(account_id)) {
                if (!block::DbAccountInfo::AddNewAccountToDb(account_id, db_batch)) {
                    BLOCK_ERROR("fromAddNewAccountToDb failed: %s, %llu",
                        common::Encode::HexEncode(account_id).c_str());
                    return kBlockError;
                }

                account_info->SetConsensuseNetid(tx_info.network_id(), db_batch);
                account_info->SetMaxHeightHash(block_item->height(), block_item->hash(), db_batch);
                account_info->SetBalance(tx_info.balance(), db_batch);
                exist_height = block_item->height();
            }

            acc_map_[account_id] = account_info;
            account_info->set_added_timeout(common::TimeUtils::TimestampMs());
            account_info->set_heap_index(acc_limit_heap_.push(account_info));
        } else {
            account_info = iter->second;
            account_info->set_added_timeout(common::TimeUtils::TimestampMs());
            acc_limit_heap_.AdjustDown(account_info->heap_index());
            if (account_info->GetMaxHeight(&exist_height) != block::kBlockSuccess) {
                BLOCK_ERROR("GetMaxHeight failed!");
                return kBlockError;
            }
        }
    }

    account_info->NewHeight(block_item->height(), db_batch);
    if (exist_height <= block_item->height()) {
        account_info->SetMaxHeightHash(block_item->height(), block_item->hash(), db_batch);
    }

    uint32_t pool_idx = common::GetPoolIndex(account_id);
    if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId) {
        uint32_t pool_idx = common::GetPoolIndex(account_id);
        if (exist_height <= block_item->height()) {
            account_info->SetBalance(tx_info.balance(), db_batch);
        }
    }
    
    if (SetAccountAttrs(
            account_id,
            tx_info,
            exist_height,
            block_item->height(),
            account_info.get(),
            db_batch) != kBlockSuccess) {
        return kBlockError;
    }

    if (tx_info.status() == bft::kBftSuccess &&
            (tx_info.type() == common::kConsensusCallContract ||
            tx_info.type() == common::kConsensusCreateContract)) {
        if (tx_info.call_contract_step() == contract::kCallStepCallerInited) {
            account_info->LockAccount();
        }

        if (tx_info.call_contract_step() == contract::kCallStepContractFinal) {
            account_info->UnLockAccount();
        }
    }

    return kBlockSuccess;
}

bool AccountManager::IsInvalidKey(const std::string& key) {
    if (key.size() < 2) {
        return false;
    }

    if (key[0] == '_' && key[1] == '_') {
        return true;
    }

    return false;
}

int AccountManager::SetAccountAttrs(
        const std::string& account_id,
        const bft::protobuf::TxInfo& tx_info,
        uint64_t exist_height,
        uint64_t tmp_now_height,
        block::DbAccountInfo* account_info,
        db::DbWriteBach& db_batch) {
    if (tx_info.status() == bft::kBftSuccess) {
        int res = 0;
        if (tx_info.type() == common::kConsensusCreateContract &&
                tx_info.to_add() &&
                account_id == tx_info.to()) {
            res += account_info->SetAddressType(kContractAddress, db_batch);
            for (int32_t i = 0; i < tx_info.storages_size(); ++i) {
                if (tx_info.storages(i).key() == bft::kContractCreatedBytesCode) {
                    res += account_info->SetBytesCode(tx_info.storages(i).value(), db_batch);
                }
            }

            res += account_info->SetAttrValue(kFieldContractOwner, tx_info.from(), db_batch);
        }

        if ((tx_info.type() != common::kConsensusCallContract && !tx_info.to_add()) ||
                (tx_info.type() == common::kConsensusCallContract &&
                (tx_info.call_contract_step() == contract::kCallStepContractCalled ||
                tx_info.call_contract_step() == contract::kCallStepContractFinal)) ||
                (tx_info.type() == common::kConsensusCreateContract && tx_info.to_add())) {
            if (exist_height <= tmp_now_height) {
                uint64_t tmblock_tm = common::kInvalidUint64;
                uint64_t tmblock_vss_random = common::kInvalidUint64;
                for (int32_t attr_idx = 0; attr_idx < tx_info.attr_size(); ++attr_idx) {
                    if (tx_info.type() == common::kConsensusRootElectShard) {
                        if (tx_info.attr(attr_idx).key() == elect::kElectNodeAttrElectBlock) {
                            account_info->AddNewElectBlock(
                                tx_info.network_id(),
                                tmp_now_height,
                                tx_info.attr(attr_idx).value(),
                                db_batch);
                        }
                    }

                    if (tx_info.type() == common::kConsensusRootTimeBlock) {
                        if (tx_info.attr(attr_idx).key() == tmblock::kAttrTimerBlock) {
                            if (!common::StringUtil::ToUint64(tx_info.attr(attr_idx).value(), &tmblock_tm)) {
                                return kBlockError;
                            }
                        }

                        if (tx_info.attr(attr_idx).key() == tmblock::kVssRandomAttr) {
                            if (!common::StringUtil::ToUint64(tx_info.attr(attr_idx).value(), &tmblock_vss_random)) {
                                return kBlockError;
                            }
                        }
                    }

                    if (IsInvalidKey(tx_info.attr(attr_idx).key())) {
                        continue;
                    }

                    res += account_info->SetAttrValue(
                        tx_info.attr(attr_idx).key(),
                        tx_info.attr(attr_idx).value(),
                        db_batch);
                }

                if (tmblock_tm != common::kInvalidUint64) {
                    account_info->AddNewTimeBlock(
                        tmp_now_height,
                        tmblock_tm,
                        tmblock_vss_random,
                        db_batch);
                }
                
                for (int32_t storage_idx = 0;
                        storage_idx < tx_info.storages_size(); ++storage_idx) {
//                     if (tx_info.storages(storage_idx).id() != account_id) {
//                         continue;
//                     }
// 
                    if (IsInvalidKey(tx_info.storages(storage_idx).key())) {
                        continue;
                    }

                    res += account_info->SetAttrValue(
                        tx_info.storages(storage_idx).key(),
                        tx_info.storages(storage_idx).value(),
                        db_batch);
                }
            }
        }

        if (res != 0) {
            BLOCK_ERROR("SetCreateAccountHeight failed!");
            return kBlockError;
        }
    }

    return kBlockSuccess;
}

int AccountManager::GetBlockInfo(
        uint32_t pool_idx,
        uint64_t* height,
        std::string* hash,
        uint64_t* tm_height,
        uint64_t* tm_with_block_height) {
    int res = block_pools_[pool_idx]->GetHeight(height);
    if (res != kBlockSuccess) {
        BLOCK_ERROR("db_pool_info->GetHeight error pool_idx: %d", pool_idx);
        return res;
    }

    if (block_pools_[pool_idx]->GetHash(hash) != kBlockSuccess) {
        return kBlockError;
    }

    if (block_pools_[pool_idx]->GetTimeBlockHeight(
            tm_height,
            tm_with_block_height) != kBlockSuccess) {
        return kBlockError;
    }

    return kBlockSuccess;
}

void AccountManager::SetPool(
        uint32_t pool_index,
        const std::shared_ptr<bft::protobuf::Block>& block_item,
        db::DbWriteBach& db_batch) {
    uint64_t height = 0;
    if (block_pools_[pool_index]->GetHeight(&height) == block::kBlockSuccess) {
        if (height > block_item->height()) {
            return;
        }
    }

    block_pools_[pool_index]->SetHash(block_item->hash(), db_batch);
    block_pools_[pool_index]->SetHeight(block_item->height(), db_batch);
    block_pools_[pool_index]->SetTimeBlockHeight(
        block_item->timeblock_height(),
        block_item->height(),
        db_batch);
}

std::string AccountManager::GetPoolBaseAddr(uint32_t pool_index) {
    return block_pools_[pool_index]->GetBaseAddr();
}

void AccountManager::CheckMissingHeight() {
    uint32_t synced_height = 0;
    uint32_t net_id = common::GlobalInfo::Instance()->network_id();
    if (net_id >= network::kConsensusWaitingShardBeginNetworkId &&
            net_id < network::kConsensusWaitingShardEndNetworkId) {
        net_id -= network::kConsensusWaitingShardOffset;
    }
    
    std::string missing_heihts = std::to_string(net_id) + ": ";
    if (net_id >= network::kRootCongressNetworkId && net_id < network::kConsensusShardEndNetworkId) {
        for (int32_t i = (int32_t)common::kImmutablePoolSize; i >= 0; --i) {
            std::vector<uint64_t> missing_heights;
            block_pools_[i]->GetMissingHeights(&missing_heights);
            if (missing_heights.empty()) {
                continue;
            }

            synced_height += missing_heights.size();
            missing_heihts += std::to_string(i)  + ": [ ";
            for (uint32_t h_idx = 0; h_idx < missing_heights.size(); ++h_idx) {
                if (i == common::kImmutablePoolSize) {
                    sync::KeyValueSync::Instance()->AddSyncHeight(
                        network::kRootCongressNetworkId,
                        i,
                        missing_heights[h_idx],
                        sync::kSyncHighest);
                } else {
                    sync::KeyValueSync::Instance()->AddSyncHeight(
                        net_id,
                        i,
                        missing_heights[h_idx],
                        sync::kSyncHighest);
                }
                missing_heihts += std::to_string(missing_heights[h_idx]) + ", ";
            }

            if (synced_height > 64) {
                break;
            }
        }
    }

//     BLOCK_DEBUG("missing_heihts: %s", missing_heihts.c_str());
    check_missing_height_tick_.CutOff(
        kCheckMissingHeightPeriod,
        std::bind(&AccountManager::CheckMissingHeight, this));
}

void AccountManager::PrintPoolHeightTree(uint32_t pool_idx) {
    block_pools_[pool_idx]->PrintHeightTree();

}

void AccountManager::FlushPoolHeightTreeToDb() {
    for (uint32_t i = 0; i <= common::kImmutablePoolSize; ++i) {
        block_pools_[i]->FlushTreeToDb();
    }

    flush_db_tick_.CutOff(
        kFushTreeToDbPeriod,
        std::bind(&AccountManager::FlushPoolHeightTreeToDb, this));
}

void AccountManager::RefreshPoolMaxHeight() {
//     auto now_tm_sec = common::TimeUtils::TimestampSeconds();
//     if (now_tm_sec - prev_refresh_heights_tm_ > 10) {
        SendRefreshHeightsRequest();
//     }

    refresh_pool_max_height_tick_.CutOff(
        kRefreshPoolMaxHeightPeriod,
        std::bind(&AccountManager::RefreshPoolMaxHeight, this));
}

void AccountManager::SendRefreshHeightsRequest() {
    transport::protobuf::Header msg;
    dht::BaseDhtPtr dht = nullptr;
//     dht = network::DhtManager::Instance()->GetDht(
//         common::GlobalInfo::Instance()->network_id());
    uint32_t des_net_id = common::GlobalInfo::Instance()->network_id();
//     if (!dht || dht->readonly_dht()->size() < 3) {
        dht = network::UniversalManager::Instance()->GetUniversal(network::kUniversalNetworkId);
        if (des_net_id >= network::kConsensusShardEndNetworkId) {
            des_net_id -= network::kConsensusWaitingShardOffset;
        }
//     }

    msg.set_src_dht_key(dht->local_node()->dht_key());
    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_des_dht_key_hash(common::Hash::Hash64(dht_key.StrKey()));
    msg.set_priority(transport::kTransportPriorityMiddle);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_universal(false);
    msg.set_type(common::kBlockMessage);
    msg.set_hop_count(0);
    msg.set_client(false);
    block::protobuf::BlockMessage block_msg;
    auto ref_hegihts_req = block_msg.mutable_ref_heights_req();
    for (uint32_t i = 0; i <= common::kImmutablePoolSize; ++i) {
        uint64_t height = 0;
        block_pools_[i]->GetHeight(&height);
        ref_hegihts_req->add_heights(height);
    }

    msg.set_data(block_msg.SerializeAsString());
    dht->RandomSend(msg);
    BLOCK_DEBUG("sent refresh max height.");
}

void AccountManager::SendRefreshHeightsResponse(const transport::protobuf::Header& header) {
    transport::protobuf::Header msg;
    msg.set_src_dht_key(header.des_dht_key());
    msg.set_des_dht_key(header.src_dht_key());
    msg.set_priority(transport::kTransportPriorityMiddle);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_universal(false);
    msg.set_type(common::kBlockMessage);
    msg.set_hop_count(0);
    msg.set_client(false);
    block::protobuf::BlockMessage block_msg;
    auto ref_hegihts_req = block_msg.mutable_ref_heights_res();
    for (uint32_t i = 0; i <= common::kImmutablePoolSize; ++i) {
        uint64_t height = 0;
        block_pools_[i]->GetHeight(&height);
        ref_hegihts_req->add_heights(height);
    }

    msg.set_data(block_msg.SerializeAsString());
    transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
        header.from_ip(), header.from_port(), 0, msg);
}

int AccountManager::HandleRefreshHeightsReq(
        const transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg) {
    for (int32_t i = 0; i < block_msg.ref_heights_req().heights_size(); ++i) {
        block_pools_[i]->SetMaxHeight(block_msg.ref_heights_req().heights(i));
    }

    SendRefreshHeightsResponse(header);
//     prev_refresh_heights_tm_ = common::TimeUtils::TimestampSeconds();
    return kBlockSuccess;
}

int AccountManager::HandleRefreshHeightsRes(
        const transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg) {
    std::string pool_heights;
    for (int32_t i = 0; i < block_msg.ref_heights_res().heights_size(); ++i) {
        block_pools_[i]->SetMaxHeight(block_msg.ref_heights_res().heights(i));
        pool_heights += std::to_string(i) + ":" + std::to_string(block_msg.ref_heights_res().heights(i)) + ",";
    }

    BLOCK_DEBUG("HandleRefreshHeightsRes %s", pool_heights.c_str());
//     prev_refresh_heights_tm_ = common::TimeUtils::TimestampSeconds();
    return kBlockSuccess;
}

}  // namespace block

}  //namespace tenon
