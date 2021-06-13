#include "stdafx.h"
#include "block/account_manager.h"

#include "common/encode.h"
#include "statistics/statistics.h"
#include "contract/contract_manager.h"
#include "db/db.h"
#include "election/member_manager.h"
#include "election/proto/elect.pb.h"
#include "election/elect_manager.h"
#include "timeblock/time_block_utils.h"
#include "timeblock/time_block_manager.h"

namespace tenon {

namespace block {

AccountManager* AccountManager::Instance() {
    static AccountManager ins;
    return &ins;
}

AccountManager::AccountManager() {
    memset(network_block_,0, (common::kImmutablePoolSize + 1) * sizeof(network_block_[0]));
}

AccountManager::~AccountManager() {
    for (uint32_t i = 0; i < common::kImmutablePoolSize + 1; ++i) {
        if (network_block_[i] != nullptr) {
            delete network_block_[i];
        }
    }
}

bool AccountManager::AccountExists(const std::string& acc_id) {
    {
        std::lock_guard<std::mutex> guard(acc_map_mutex_);
        auto iter = acc_map_.find(acc_id);
        if (iter != acc_map_.end()) {
            return true;
        }
    }

    if (DbAccountInfo::AccountExists(acc_id)) {
        auto account_info = new block::DbAccountInfo(acc_id);
        std::lock_guard<std::mutex> guard(acc_map_mutex_);
        acc_map_[acc_id] = account_info;
        return true;
    }

    return false;
}

DbAccountInfo* AccountManager::GetAcountInfo(const std::string& acc_id) {
    {
        std::lock_guard<std::mutex> guard(acc_map_mutex_);
        auto iter = acc_map_.find(acc_id);
        if (iter != acc_map_.end()) {
            return iter->second;
        }
    }

    if (DbAccountInfo::AccountExists(acc_id)) {
        auto account_info = new block::DbAccountInfo(acc_id);
        std::lock_guard<std::mutex> guard(acc_map_mutex_);
        acc_map_[acc_id] = account_info;
        return account_info;
    }

    return nullptr;
}

DbAccountInfo* AccountManager::GetContractInfoByAddress(const std::string& address) {
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

int AccountManager::HandleElectBlock(uint64_t height, const bft::protobuf::TxInfo& tx_info) {
    if (tx_info.network_id() == common::GlobalInfo::Instance()->network_id() ||
            tx_info.network_id() + network::kConsensusWaitingShardOffset ==
            common::GlobalInfo::Instance()->network_id()) {
        elect::protobuf::ElectBlock elect_block;
        for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
            if (tx_info.attr(i).key() == elect::kElectNodeAttrElectBlock) {
                elect_block.ParseFromString(tx_info.attr(i).value());
            }
        }

        if (!elect_block.IsInitialized()) {
            return kBlockError;
        }

        elect::ElectManager::Instance()->ProcessNewElectBlock(height, elect_block, false);
    }

    return kBlockSuccess;
}

int AccountManager::HandleTimeBlock(uint64_t height, const bft::protobuf::TxInfo& tx_info) {
    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        if (tx_info.attr(i).key() == tmblock::kAttrTimerBlock) {
            tmblock::TimeBlockManager::Instance()->UpdateTimeBlock(
                height,
                common::StringUtil::ToUint64(tx_info.attr(i).value()));
        }
    }

    return kBlockSuccess;
}

int AccountManager::HandleRootSingleBlockTx(
        uint64_t height,
        const bft::protobuf::TxInfo& tx_info) {
    switch (tx_info.type()) {
    case common::kConsensusRootElectRoot:
    case common::kConsensusRootElectShard:
        return HandleElectBlock(height, tx_info);
    case common::kConsensusRootTimeBlock:
        return HandleTimeBlock(height, tx_info);
        break;
    case common::kConsensusRootVssBlock:
        break;
    default:
        break;
    }

    return kBlockSuccess;
}

int AccountManager::AddBlockItem(
        const std::shared_ptr<bft::protobuf::Block>& block_item,
        db::DbWriteBach& db_batch) {
    const auto& tx_list = block_item->tx_list();
    if (tx_list.empty()) {
        BLOCK_ERROR("tx block tx list is empty.");
        return kBlockError;
    }
    
    // one block must be one consensus pool
    uint32_t consistent_pool_index = common::kInvalidPoolIndex;
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        if (bft::IsRootSingleBlockTx(tx_list[i].type())) {
            if (HandleRootSingleBlockTx(block_item->height(), tx_list[i]) != kBlockSuccess) {
                return kBlockError;
            }
        }

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

        if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId) {
            std::string account_gid;
            if (tx_list[i].type() != common::kConsensusCallContract &&
                    tx_list[i].type() != common::kConsensusCreateContract) {
                if (tx_list[i].to_add()) {
                    account_gid = tx_list[i].to() + tx_list[i].gid();
                } else {
                    account_gid = tx_list[i].from() + tx_list[i].gid();
                }
            } else {
                if (tx_list[i].call_contract_step() == contract::kCallStepContractCalled) {
                    account_gid = tx_list[i].to() + tx_list[i].gid();
                } else if (tx_list[i].call_contract_step() == contract::kCallStepContractFinal) {
                    account_gid = tx_list[i].from() + tx_list[i].gid();
                }
            }
            
            if (!account_gid.empty()) {
                db_batch.Put(account_gid, block_item->hash());
            }
        }
    }

    if (block_item->network_id() == common::GlobalInfo::Instance()->network_id() ||
            consistent_pool_index == common::kRootChainPoolIndex) {
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
    block::DbAccountInfo* account_info = nullptr;
    auto iter = acc_map_.find(account_id);
    if (iter != acc_map_.end()) {
        return kBlockSuccess;
    }

    if (block::DbAccountInfo::AccountExists(account_id)) {
        return kBlockSuccess;
    }

    if (tx_info.amount() == 0 && tx_info.type() != common::kConsensusCreateContract) {
        return kBlockSuccess;
    }

    account_info = new block::DbAccountInfo(account_id);
    if (!block::DbAccountInfo::AddNewAccountToDb(account_id, db_batch)) {
        BLOCK_ERROR("fromAddNewAccountToDb failed: %s, %llu",
                common::Encode::HexEncode(account_id).c_str());
        return kBlockError;
    }

    account_info->SetMaxHeightHash(tmp_now_height, create_hash, db_batch);
    account_info->NewHeight(tmp_now_height, db_batch);
    int res = account_info->SetBalance(0, db_batch);
    res += account_info->SetCreateAccountHeight(tmp_now_height, db_batch);
    if (res != 0) {
        BLOCK_ERROR("SetCreateAccountHeight failed: %s, %llu",
            common::Encode::HexEncode(account_id).c_str());
        return kBlockError;
    }

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
        BLOCK_ERROR("SetOutLego failed: %s, %llu",
            common::Encode::HexEncode(account_id).c_str());
        return kBlockError;
    }

    acc_map_[account_id] = account_info;
    uint64_t exist_height = 0;
    if (account_info->GetMaxHeight(&exist_height) != block::kBlockSuccess) {
        BLOCK_ERROR("GetMaxHeight failed!");
        return kBlockError;
    }

    uint64_t create_height = 0;
    if (account_info->GetCreateAccountHeight(&create_height) != block::kBlockSuccess) {
        BLOCK_ERROR("GetCreateAccountHeight failed!");
        return kBlockError;
    }

    account_info->NewHeight(tmp_now_height, db_batch);
    if (SetAccountAttrs(
            account_id,
            tx_info,
            exist_height,
            tmp_now_height,
            account_info,
            db_batch) != kBlockSuccess) {
        return kBlockError;
    }

    if (exist_height <= tmp_now_height) {
        res += account_info->SetMaxHeightHash(tmp_now_height, create_hash, db_batch);
    } else {
        if (create_height > tmp_now_height) {
            res += account_info->SetCreateAccountHeight(tmp_now_height, db_batch);
        }
    }

    if (res != 0) {
        BLOCK_ERROR("SetCreateAccountHeight failed!");
        return kBlockError;
    }

    return kBlockSuccess;
}

int AccountManager::GenesisAddAccountInfo(
        const std::string& account_id,
        db::DbWriteBach& db_batch,
        block::DbAccountInfo* account_info) {
    if (!block::DbAccountInfo::AddNewAccountToDb(account_id, db_batch)) {
        BLOCK_ERROR("fromAddNewAccountToDb failed: %s, %llu",
            common::Encode::HexEncode(account_id).c_str());
        return kBlockError;
    }

    account_info->SetMaxHeightHash(0, "", db_batch);
    account_info->NewHeight(0, db_batch);
    int res = account_info->SetBalance(0, db_batch);
    res += account_info->SetCreateAccountHeight(0, db_batch);
    if (res != 0) {
        BLOCK_ERROR("SetCreateAccountHeight failed: %s, %llu",
            common::Encode::HexEncode(account_id).c_str());
        return kBlockError;
    }

    if (res != kBlockSuccess) {
        BLOCK_ERROR("SetOutLego failed: %s, %llu",
            common::Encode::HexEncode(account_id).c_str());
        return kBlockError;
    }

    BLOCK_DEBUG("genesis add new block account[%s].", common::Encode::HexEncode(account_id).c_str());
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

    std::lock_guard<std::mutex> guard(acc_map_mutex_);
    block::DbAccountInfo* account_info = nullptr;
    auto iter = acc_map_.find(account_id);
    if (iter == acc_map_.end()) {
        account_info = new block::DbAccountInfo(account_id);
        if (!block::DbAccountInfo::AccountExists(account_id)) {
            if (tx_info.type() == common::kConsensusCreateGenesisAcount ||
                    bft::IsRootSingleBlockTx(tx_info.type())) {
                if (GenesisAddAccountInfo(account_id, db_batch, account_info) != kBlockSuccess) {
                    delete account_info;
                    return kBlockError;
                }
            } else if (tx_info.type() == common::kConsensusCreateAcount &&
                    tx_info.network_id() != 0) {
            } else {
                BLOCK_ERROR("account id not exists[%s]!",
                    common::Encode::HexEncode(account_id).c_str());
                delete account_info;
                return kBlockError;
            }

            account_info->SetConsensuseNetid(tx_info.network_id(), db_batch);
        }

        acc_map_[account_id] = account_info;
    } else {
        account_info = iter->second;
    }

    uint64_t exist_height = 0;
    if (account_info->GetMaxHeight(&exist_height) != block::kBlockSuccess) {
        BLOCK_ERROR("GetMaxHeight failed!");
        return kBlockError;
    }

    account_info->NewHeight(block_item->height(), db_batch);
    if (!tx_info.to().empty() && tx_info.amount() > 0) {
        account_info->NewTxHeight(
            block_item->height(),
            block_item->timestamp(),
            block_item->hash(),
            tx_info,
            db_batch);
    }

    if (exist_height <= block_item->height()) {
        account_info->SetMaxHeightHash(block_item->height(), block_item->hash(), db_batch);
    } else {
        uint64_t create_height = 0;
        if (account_info->GetCreateAccountHeight(&create_height) != block::kBlockSuccess) {
            BLOCK_ERROR("GetCreateAccountHeight failed!");
            return kBlockError;
        }

        if (create_height > block_item->height()) {
            account_info->SetCreateAccountHeight(block_item->height(), db_batch);
        }
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
            account_info,
            db_batch) != kBlockSuccess) {
        return kBlockError;
    }

//     if (IsPoolBaseAddress(account_id)) {
//         if (account_info->AddStatistic(block_item) != kBlockSuccess) {
//             return kBlockError;
//         }
//     }
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

//     if (key == kFieldContractOwner) {
//         return true;
//     }

//     if (key == kFieldFullAddress) {
//         return true;
//     }

    return false;
}

int AccountManager::SetAccountAttrs(
        const std::string& account_id,
        const bft::protobuf::TxInfo& tx_info,
        uint64_t exist_height,
        uint64_t tmp_now_height,
        block::DbAccountInfo* account_info,
        db::DbWriteBach& db_batch) {
//     if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
//         return kBlockSuccess;
//     }
// 

    if (tx_info.status() == bft::kBftSuccess) {
        int res = 0;
        if (tx_info.type() == common::kConsensusCreateContract && tx_info.to_add() && account_id == tx_info.to()) {
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
                for (int32_t attr_idx = 0; attr_idx < tx_info.attr_size(); ++attr_idx) {
                    if (tx_info.type() == common::kConsensusRootElectShard ||
                            tx_info.type() == common::kConsensusRootElectRoot) {
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
                            account_info->AddNewTimeBlock(
                                tmp_now_height,
                                common::StringUtil::ToUint64(tx_info.attr(attr_idx).value()),
                                db_batch);
                        }
                    }

                    if (IsInvalidKey(tx_info.attr(attr_idx).key())) {
                        continue;
                    }

                    res += account_info->SetAttrWithHeight(
                        tx_info.attr(attr_idx).key(),
                        tmp_now_height,
                        db_batch);
                    res += account_info->SetAttrValue(
                        tx_info.attr(attr_idx).key(),
                        tx_info.attr(attr_idx).value(),
                        db_batch);
                }

                for (int32_t storage_idx = 0;
                        storage_idx < tx_info.storages_size(); ++storage_idx) {
                    if (tx_info.storages(storage_idx).id() != account_id) {
                        continue;
                    }

                    if (IsInvalidKey(tx_info.storages(storage_idx).key())) {
                        continue;
                    }

                    res += account_info->SetAttrWithHeight(
                        tx_info.storages(storage_idx).key(),
                        tmp_now_height,
                        db_batch);
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
    std::lock_guard<std::mutex> guard(network_block_mutex_);
    if (network_block_[pool_idx] == nullptr) {
        auto db_pool_info = new block::DbPoolInfo(pool_idx);
        if (db_pool_info->GetHeight(height) != kBlockSuccess) {
            BLOCK_ERROR("db_pool_info->GetHeight error pool_idx: %d", pool_idx);
            delete db_pool_info;
            return kBlockError;
        }

        network_block_[pool_idx] = db_pool_info;
        if (network_block_[pool_idx]->GetHash(hash) != kBlockSuccess) {
            return kBlockError;
        }

        if (network_block_[pool_idx]->GetTimeBlockHeight(
                tm_height,
                tm_with_block_height) != kBlockSuccess) {
            return kBlockError;
        }

        return kBlockSuccess;
    }

    int res = network_block_[pool_idx]->GetHeight(height);
    if (res != kBlockSuccess) {
        BLOCK_ERROR("db_pool_info->GetHeight error pool_idx: %d", pool_idx);
        return res;
    }

    if (network_block_[pool_idx]->GetHash(hash) != kBlockSuccess) {
        return kBlockError;
    }

    if (network_block_[pool_idx]->GetTimeBlockHeight(
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
    std::lock_guard<std::mutex> guard(network_block_mutex_);
    block::DbPoolInfo* db_pool_info = nullptr;
    if (network_block_[pool_index] != nullptr) {
        uint64_t height = 0;
        if (network_block_[pool_index]->GetHeight(&height) != block::kBlockSuccess) {
            return;
        }

        if (height > block_item->height()) {
            return;
        }

        db_pool_info = network_block_[pool_index];
    } else {
        db_pool_info = new block::DbPoolInfo(pool_index);
        network_block_[pool_index] = db_pool_info;
    }

    uint64_t height = 0;
    if (db_pool_info->GetHeight(&height) == block::kBlockSuccess) {
        if (height > block_item->height()) {
            return;
        }
    }

    db_pool_info->SetHash(block_item->hash(), db_batch);
    db_pool_info->SetHeight(block_item->height(), db_batch);
    db_pool_info->SetTimeBlockHeight(
        block_item->timeblock_height(),
        block_item->height(),
        db_batch);
}

std::string AccountManager::GetPoolBaseAddr(uint32_t pool_index) {
    std::lock_guard<std::mutex> guard(network_block_mutex_);
    if (network_block_[pool_index] != nullptr) {
        return network_block_[pool_index]->GetBaseAddr();
    }

    return "";
}

}  // namespace block

}  //namespace tenon
