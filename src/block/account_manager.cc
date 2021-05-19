#include "stdafx.h"
#include "block/account_manager.h"

#include "common/encode.h"
#include "statistics/statistics.h"
#include "contract/contract_manager.h"
#include "db/db.h"

namespace lego {

namespace block {

AccountManager* AccountManager::Instance() {
    static AccountManager ins;
    return &ins;
}

AccountManager::AccountManager() {
    memset(network_block_,0, common::kImmutablePoolSize * sizeof(network_block_[0]));
}

AccountManager::~AccountManager() {
    for (uint32_t i = 0; i < common::kImmutablePoolSize; ++i) {
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

int AccountManager::AddBlockItem(
        const bft::protobuf::Block& block_item,
        db::DbWriteBach& db_batch) {
    const auto& tx_list = block_item.tx_list();
    if (tx_list.empty()) {
        BLOCK_ERROR("tx block tx list is empty.");
        return kBlockError;
    }
    
    // one block must be one consensus pool
    uint32_t consistent_pool_index = common::kImmutablePoolSize;
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        if (tx_list[i].to_add()) {
            if (UpdateAccountInfo(
                    tx_list[i],
                    block_item.height(),
                    block_item.timestamp(),
                    block_item.hash(),
                    db_batch) != kBlockSuccess) {
                BLOCK_ERROR("to add account failed: %s, %llu",
                        common::Encode::HexEncode(block_item.hash()).c_str(),
                        block_item.height());
                assert(false);
                continue;
            }

            uint32_t pool_idx = common::GetPoolIndex(tx_list[i].to());
            if (consistent_pool_index == common::kImmutablePoolSize) {
                consistent_pool_index = pool_idx;
            }

            if (consistent_pool_index != pool_idx) {
                BLOCK_ERROR("block pool index not consistent[%u][%u]",
                    consistent_pool_index, pool_idx);
                assert(false);
                exit(0);
            }

            std::string tx_gid = common::GetTxDbKey(false, tx_list[i].gid());
            db_batch.Put(tx_gid, block_item.hash());
        } else {
            if (UpdateAccountInfo(
                    tx_list[i],
                    block_item.height(),
                    block_item.timestamp(),
                    block_item.hash(),
                    db_batch) != kBlockSuccess) {
                BLOCK_ERROR("from add account failed: %s, %llu",
                        common::Encode::HexEncode(block_item.hash()).c_str(),
                        block_item.height());
                assert(false);
                continue;
            }

            uint32_t pool_idx = common::GetPoolIndex(tx_list[i].from());
            if (consistent_pool_index == common::kImmutablePoolSize) {
                consistent_pool_index = pool_idx;
            }

            if (consistent_pool_index != pool_idx) {
                BLOCK_ERROR("block pool index not consistent[%u][%u][%s]",
                    consistent_pool_index, pool_idx,
                    common::Encode::HexEncode(tx_list[i].from()).c_str());
                assert(false);
                exit(0);
            }

            std::string tx_gid = common::GetTxDbKey(true, tx_list[i].gid());
            db_batch.Put(tx_gid, block_item.hash());
        }
    }

    if (block_item.network_id() == common::GlobalInfo::Instance()->network_id()) {
        assert(consistent_pool_index < common::kImmutablePoolSize);
        SetPool(
            consistent_pool_index,
            block_item.height(),
            block_item.hash(),
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
        for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
            if (tx_info.attr(i).key() == bft::kContractBytesCode) {
                res += account_info->SetBytesCode(tx_info.attr(i).value(), db_batch);
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

    assert(false);
    // just sender can modify self attrs
    if ((tx_info.type() != common::kConsensusCallContract && tx_info.to_add()) ||
            (tx_info.type() == common::kConsensusCallContract &&
            tx_info.call_contract_step() == contract::kCallStepContractCalled)) {
        if (exist_height <= tmp_now_height) {
            for (int32_t attr_idx = 0; attr_idx < tx_info.attr_size(); ++attr_idx) {
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

    return kBlockSuccess;
}

int AccountManager::UpdateAccountInfo(
        const bft::protobuf::TxInfo& tx_info,
        uint64_t tmp_now_height,
        uint64_t timestamp,
        const std::string& hash,
        db::DbWriteBach& db_batch) {
    std::string account_id;
    if (tx_info.to_add()) {
        account_id = tx_info.to();
    } else {
        account_id = tx_info.from();
    }

    if (tx_info.type() == common::kConsensusCallContract) {
        switch (tx_info.call_contract_step()) {
        case contract::kCallStepCallerInited:
            account_id = tx_info.from();
            break;
        case contract::kCallStepContractLocked:
            account_id = tx_info.to();
            break;
        case contract::kCallStepContractCalled:
            account_id = tx_info.from();
            break;
        case contract::kCallStepContractFinal:
            account_id = tx_info.to();
            break;
        default:
            break;
        }
    }

    std::lock_guard<std::mutex> guard(acc_map_mutex_);
    block::DbAccountInfo* account_info = nullptr;
    auto iter = acc_map_.find(account_id);
    if (iter == acc_map_.end()) {
        account_info = new block::DbAccountInfo(account_id);
        if (!block::DbAccountInfo::AccountExists(account_id)) {
            if (tx_info.type() == common::kConsensusCreateGenesisAcount) {
                if (GenesisAddAccountInfo(account_id, db_batch, account_info) != kBlockSuccess) {
                    delete account_info;
                    return kBlockError;
                }
            } else if (tx_info.type() == common::kConsensusCreateAcount && tx_info.network_id() != 0) {
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

    if (exist_height <= tmp_now_height) {
        account_info->SetBalance(tx_info.balance(), db_batch);
    }

    account_info->NewHeight(tmp_now_height, db_batch);
    if (!tx_info.to().empty() && tx_info.amount() > 0) {
        account_info->NewTxHeight(tmp_now_height, timestamp, hash, tx_info, db_batch);
    }

    if (exist_height <= tmp_now_height) {
        account_info->SetMaxHeightHash(tmp_now_height, hash, db_batch);
    } else {
        uint64_t create_height = 0;
        if (account_info->GetCreateAccountHeight(&create_height) != block::kBlockSuccess) {
            BLOCK_ERROR("GetCreateAccountHeight failed!");
            return kBlockError;
        }

        if (create_height > tmp_now_height) {
            account_info->SetCreateAccountHeight(tmp_now_height, db_batch);
        }
    }

    if (tx_info.status() == bft::kBftSuccess) {
        int res = 0;
        if (tx_info.type() == common::kConsensusCreateContract) {
            res += account_info->SetAddressType(kContractAddress, db_batch);
            for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
                if (tx_info.attr(i).key() == bft::kContractBytesCode) {
                    res += account_info->SetBytesCode(tx_info.attr(i).value(), db_batch);
                }
            }

            res += account_info->SetAttrValue(kFieldContractOwner, tx_info.from(), db_batch);
        }

        if ((tx_info.type() != common::kConsensusCallContract && tx_info.to_add()) ||
                (tx_info.type() == common::kConsensusCallContract &&
                tx_info.call_contract_step() == contract::kCallStepContractCalled)) {
            if (exist_height <= tmp_now_height) {
                for (int32_t attr_idx = 0; attr_idx < tx_info.attr_size(); ++attr_idx) {
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
    
    if (tx_info.type() == common::kConsensusCallContract) {
        if (tx_info.call_contract_step() == contract::kCallStepContractLocked) {
            account_info->LockAccount();
        }

        if (tx_info.call_contract_step() == contract::kCallStepContractCalled) {
            account_info->UnLockAccount();
        }
    }

    return kBlockSuccess;
}

int AccountManager::GetBlockInfo(
        uint32_t pool_idx,
        uint64_t* height,
        std::string* hash) {
    std::lock_guard<std::mutex> guard(network_block_mutex_);
    if (network_block_[pool_idx] == nullptr) {
        auto db_pool_info = new block::DbPoolInfo(pool_idx);
        if (db_pool_info->GetHeight(height) != block::kBlockSuccess) {
            BLOCK_ERROR("db_pool_info->GetHeight error pool_idx: %d", pool_idx);
            delete db_pool_info;
            return kBlockError;
        }

        network_block_[pool_idx] = db_pool_info;
        return network_block_[pool_idx]->GetHash(hash);
    }

    int res = network_block_[pool_idx]->GetHeight(height);
    if (res != kBlockSuccess) {
        BLOCK_ERROR("db_pool_info->GetHeight error pool_idx: %d", pool_idx);
        return res;
    }

    return network_block_[pool_idx]->GetHash(hash);
}

void AccountManager::SetPool(
        uint32_t pool_index,
        uint64_t now_height,
        const std::string& hash,
        db::DbWriteBach& db_batch) {
    std::lock_guard<std::mutex> guard(network_block_mutex_);
    block::DbPoolInfo* db_pool_info = nullptr;
    if (network_block_[pool_index] != nullptr) {
        uint64_t height = 0;
        if (network_block_[pool_index]->GetHeight(&height) != block::kBlockSuccess) {
            return;
        }

        if (height > now_height) {
            return;
        }

        db_pool_info = network_block_[pool_index];
    } else {
        db_pool_info = new block::DbPoolInfo(pool_index);
        network_block_[pool_index] = db_pool_info;
    }

    uint64_t height = 0;
    if (db_pool_info->GetHeight(&height) == block::kBlockSuccess) {
        if (height > now_height) {
            return;
        }
    }

    db_pool_info->SetHash(hash, db_batch);
    db_pool_info->SetHeight(now_height, db_batch);
    std::string key = GetLastBlockHash(common::kTestForNetworkId, pool_index);
    db_batch.Put(key, hash);
}

}  // namespace block

}  //namespace lego
