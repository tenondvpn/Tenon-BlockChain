#include "stdafx.h"
#include "bft/tx_pool_manager.h"

#include "common/hash.h"
#include "common/string_utils.h"
#include "common/global_info.h"
#include "block/account_manager.h"
#include "election/elect_manager.h"
#include "network/network_utils.h"
#include "timeblock/time_block_utils.h"
#include "timeblock/time_block_manager.h"

namespace tenon {

namespace bft {

TxPoolManager::TxPoolManager() {
    tx_pool_ = new TxPool[common::kImmutablePoolSize + 1];
    for (uint32_t i = 0; i < common::kImmutablePoolSize + 1; ++i) {
        tx_pool_[i].set_pool_index(i);
        waiting_pools_height_[i] = 0;
    }
}

TxPoolManager::~TxPoolManager() {
    if (tx_pool_ != nullptr) {
        delete []tx_pool_;
    }
}

bool TxPoolManager::InitCheckTxValid(const bft::protobuf::BftMessage& bft_msg) {
    protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("protobuf::TxBft ParseFromString failed!");
        return false;
    }

    if (tx_bft.new_tx().type() == common::kConsensusRootTimeBlock) {
        bool tm_tx_valid = false;
        for (int32_t i = 0; i < tx_bft.new_tx().attr_size(); ++i) {
            if (tx_bft.new_tx().attr(0).key() == tmblock::kAttrTimerBlock) {
                uint64_t leader_tm = 0;
                if (!common::StringUtil::ToUint64(tx_bft.new_tx().attr(0).value(), &leader_tm)) {
                    return false;
                }

                if (!tmblock::TimeBlockManager::Instance()->BackupheckNewTimeBlockValid(leader_tm)) {
                    return false;
                }

                tm_tx_valid = true;
                break;
            }
        }

        if (!tm_tx_valid) {
            return false;
        }
    }
    if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId) {
        uint32_t network_id = 0;
        if (block::AccountManager::Instance()->GetAddressConsensusNetworkId(
                tx_bft.new_tx().from(),
                &network_id) != block::kBlockSuccess) {
            BFT_ERROR("get from addr network id failed! account address not exists[%s]",
                common::Encode::HexEncode(tx_bft.new_tx().from()).c_str());
            return false;
        }

        if (network_id != common::GlobalInfo::Instance()->network_id()) {
            BFT_ERROR("get from addr network id failed! network_id [%u] not equal local [%u]",
                network_id, common::GlobalInfo::Instance()->network_id());
            return false;
        }
    } else {
        // just check create new account
        auto account_info = block::AccountManager::Instance()->GetAcountInfo(
            tx_bft.new_tx().to());
        if (account_info != nullptr) {
            BFT_ERROR("root network create to addr failed, exists[%s]",
                common::Encode::HexEncode(tx_bft.new_tx().to()).c_str());
            return false;
        }
    }

    return true;
}

int TxPoolManager::AddTx(TxItemPtr& tx_ptr) {
    if (tx_ptr->tx.from() == tx_ptr->tx.to()) {
        BFT_ERROR("add tx from is eq to to[%s][%s]",
            common::Encode::HexEncode(tx_ptr->tx.from()).c_str(),
            common::Encode::HexEncode(tx_ptr->tx.to()).c_str());
        return kBftError;
    }

    // call contract and init
    uint32_t pool_index = common::kInvalidPoolIndex;
    if (tx_ptr->tx.type() == common::kConsensusCallContract ||
            tx_ptr->tx.type() == common::kConsensusCreateContract) {
        if (tx_ptr->tx.call_contract_step() == contract::kCallStepDefault) {
            // caller network to consensus and consume gas, no balance will fail
            if (!CheckCallerAccountInfoValid(tx_ptr->tx.from())) {
                return kBftError;
            }

            pool_index = common::GetPoolIndex(tx_ptr->tx.from());
        } else if (tx_ptr->tx.call_contract_step() == contract::kCallStepCallerInited) {
            pool_index = common::GetPoolIndex(tx_ptr->tx.to());
        } else if (tx_ptr->tx.call_contract_step() == contract::kCallStepContractCalled) {
            // just contract's network handle this message and unlock it
            if (!CheckCallerAccountInfoValid(tx_ptr->tx.from())) {
                return kBftError;
            }

            pool_index = common::GetPoolIndex(tx_ptr->tx.from());
        } else {
            return kBftError;
        }
    } else {
        if (!CheckDispatchNormalTransaction(tx_ptr)) {
            return kBftError;
        }

        if (!tx_ptr->tx.to_add()) {
            pool_index = common::GetPoolIndex(tx_ptr->tx.from());
        } else {
            pool_index = common::GetPoolIndex(tx_ptr->tx.to());
        }
    }

    return tx_pool_[pool_index].AddTx(tx_ptr);
}

bool TxPoolManager::CheckCallContractAddressValid(const std::string& contract_addr) {
    auto acc_info = block::AccountManager::Instance()->GetContractInfoByAddress(contract_addr);
    if (acc_info == nullptr) {
        BFT_ERROR("tx invalid. account address not exists[%s]",
            common::Encode::HexEncode(contract_addr).c_str());
        return false;
    }

    uint32_t network_id = 0;
    if (acc_info->GetConsensuseNetId(&network_id) != block::kBlockSuccess) {
        return false;
    }

    if (network_id != common::GlobalInfo::Instance()->network_id()) {
        return false;
    }

    return true;
}

bool TxPoolManager::CheckCallerAccountInfoValid(const std::string& caller_address) {
    if (caller_address == common::kRootChainSingleBlockTxAddress) {
        return true;
    }

    auto acc_info = block::AccountManager::Instance()->GetAcountInfo(caller_address);
    if (acc_info == nullptr) {
        if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
            return true;
        }

        BFT_ERROR("tx invalid. account address not exists[%s]",
            common::Encode::HexEncode(caller_address).c_str());
        return false;
    }

    if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId) {
        uint32_t network_id = 0;
        if (acc_info->GetConsensuseNetId(&network_id) != block::kBlockSuccess) {
            return false;
        }

        if (network_id != common::GlobalInfo::Instance()->network_id()) {
            return false;
        }
    }

    if (block::IsPoolBaseAddress(caller_address)) {
        return true;
    }

    uint64_t db_balance = 0;
    if (acc_info->GetBalance(&db_balance) != block::kBlockSuccess) {
        BFT_ERROR("tx invalid. account address not exists");
        return false;
    }

    if (db_balance <= 0) {
        BFT_ERROR("tx invalid. balance error[%lld]", db_balance);
        return false;
    }

    return true;
}

bool TxPoolManager::CheckDispatchNormalTransaction(TxItemPtr& tx_ptr) {
    if (!tx_ptr->tx.to_add()) {
        return CheckCallerAccountInfoValid(tx_ptr->tx.from());
    } else {
        if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId) {
            auto acc_info = block::AccountManager::Instance()->GetAcountInfo(tx_ptr->tx.to());
            if (acc_info == nullptr) {
                BFT_ERROR("tx invalid. account address not exists[%s]",
                    common::Encode::HexEncode(tx_ptr->tx.to()).c_str());
                return false;
            }

            uint32_t network_id = 0;
            if (acc_info->GetConsensuseNetId(&network_id) != block::kBlockSuccess) {
                BFT_ERROR("get consensus network id failed!");
                return false;
            }

            if (network_id != common::GlobalInfo::Instance()->network_id()) {
                BFT_ERROR("get consensus network id failed![%d: %d]",
                    network_id,
                    common::GlobalInfo::Instance()->network_id());
                return false;
            }
        }
    }

    return true;
}

TxItemPtr TxPoolManager::GetRootTx() {
    std::lock_guard<std::mutex> guard(waiting_pools_mutex_);
    if (tx_pool_[common::kRootChainPoolIndex].TxPoolEmpty()) {
        return nullptr;
    }

    if (root_tx_pool_valid_) {
        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm_height;
        uint64_t tm_with_block_height;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            common::kRootChainPoolIndex,
            &pool_height,
            &pool_hash,
            &tm_height,
            &tm_with_block_height);
        if (res != block::kBlockSuccess) {
            BFT_ERROR("TxPoolEmpty tx add i: %d, waiting_pools_.Valid(i): %u,"
                "tx_pool_.empty(): %u, res: %d",
                common::kRootChainPoolIndex,
                root_tx_pool_valid_ == true ? 1 : 0,
                tx_pool_[common::kRootChainPoolIndex].TxPoolEmpty(),
                res);
            return nullptr;
        }


        if (pool_height < waiting_pools_height_[common::kRootChainPoolIndex]) {
            return nullptr;
        }

        root_tx_pool_valid_ = false;
        waiting_pools_height_[common::kRootChainPoolIndex] = pool_height;
        std::vector<TxItemPtr> res_vec;
        tx_pool_[common::kRootChainPoolIndex].GetTx(res_vec);
        assert(res_vec.size() <= 1);
        if (res_vec.empty()) {
            root_tx_pool_valid_ = true;
            return nullptr;
        }

        return res_vec[0];
    }

    return nullptr;
}

void TxPoolManager::GetTx(
        uint32_t& pool_index,
        int32_t pool_mod_idx,
        std::vector<TxItemPtr>& res_vec) {
    int valid_pool = -1;
    uint64_t height = 0;
    int32_t leader_count = elect::ElectManager::Instance()->GetNetworkLeaderCount(
        common::GlobalInfo::Instance()->network_id());
    std::lock_guard<std::mutex> guard(waiting_pools_mutex_);
    for (int32_t i = prev_pool_index_; i < (int32_t)common::kImmutablePoolSize; ++i) {
        if (i % leader_count != pool_mod_idx) {
            continue;
        }

        if (!waiting_pools_.Valid(i) && !tx_pool_[i].TxPoolEmpty()) {
            std::string pool_hash;
            uint64_t pool_height = 0;
            uint64_t tm_height;
            uint64_t tm_with_block_height;
            uint32_t last_pool_index = common::kImmutablePoolSize;
            int res = block::AccountManager::Instance()->GetBlockInfo(
                i,
                &pool_height,
                &pool_hash,
                &tm_height,
                &tm_with_block_height);
            if (res != block::kBlockSuccess) {
                BFT_ERROR("TxPoolEmpty tx add i: %d, waiting_pools_.Valid(i): %u,"
                    "tx_pool_.empty(): %u, res: %d",
                    i, waiting_pools_.Valid(i), tx_pool_[i].TxPoolEmpty(), res);
                continue;
            }

            height = pool_height;
            waiting_pools_.Set(i);
            valid_pool = i;
            break;
        }
    }

    if (valid_pool < 0) {
        for (int32_t i = 0; i < (int32_t)prev_pool_index_; ++i) {
            if (i % leader_count != pool_mod_idx) {
                continue;
            }

            if (!waiting_pools_.Valid(i) && !tx_pool_[i].TxPoolEmpty()) {
                std::string pool_hash;
                uint64_t pool_height = 0;
                uint64_t tm_height;
                uint64_t tm_with_block_height;
                uint32_t last_pool_index = common::kInvalidPoolIndex;
                int res = block::AccountManager::Instance()->GetBlockInfo(
                    i,
                    &pool_height,
                    &pool_hash,
                    &tm_height,
                    &tm_with_block_height);
                if (res != block::kBlockSuccess) {
                    BFT_ERROR("TxPoolEmpty tx add i: %d, waiting_pools_.Valid(i): %u,"
                        "tx_pool_.empty(): %u, res: %d",
                        i, waiting_pools_.Valid(i), tx_pool_[i].TxPoolEmpty(), res);
                    continue;
                }

                height = pool_height;
                waiting_pools_.Set(i);
                valid_pool = i;
                break;
            }
        }
    }

    if (valid_pool < 0) {
        return;
    }

    if (height < waiting_pools_height_[valid_pool]) {
        return;
    }

    tx_pool_[valid_pool].GetTx(res_vec);
//     BFT_DEBUG("pool index: %d get tx size: %u", valid_pool, res_vec.size());
    if (res_vec.empty()) {
        waiting_pools_.UnSet(valid_pool);
        return;
    }

    waiting_pools_height_[valid_pool] = height;
    pool_index = valid_pool;
    prev_pool_index_ = (valid_pool + 1) % common::kInvalidPoolIndex;
}

TxItemPtr TxPoolManager::GetTx(
        uint32_t pool_index,
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid) {
    assert(pool_index < common::kInvalidPoolIndex);
    return tx_pool_[pool_index].GetTx(add_to, tx_type, call_contract_step, gid);
}

void TxPoolManager::RemoveTx(
        uint32_t pool_index,
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid) {
    assert(pool_index < common::kInvalidPoolIndex);
    tx_pool_[pool_index].RemoveTx(add_to, tx_type, call_contract_step, gid);
}

void TxPoolManager::BftOver(BftInterfacePtr& bft_ptr) {
    assert(bft_ptr->pool_index() < common::kInvalidPoolIndex);
    tx_pool_[bft_ptr->pool_index()].BftOver(bft_ptr);
    std::lock_guard<std::mutex> guard(waiting_pools_mutex_);
//     if (bft_ptr->prpare_block()) {
//         if (bft_ptr->prpare_block()->height() ==
//                 (waiting_pools_height_[bft_ptr->pool_index()] + 1)) {
            if (bft_ptr->pool_index() == common::kRootChainPoolIndex) {
                root_tx_pool_valid_ = true;
            } else {
                waiting_pools_.UnSet(bft_ptr->pool_index());
            }

//             BFT_DEBUG("bft over pool index: %d", bft_ptr->pool_index());
//         }
//     }
}

void TxPoolManager::CheckTimeoutTx() {
    for (uint32_t i = 0; i < common::kImmutablePoolSize + 1; ++i) {
        tx_pool_[i].CheckTimeoutTx();
    }
}

}  // namespace bft

}  // namespace bft
