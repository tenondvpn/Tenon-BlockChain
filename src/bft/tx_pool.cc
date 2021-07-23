#include "stdafx.h"
#include "bft/tx_pool.h"

#include <cassert>

#include "bft/bft_utils.h"
#include "common/encode.h"
#include "common/time_utils.h"
#include "block/account_manager.h"
#include "bft/gid_manager.h"
#include "timeblock/time_block_utils.h"
#include "timeblock/time_block_manager.h"

namespace tenon {

namespace bft {

std::atomic<uint64_t> TxPool::pool_index_gen_{ 0 };

TxPool::TxPool() {}

TxPool::~TxPool() {}

int TxPool::AddTx(TxItemPtr tx_ptr) {
    assert(tx_ptr != nullptr);
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    std::string uni_gid = GidManager::Instance()->GetUniversalGid(
        tx_ptr->tx.to_add(),
        tx_ptr->tx.type(),
        tx_ptr->tx.call_contract_step(),
        tx_ptr->tx.gid());
    auto iter = added_tx_map_.find(uni_gid);
    if (iter != added_tx_map_.end()) {
        BFT_ERROR("gid exists: %s, tx_ptr->add_to_acc_addr: %d.",
            common::Encode::HexEncode(uni_gid).c_str(), tx_ptr->tx.to_add());
        return kBftTxAdded;
    }

    uint64_t tx_index = pool_index_gen_.fetch_add(1);
    added_tx_map_.insert(std::make_pair(uni_gid, tx_index));
    tx_pool_[tx_index] = tx_ptr;
    tx_ptr->index = tx_index;
    BFT_DEBUG("add new tx tx index: %lu, [to: %d] [pool idx: %d] type: %d,"
        "call_contract_step: %d has tx[%s]to[%s][%s], uni_gid[%s], now tx size: %d!",
        tx_index,
        tx_ptr->tx.to_add(),
        pool_index_,
        tx_ptr->tx.type(),
        tx_ptr->tx.call_contract_step(),
        common::Encode::HexEncode(tx_ptr->tx.from()).c_str(),
        common::Encode::HexEncode(tx_ptr->tx.to()).c_str(),
        common::Encode::HexEncode(tx_ptr->tx.gid()).c_str(),
        common::Encode::HexEncode(uni_gid).c_str(),
        tx_pool_.size());
    return kBftSuccess;
}

void TxPool::GetTx(std::vector<TxItemPtr>& res_vec) {
    auto timestamp_now = common::TimeUtils::TimestampUs();
    {
        std::lock_guard<std::mutex> guard(tx_pool_mutex_);
        for (auto iter = tx_pool_.begin(); iter != tx_pool_.end();) {
            if (!IsTxValid(iter->second)) {
                tx_pool_.erase(iter++);
                BFT_ERROR("timeout and remove tx.");
                continue;
            }

            if (iter->second->time_valid <= timestamp_now) {
                if (IsTxContractLocked(iter->second)) {
                    ++iter;
                    BFT_ERROR("IsTxContractLocked error.");
                    continue;
                }

                // root single block tx must just one tx
                if (!res_vec.empty() && IsShardSingleBlockTx(iter->second->tx.type())) {
                    break;
                }

                res_vec.push_back(iter->second);
//                 BFT_DEBUG("get tx [to: %d] [pool idx: %d] type: %d,"
//                     "call_contract_step: %d has tx[%s]to[%s][%s] tx size[%u]!\n",
//                     iter->second->tx.to_add(),
//                     pool_index_,
//                     iter->second->tx.type(),
//                     iter->second->tx.call_contract_step(),
//                     common::Encode::HexEncode(iter->second->tx.from()).c_str(),
//                     common::Encode::HexEncode(iter->second->tx.to()).c_str(),
//                     common::Encode::HexEncode(iter->second->tx.gid()).c_str(),
//                     res_vec.size());
                if (IsShardSingleBlockTx(iter->second->tx.type())) {
                    break;
                }

                if (res_vec.size() >= kBftOneConsensusMaxCount) {
                    break;
                }
            }

            ++iter;
        }
    }

//     BFT_DEBUG("get tx size[%u]", res_vec.size());
    if (res_vec.size() < kBftOneConsensusMinCount) {
        res_vec.clear();
    }
}

bool TxPool::IsTxValid(TxItemPtr tx_ptr) {
    auto now_time = std::chrono::steady_clock::now();
    if (tx_ptr->timeout <= now_time) {
        BFT_ERROR("timeout and remove tx: %s", common::Encode::HexEncode(tx_ptr->tx.gid()).c_str());
        return false;
    }

    if (!tx_ptr) {
        BFT_ERROR("iter second invalid.");
        return false;
    }

    if (tx_ptr->tx.type() == common::kConsensusRootTimeBlock) {
        for (int32_t i = 0; i < tx_ptr->tx.attr_size(); ++i) {
            if (tx_ptr->tx.attr(i).key() == tmblock::kAttrTimerBlock) {
                uint64_t tmblock_tm = 0;
                if (!common::StringUtil::ToUint64(tx_ptr->tx.attr(i).value(), &tmblock_tm)) {
                    return false;
                }

                if (tmblock_tm < tmblock::TimeBlockManager::Instance()->LatestTimestamp()) {
                    return false;
                }

                return true;
            }
        }

        return false;
    }

    return true;
}

bool TxPool::IsTxContractLocked(TxItemPtr tx_ptr) {
    if (tx_ptr->tx.to_add()) {
        return false;
    }

    if (common::IsBaseAddress(tx_ptr->tx.from())) {
        return false;
    }

    if (tx_ptr->tx.type() == common::kConsensusCallContract &&
        tx_ptr->tx.call_contract_step() == contract::kCallStepContractCalled) {
        return false;
    }

    auto contract_info = block::AccountManager::Instance()->GetAcountInfo(
        tx_ptr->tx.from());
    if (contract_info == nullptr) {
        BFT_ERROR("account address not exists: %s, type: %d",
            common::Encode::HexEncode(tx_ptr->tx.from()).c_str(),
            tx_ptr->tx.type());
        assert(contract_info != nullptr);
        return false;
    }

    if (contract_info->locked()) {
        return true;
    }

    return false;
}

TxItemPtr TxPool::GetTx(
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid) {
    std::string uni_gid = GidManager::Instance()->GetUniversalGid(
        add_to,
        tx_type,
        call_contract_step,
        gid);
//     BFT_DEBUG("prepare [to: %d] [pool idx: %d] type: %d,"
//         "call_contract_step: %d get tx[%s]to[%s][%s], uni_gid[%s]!",
//         add_to,
//         pool_index_,
//         tx_type,
//         call_contract_step,
//         "",
//         "",
//         common::Encode::HexEncode(gid).c_str(),  
//         common::Encode::HexEncode(uni_gid).c_str());
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    auto iter = added_tx_map_.find(uni_gid);
    if (iter == added_tx_map_.end()) {
        BFT_ERROR("prepare [to: %d] [pool idx: %d] type: %d,"
            "call_contract_step: %d not has tx[%s]to[%s][%s], uni_gid[%s]!",
            add_to,
            pool_index_,
            tx_type,
            call_contract_step,
            "",
            "",
            common::Encode::HexEncode(gid).c_str(),
            common::Encode::HexEncode(uni_gid).c_str());
        return nullptr;
    }

    auto item_iter = tx_pool_.find(iter->second);
    if (item_iter != tx_pool_.end()) {
//         BFT_DEBUG("prepare [to: %d] [pool idx: %d] type: %d,"
//             "call_contract_step: %d got tx[%s]to[%s][%s], uni_gid[%s]!",
//             add_to,
//             pool_index_,
//             tx_type,
//             call_contract_step,
//             "",
//             "",
//             common::Encode::HexEncode(gid).c_str(),
//             common::Encode::HexEncode(uni_gid).c_str());
        return item_iter->second;
    }

    BFT_ERROR("prepare [to: %d] [pool idx: %d] type: %d,"
        "call_contract_step: %d not has tx[%s]to[%s][%s], uni_gid[%s]!",
        add_to,
        pool_index_,
        tx_type,
        call_contract_step,
        "",
        "",
        common::Encode::HexEncode(gid).c_str(),
        common::Encode::HexEncode(uni_gid).c_str());
    return nullptr;
}

void TxPool::RemoveTx(
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid) {
    std::string uni_gid = GidManager::Instance()->GetUniversalGid(
        add_to,
        tx_type,
        call_contract_step,
        gid);
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    auto iter = added_tx_map_.find(uni_gid);
    if (iter == added_tx_map_.end()) {
        return;
    }

    auto item_iter = tx_pool_.find(iter->second);
    if (item_iter != tx_pool_.end()) {
        BFT_ERROR("RemoveTx [to: %d] [pool idx: %d] type: %d,"
            "call_contract_step: %d not has tx[%s]to[%s][%s], uni_gid[%s]!",
            add_to,
            pool_index_,
            tx_type,
            call_contract_step,
            "",
            "",
            common::Encode::HexEncode(gid).c_str(),
            common::Encode::HexEncode(uni_gid).c_str());
        tx_pool_.erase(item_iter);
    }
}

bool TxPool::TxPoolEmpty() {
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    return tx_pool_.empty();
}

void TxPool::BftOver(BftInterfacePtr& bft_ptr) {
    auto item_vec = bft_ptr->item_index_vec();
//     BFT_DEBUG("bft over called pool index: %d, status: %d., remove tx index size: %d",
//         pool_index_, bft_ptr->status(), item_vec.size());
    if (bft_ptr->status() != kBftCommited && bft_ptr->status() != kBftStepTimeout) {
        return;
    }

    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    for (uint32_t i = 0; i < item_vec.size(); ++i) {
        auto iter = tx_pool_.find(item_vec[i]);
        if (iter != tx_pool_.end()) {
//             BFT_DEBUG("remove tx tx index: %lu, from: %s, to: %s, gid: %s, amount: %lu.",
//                 item_vec[i],
//                 common::Encode::HexEncode(iter->second->tx.from()).c_str(),
//                 common::Encode::HexEncode(iter->second->tx.to()).c_str(),
//                 common::Encode::HexEncode(iter->second->tx.gid()).c_str(),
//                 iter->second->tx.amount());
            tx_pool_.erase(iter);
        }
    }
}

}  // namespace bft

}  // namespace tenon
