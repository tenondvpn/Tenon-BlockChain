#include "stdafx.h"
#include "bft/tx_pool.h"

#include <cassert>

#include "bft/bft_utils.h"
#include "common/encode.h"
#include "block/account_manager.h"
#include "bft/gid_manager.h"

namespace tenon {

namespace bft {

std::atomic<uint64_t> TxPool::pool_index_gen_{ 0 };

TxPool::TxPool() {}

TxPool::~TxPool() {}

bool TxPool::GidValid(const std::string& gid) {
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    if (gid_set_.find(gid) != gid_set_.end()) {
        return false;
    }

    gid_queue_.push_back(gid);
    if (gid_queue_.size() > kKeepCoverLoadCount) {
        gid_set_.erase(gid_queue_.front());
        gid_queue_.pop_front();
    }

    gid_set_.insert(gid);
    return true;
}

bool TxPool::NewAddrValid(const std::string& new_addr) {
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    if (new_addr_set_.find(new_addr) != new_addr_set_.end()) {
        return false;
    }

    if (new_addr_queue_.size() > kKeepCoverLoadCount) {
        new_addr_set_.erase(new_addr_queue_.front());
        new_addr_queue_.pop_front();
    }

    BFT_ERROR("insert new addr : %s", common::Encode::HexEncode(new_addr).c_str());
    new_addr_set_.insert(new_addr);
    return true;
}

int TxPool::AddTx(TxItemPtr& tx_ptr) {
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
    BFT_ERROR("prepare [to: %d] [pool idx: %d] type: %d,"
        "call_contract_step: %d has tx[%s]to[%s][%s], uni_gid[%s]!",
        tx_ptr->tx.to_add(),
        pool_index_,
        tx_ptr->tx.type(),
        tx_ptr->tx.call_contract_step(),
        common::Encode::HexEncode(tx_ptr->tx.from()).c_str(),
        common::Encode::HexEncode(tx_ptr->tx.to()).c_str(),
        common::Encode::HexEncode(tx_ptr->tx.gid()).c_str(),
        common::Encode::HexEncode(uni_gid).c_str());
    return kBftSuccess;
}

void TxPool::GetTx(std::vector<TxItemPtr>& res_vec) {
    auto timestamp_now = common::TimeStampUsec();
    auto now_time = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> guard(tx_pool_mutex_);
        for (auto iter = tx_pool_.begin(); iter != tx_pool_.end();) {
            if (iter->second->timeout <= now_time) {
                tx_pool_.erase(iter++);
                BFT_ERROR("timeout and remove tx.");
                continue;
            }

            if (iter->second == nullptr) {
                ++iter;
                BFT_ERROR("iter second invalid.");
                continue;
            }


            if (iter->second->time_valid <= timestamp_now) {
                if (IsTxContractLocked(iter->second)) {
                    ++iter;
                    BFT_ERROR("IsTxContractLocked error.");
                    continue;
                }

                res_vec.push_back(iter->second);
                BFT_ERROR("get tx [to: %d] [pool idx: %d] type: %d,"
                    "call_contract_step: %d has tx[%s]to[%s][%s] tx size[%u]!",
                    iter->second->tx.to_add(),
                    pool_index_,
                    iter->second->tx.type(),
                    iter->second->tx.call_contract_step(),
                    common::Encode::HexEncode(iter->second->tx.from()).c_str(),
                    common::Encode::HexEncode(iter->second->tx.to()).c_str(),
                    common::Encode::HexEncode(iter->second->tx.gid()).c_str(),
                    res_vec.size());
                if (res_vec.size() >= kBftOneConsensusMaxCount) {
                    break;
                }
            }

            ++iter;
        }
    }

    BFT_ERROR("get tx size[%u]", res_vec.size());
    if (res_vec.size() < kBftOneConsensusMinCount) {
        res_vec.clear();
    }
}

bool TxPool::IsTxContractLocked(TxItemPtr& tx_ptr) {
    if (tx_ptr->tx.type() == common::kConsensusCallContract &&
            tx_ptr->tx.call_contract_step() == contract::kCallStepDefault) {
        auto contract_info = block::AccountManager::Instance()->GetContractInfoByAddress(
            tx_ptr->tx.to());
        assert(contract_info != nullptr);
        if (contract_info->locked()) {
            return true;
        }

        // lock contract until kCallStepContractCalled coming and unlock it
//         contract_info->LockAccount();
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
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    auto iter = added_tx_map_.find(uni_gid);
    if (iter == added_tx_map_.end()) {
        return nullptr;
    }

    auto item_iter = tx_pool_.find(iter->second);
    if (item_iter != tx_pool_.end()) {
        return item_iter->second;
    }
    return nullptr;
}

bool TxPool::TxPoolEmpty() {
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    return tx_pool_.empty();
}

void TxPool::BftOver(BftInterfacePtr& bft_ptr) {
    auto item_vec = bft_ptr->item_index_vec();
    if (bft_ptr->status() != kBftCommited) {
        return;
    }

    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    for (uint32_t i = 0; i < item_vec.size(); ++i) {
        auto iter = tx_pool_.find(item_vec[i]);
        if (iter != tx_pool_.end()) {
            tx_pool_.erase(iter);
        }
    }
}

}  // namespace bft

}  // namespace tenon
