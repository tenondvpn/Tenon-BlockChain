#include "stdafx.h"
#include "bft/tx_pool.h"

#include <cassert>

#include "bft/bft_utils.h"
#include "common/encode.h"

namespace lego {

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

std::string TxPool::GetUniqueId(const std::string& gid, bool to_add) {
    if (to_add) {
        return std::to_string(common::GlobalInfo::Instance()->network_id()) + "_t_" + gid;
    } else {
        return std::to_string(common::GlobalInfo::Instance()->network_id()) + "_" + gid;
    }
}

int TxPool::AddTx(TxItemPtr& tx_ptr) {
    assert(tx_ptr != nullptr);
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    std::string uni_gid = GetUniqueId(tx_ptr->gid, tx_ptr->add_to_acc_addr);
    auto iter = added_tx_map_.find(uni_gid);
    if (iter != added_tx_map_.end()) {
        BFT_ERROR("gid exists: %s, tx_ptr->add_to_acc_addr: %d.",
            common::Encode::HexEncode(uni_gid).c_str(), tx_ptr->add_to_acc_addr);
        return kBftTxAdded;
    }

    uint64_t tx_index = pool_index_gen_.fetch_add(1);
    added_tx_map_.insert(std::make_pair(uni_gid, tx_index));
    tx_pool_[tx_index] = tx_ptr;
    tx_ptr->index = tx_index;
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
                continue;
            }

            if (iter->second == nullptr) {
                ++iter;
                continue;
            }


            if (iter->second->time_valid <= timestamp_now) {
                res_vec.push_back(iter->second);
                if (res_vec.size() >= kBftOneConsensusMaxCount) {
                    break;
                }
            }

            ++iter;
        }
    }

    if (res_vec.size() < kBftOneConsensusMinCount) {
        res_vec.clear();
    }
}

bool TxPool::HasTx(bool to, const std::string& tx_gid) {
    std::string uni_gid = GetUniqueId(tx_gid, to);
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    auto iter = added_tx_map_.find(uni_gid);
    return iter != added_tx_map_.end();
}

TxItemPtr TxPool::GetTx(bool to, const std::string& tx_gid) {
    std::string uni_gid = GetUniqueId(tx_gid, to);
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

}  // namespace lego
