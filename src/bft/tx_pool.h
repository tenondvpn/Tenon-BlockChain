#pragma once

#include <memory>
#include <map>
#include <atomic>
#include <chrono>
#include <mutex>
#include <unordered_set>
#include <vector>
#include <set>
#include <deque>

#include "common/utils.h"
#include "common/hash.h"
#include "common/global_info.h"
#include "common/user_property_key_define.h"
#include "bft/bft_utils.h"
#include "bft/bft_interface.h"
#include "network/network_utils.h"
#include "contract/contract_utils.h"

namespace lego {

namespace bft {

struct TxItem {
    TxItem(
            uint32_t in_tx_version,
            const std::string& in_gid,
            const std::string& in_from_acc_addr,
            const std::string& in_from_pubkey,
            const std::string& in_from_sign,
            const std::string& in_to_acc_addr,
            uint64_t in_lego_count,
            uint32_t type,
            uint64_t in_gas,
            uint32_t in_call_contract_step,
            const std::string& in_tx_hash)
            : tx_version(in_tx_version),
              gid(in_gid),
              from_acc_addr(in_from_acc_addr),
              from_pubkey(in_from_pubkey),
              from_sign(in_from_sign),
              to_acc_addr(in_to_acc_addr),
              lego_count(in_lego_count),
              bft_type(type),
              gas(in_gas),
            call_contract_step(in_call_contract_step),
              tx_hash(in_tx_hash) {
        delta_time = (std::chrono::steady_clock::now() +
                std::chrono::microseconds(kBftStartDeltaTime));
        time_valid += common::TimeStampUsec() + kBftStartDeltaTime;
        timeout = std::chrono::steady_clock::now() + std::chrono::microseconds(kTxPoolTimeout);
    }

    void add_attr(const std::string& key, const std::string& val) {
        attr_map[key] = val;
    }

    uint32_t tx_version{ common::kTransactionVersion };
    std::string gid;
    std::string from_acc_addr;
    std::string from_pubkey;
    std::string from_sign;
    std::string to_acc_addr;
    uint64_t lego_count{ 0 };
    uint64_t gas{ 0 };
    bool add_to_acc_addr{ false };
    // delay to wait all node ready
    std::chrono::steady_clock::time_point delta_time;
    uint64_t time_valid{ 0 };
    uint64_t index{ 0 };
    uint32_t call_contract_step{ contract::kCallStepDefault };
    std::map<std::string, std::string> attr_map;
    uint32_t bft_type{ common::kConsensusTransaction };
    std::string tx_hash;
    std::chrono::steady_clock::time_point timeout;
};

typedef std::shared_ptr<TxItem> TxItemPtr;

class TxPool {
public:
    TxPool();
    ~TxPool();

    bool GidValid(const std::string& gid);
    bool NewAddrValid(const std::string& new_addr);
    int AddTx(TxItemPtr& account_ptr);
    void GetTx(std::vector<TxItemPtr>& res_vec);
    bool TxPoolEmpty();
    bool HasTx(bool to, const std::string& tx_gid);
    TxItemPtr GetTx(bool to, const std::string& tx_gid);
    void BftOver(BftInterfacePtr& bft_ptr);
    void set_pool_index(uint32_t pool_idx) {
        pool_index_ = pool_idx;
    }

private:
    std::string GetUniqueId(const std::string& gid, bool to_add);

    static const uint32_t kKeepCoverLoadCount = 1024u;

    static std::atomic<uint64_t> pool_index_gen_;
    std::map<uint64_t, TxItemPtr> tx_pool_;
    std::unordered_map<std::string, uint64_t> added_tx_map_;
    std::unordered_set<std::string> gid_set_;
    std::deque<std::string> gid_queue_;
    std::unordered_set<std::string> new_addr_set_;
    std::deque<std::string> new_addr_queue_;
    std::mutex tx_pool_mutex_;
    uint32_t pool_index_;

    DISALLOW_COPY_AND_ASSIGN(TxPool);
};

}  // namespace bft

}  // namespace lego
