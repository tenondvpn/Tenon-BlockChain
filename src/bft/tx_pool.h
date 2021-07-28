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
#include "common/time_utils.h"
#include "bft/bft_utils.h"
#include "bft/bft_interface.h"
#include "bft/proto/bft.pb.h"
#include "network/network_utils.h"
#include "contract/contract_utils.h"

namespace tenon {

namespace bft {

struct TxItem {
    TxItem(const protobuf::TxInfo& in_tx)
            : tx(in_tx) {
        delta_time = (std::chrono::steady_clock::now() +
            std::chrono::microseconds(kBftStartDeltaTime));
        switch (tx.type()) {
        case common::kConsensusFinalStatistic:
            time_valid = common::TimeUtils::TimestampUs() + kBftFinalStatisticStartDeltaTime;
            timeout = std::chrono::steady_clock::now() + std::chrono::seconds(kTxPoolFinalStatisticTimeoutSeconds);
            break;
        case common::kConsensusRootElectShard:
            time_valid = common::TimeUtils::TimestampUs() + kBftElectionStartDeltaTime;
            timeout = std::chrono::steady_clock::now() + std::chrono::seconds(kTxPoolElectionTimeoutSeconds);
            break;
        default:
            time_valid = common::TimeUtils::TimestampUs() + kBftStartDeltaTime;
            timeout = std::chrono::steady_clock::now() + std::chrono::seconds(kTxPoolTimeoutSeconds);
            break;
        }

        for (int32_t i = 0; i < tx.attr_size(); ++i) {
            attr_map[tx.attr(i).key()] = tx.attr(i).value();
        }
    }
    
    protobuf::TxInfo tx;
    std::map<std::string, std::string> attr_map;
    std::chrono::steady_clock::time_point timeout;
    std::chrono::steady_clock::time_point delta_time;
    uint64_t time_valid{ 0 };
    uint32_t index{ common::kInvalidPoolIndex };
    std::string uni_gid;

};

typedef std::shared_ptr<TxItem> TxItemPtr;

class TxPool {
public:
    TxPool();
    ~TxPool();
    int AddTx(TxItemPtr account_ptr);
    void GetTx(std::vector<TxItemPtr>& res_vec);
    bool TxPoolEmpty();
    TxItemPtr GetTx(
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid);
    void BftOver(BftInterfacePtr& bft_ptr);

    void set_pool_index(uint32_t pool_idx) {
        pool_index_ = pool_idx;
    }

    void RemoveTx(
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid);
    void CheckTimeoutTx();

private:
    bool IsTxContractLocked(TxItemPtr tx_ptr);
    bool IsTxValid(TxItemPtr tx_ptr);

    static const uint32_t kKeepCoverLoadCount = 1024u;

    static std::atomic<uint64_t> pool_index_gen_;
    std::map<uint64_t, TxItemPtr> tx_pool_;
    std::unordered_map<std::string, uint64_t> added_tx_map_;
    std::mutex tx_pool_mutex_;
    volatile uint32_t pool_index_;

    DISALLOW_COPY_AND_ASSIGN(TxPool);
};

}  // namespace bft

}  // namespace tenon
