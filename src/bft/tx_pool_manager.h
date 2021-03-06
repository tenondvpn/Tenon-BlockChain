#pragma once

#include <bitset>

#include "common/bitmap.h"
#include "bft/bft_utils.h"
#include "bft/tx_pool.h"
#include "bft/proto/bft_proto.h"
#include "bft/bft_interface.h"

namespace tenon {

namespace bft {

class TxPoolManager {
public:
    TxPoolManager();
    ~TxPoolManager();
    bool InitCheckTxValid(const bft::protobuf::BftMessage& bft_msg);
    int AddTx(TxItemPtr& tx_ptr);
    void GetTx(uint32_t& pool_index, int32_t pool_mod_idx, std::vector<TxItemPtr>& res_vec);
    void BftOver(BftInterfacePtr& bft_ptr);
    TxItemPtr GetTx(
        uint32_t pool_index,
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid);
    TxItemPtr GetTx(
        uint32_t pool_index,
        const std::string& uni_gid);
    TxItemPtr GetRootTx();
    void RemoveTx(
        uint32_t pool_index,
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid);
    void CheckTimeoutTx();
    bool IsPoolLocked(uint32_t pool_index);
    void LockPool(uint32_t pool_index);
    bool ShouldChangeLeader(uint32_t pool_index) {
        return tx_pool_[pool_index].ShouldChangeLeader();
    }

    void ChangeLeader(uint32_t pool_index);
    void SetTimeout(uint32_t pool_idx);
    const PoolTxCountItem* GetTxPoolCount(uint64_t elect_height) {
        for (int32_t i = 0; i < kPoolTxCountMaxItem; ++i) {
            if (tx_counts_[i].elect_height = elect_height) {
                return &tx_counts_[i];
            }
        }

        return nullptr;
    }

private:
    bool CheckCallContractAddressValid(const std::string& contract_address);
    bool CheckDispatchNormalTransaction(TxItemPtr& tx_ptr);
    bool CheckCallerAccountInfoValid(const std::string& caller_address);
    void AddTxCount(int32_t pool);

    static const uint32_t kPoolTxCountMaxItem = 3u;

    TxPool* tx_pool_{ nullptr };
    common::Bitmap waiting_pools_{ common::kImmutablePoolSize };
    uint64_t waiting_pools_height_[common::kImmutablePoolSize + 1];
    uint64_t timeout_pools_[common::kImmutablePoolSize + 1];
    std::mutex waiting_pools_mutex_;
    uint32_t prev_pool_index_{ 0 };
    std::atomic<bool> root_tx_pool_valid_{ true };
    PoolTxCountItem tx_counts_[kPoolTxCountMaxItem];

    DISALLOW_COPY_AND_ASSIGN(TxPoolManager);
};

}  // namespace bft

}  // namespace bft
