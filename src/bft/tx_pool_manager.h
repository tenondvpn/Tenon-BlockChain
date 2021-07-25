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
    TxItemPtr GetRootTx();
    void RemoveTx(
        uint32_t pool_index,
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid);

private:
    bool CheckCallContractAddressValid(const std::string& contract_address);
    bool CheckDispatchNormalTransaction(TxItemPtr& tx_ptr);
    bool CheckCallerAccountInfoValid(const std::string& caller_address);

    TxPool* tx_pool_{ nullptr };
    common::Bitmap waiting_pools_{ common::kImmutablePoolSize };
    uint64_t waiting_pools_height_[common::kImmutablePoolSize + 1];
    std::mutex waiting_pools_mutex_;
    uint32_t prev_pool_index_{ 0 };
    std::atomic<bool> root_tx_pool_valid_{ true };

    DISALLOW_COPY_AND_ASSIGN(TxPoolManager);
};

}  // namespace bft

}  // namespace bft
