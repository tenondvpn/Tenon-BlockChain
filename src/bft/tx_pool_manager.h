#pragma once

#include <bitset>

#include "common/bitmap.h"
#include "bft/bft_utils.h"
#include "bft/tx_pool.h"
#include "bft/proto/bft_proto.h"
#include "bft/bft_interface.h"

namespace lego {

namespace bft {

class TxPoolManager {
public:
    TxPoolManager();
    ~TxPoolManager();
    bool InitCheckTxValid(const bft::protobuf::BftMessage& bft_msg);
    int AddTx(TxItemPtr& tx_ptr);
    void GetTx(uint32_t& pool_index, std::vector<TxItemPtr>& res_vec);
    bool HasTx(const std::string& acc_addr, bool to, const std::string& tx_gid);
    bool HasTx(uint32_t pool_index, bool to, const std::string& tx_gid);
    void BftOver(BftInterfacePtr& bft_ptr);
    bool LockPool(uint32_t pool_index);
    bool TxValid(TxItemPtr& tx_ptr);
    TxItemPtr GetTx(uint32_t pool_index, bool to, const std::string& gid);

private:
    TxPool* tx_pool_{ nullptr };
    common::Bitmap waiting_pools_{ common::kImmutablePoolSize };
    uint64_t waiting_pools_height_[common::kImmutablePoolSize];
    std::mutex waiting_pools_mutex_;
    uint32_t prev_pool_index_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(TxPoolManager);
};

}  // namespace bft

}  // namespace bft
