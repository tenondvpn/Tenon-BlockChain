#pragma once

#include "bft/tx_pool_manager.h"
#include "bft/bft_interface.h"
#include "bft/proto/bft.pb.h"

namespace tenon {

namespace bft {

class DispatchPool {
public:
    static DispatchPool* Instance();
    int Dispatch(const bft::protobuf::BftMessage& bft_msg, const std::string& tx_hash);
    int Dispatch(const protobuf::TxInfo& tx_info);
    void CheckTimeoutTx();
    void GetTx(uint32_t& pool_index, int32_t pool_mod_idx, std::vector<TxItemPtr>& res_vec);
    TxItemPtr GetTx(
        uint32_t pool_index,
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid);
    void BftOver(BftInterfacePtr& bft_ptr);
    bool InitCheckTxValid(const bft::protobuf::BftMessage& bft_msg);
    TxItemPtr GetRootTx();
    void RemoveTx(
        uint32_t pool_index,
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid);
    bool LockPool(uint32_t pool_index) {
        std::lock_guard<std::mutex> guard(pool_mutex_);
        if (tx_pool_.IsPoolLocked(pool_index)) {
            return false;
        }

        tx_pool_.LockPool(pool_index);
        return true;
    }

    bool ShouldChangeLeader(uint32_t pool_index) {
        return tx_pool_.ShouldChangeLeader(pool_index);
    }

    void ChangeLeader(uint32_t pool_index) {
        tx_pool_.ChangeLeader(pool_index);
    }

    void SetTimeout(uint32_t pool_idx) {
        tx_pool_.SetTimeout(pool_index);
    }

private:
    DispatchPool();
    ~DispatchPool();
    int AddTx(const bft::protobuf::BftMessage& bft_msg, const std::string& tx_hash);
    int CheckFromAddressValid(
        const bft::protobuf::BftMessage& bft_msg,
        const bft::protobuf::TxInfo& new_tx);
    bool TxTypeValid(const bft::protobuf::TxInfo& new_tx);

    TxPoolManager tx_pool_;
    std::mutex pool_mutex_;

    DISALLOW_COPY_AND_ASSIGN(DispatchPool);
};

}  // namespace bft

}  // namespace tenon
