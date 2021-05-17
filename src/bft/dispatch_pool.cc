#include "stdafx.h"
#include "bft/dispatch_pool.h"

#include "transport/transport_utils.h"
#include "bft/bft_utils.h"
#include "bft/proto/bft.pb.h"
#include "bft/gid_manager.h"
#include "block/account_manager.h"
#include "contract/contract_utils.h"

namespace lego {

namespace bft {

DispatchPool::DispatchPool() {}

DispatchPool::~DispatchPool() {}

DispatchPool* DispatchPool::Instance() {
    static DispatchPool ins;
    return &ins;
}

bool DispatchPool::InitCheckTxValid(const bft::protobuf::BftMessage& bft_msg) {
    return tx_pool_.InitCheckTxValid(bft_msg);
}

int DispatchPool::Dispatch(const bft::protobuf::BftMessage& bft_msg, const std::string& tx_hash) {
    return AddTx(bft_msg, tx_hash);
}

int DispatchPool::Dispatch(const protobuf::TxInfo& tx_info) {
    auto tx_ptr = std::make_shared<TxItem>(tx_info);
    if (!GidManager::Instance()->NewGidTxValid(tx_ptr->tx.gid(), tx_ptr)) {
        BFT_ERROR("global check gid exists: %s", common::Encode::HexEncode(tx_ptr->tx.gid()).c_str());
        return kBftError;
    }

    return tx_pool_.AddTx(tx_ptr);
}

bool DispatchPool::TxTypeValid(const bft::protobuf::TxInfo& new_tx) {
    switch (new_tx.type())
    {
    case common::kConsensusInvalidType:
        return false;
    case common::kConsensusCreateAcount:{
        auto account_info = block::AccountManager::Instance()->GetAcountInfo(new_tx.to());
        if (account_info != nullptr) {
            BFT_ERROR("kConsensusCreateAcount account exists.");
            return false;
        }
        break;
    }
    default:
        break;
    }

    return true;
}

int DispatchPool::AddTx(const bft::protobuf::BftMessage& bft_msg, const std::string& tx_hash) {
    protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("protobuf::TxBft ParseFromString failed!");
        return kBftError;
    }

    // (TODO): check all type and need infomation valid
    if (!TxTypeValid(tx_bft.new_tx())) {
        BFT_ERROR("invalid tx type!");
        return kBftError;
    }

    // (TODO): check sign for gid
    assert(tx_bft.has_new_tx());
    auto tx_ptr = std::make_shared<TxItem>(tx_bft.new_tx());
    if (!GidManager::Instance()->NewGidTxValid(tx_ptr->tx.gid(), tx_ptr)) {
        BFT_ERROR("gid invalid.[%s]", common::Encode::HexEncode(tx_ptr->tx.gid()).c_str());
        return kBftError;
    }

    return tx_pool_.AddTx(tx_ptr);
}

 void DispatchPool::GetTx(uint32_t& pool_index, std::vector<TxItemPtr>& res_vec) {
    return tx_pool_.GetTx(pool_index, res_vec);
}

bool DispatchPool::HasTx(const std::string& acc_addr, bool to, const std::string& gid) {
    return tx_pool_.HasTx(acc_addr, to, gid);
}

bool DispatchPool::HasTx(uint32_t pool_index, bool to, const std::string& gid) {
    return tx_pool_.HasTx(pool_index, to, gid);
}

TxItemPtr DispatchPool::GetTx(uint32_t pool_index, bool to, const std::string& gid) {
    return tx_pool_.GetTx(pool_index, to, gid);
}

void DispatchPool::BftOver(BftInterfacePtr& bft_ptr) {
    tx_pool_.BftOver(bft_ptr);
}

bool DispatchPool::TxLockPool(uint32_t pool_index) {
    return tx_pool_.LockPool(pool_index);
}

}  // namespace bft

}  // namespace lego
