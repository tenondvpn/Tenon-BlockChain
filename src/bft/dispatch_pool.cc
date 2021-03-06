#include "stdafx.h"
#include "bft/dispatch_pool.h"

#include "transport/transport_utils.h"
#include "bft/bft_utils.h"
#include "bft/proto/bft.pb.h"
#include "bft/gid_manager.h"
#include "block/account_manager.h"
#include "contract/contract_utils.h"
#include "security/secp256k1.h"
#include "election/elect_manager.h"

namespace tenon {

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

int DispatchPool::Dispatch(
        const bft::protobuf::BftMessage& bft_msg,
        const std::string& tx_hash) {
    return AddTx(bft_msg, tx_hash);
}

int DispatchPool::Dispatch(const protobuf::TxInfo& tx_info) {
    auto tx_ptr = std::make_shared<TxItem>(tx_info);
    if (!GidManager::Instance()->NewGidTxValid(tx_ptr->tx.gid(), tx_ptr)) {
        BFT_ERROR("global check gid exists: %s, call_contract_step: %d, tx_type: %d",
            common::Encode::HexEncode(tx_ptr->tx.gid()).c_str(), tx_info.call_contract_step(), tx_info.type());
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

int DispatchPool::CheckFromAddressValid(
        const bft::protobuf::BftMessage& bft_msg,
        const bft::protobuf::TxInfo& new_tx) {
    // from must valid
    if (!new_tx.to_add()) {
        if (IsRootSingleBlockTx(new_tx.type())) {
            // must leader can transaction
            if (new_tx.from() != common::kRootChainSingleBlockTxAddress &&
                    new_tx.from() != common::kRootChainTimeBlockTxAddress &&
                    new_tx.from() != common::kRootChainElectionBlockTxAddress) {
                BFT_ERROR("from is not valid root address[%s][%s]",
                    common::Encode::HexEncode(common::kRootChainSingleBlockTxAddress).c_str(),
                    common::Encode::HexEncode(new_tx.from()).c_str());
                return kBftError;
            }
        } else if (IsShardSingleBlockTx(new_tx.type())) {
            if (!block::IsPoolBaseAddress(new_tx.from())) {
                BFT_ERROR("from is not valid shard base address[%s]",
                    common::Encode::HexEncode(new_tx.from()).c_str());
                return kBftError;
            }
        } else {
            auto id_from_pubkey = security::Secp256k1::Instance()->ToAddressWithPublicKey(
                bft_msg.pubkey());
            if (id_from_pubkey != new_tx.from()) {
                BFT_ERROR("transaction from public key not match tx from.[%s][%s][%s]",
                    common::Encode::HexEncode(bft_msg.pubkey()).c_str(),
                    common::Encode::HexEncode(new_tx.from()).c_str(),
                    common::Encode::HexEncode(id_from_pubkey).c_str());
                return kBftError;
            }

            auto from_account = block::AccountManager::Instance()->GetAcountInfo(new_tx.from());
            if (from_account == nullptr) {
                BFT_ERROR("from_account is is not exists[%s].",
                    common::Encode::HexEncode(new_tx.from()).c_str());
                return kBftError;
            }

            uint64_t balance = 0;
            if (from_account->GetBalance(&balance) != block::kBlockSuccess) {
                BFT_ERROR("from_account balance error[%s].",
                    common::Encode::HexEncode(new_tx.from()).c_str());
                return kBftError;
            }

            if (balance >= common::kTenonMaxAmount) {
                BFT_ERROR("from_account balance error[%s].",
                    common::Encode::HexEncode(new_tx.from()).c_str());
                return kBftError;
            }
        }
    }

    return kBftSuccess;
}

int DispatchPool::AddTx(const bft::protobuf::BftMessage& bft_msg, const std::string& tx_hash) {
    protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("protobuf::TxBft ParseFromString failed!");
        return kBftError;
    }

    // (TODO): check all type and need information valid
    if (!TxTypeValid(tx_bft.new_tx())) {
        BFT_ERROR("invalid tx type!");
        return kBftError;
    }

    assert(tx_bft.has_new_tx());
    if (CheckFromAddressValid(bft_msg, tx_bft.new_tx()) != kBftSuccess) {
        BFT_ERROR("CheckFromAddressValid failed!");
        return kBftError;
    }

    auto tx_ptr = std::make_shared<TxItem>(tx_bft.new_tx());
    if (!GidManager::Instance()->NewGidTxValid(tx_ptr->tx.gid(), tx_ptr)) {
        BFT_ERROR("global check gid exists: %s, call_contract_step: %d, tx_type: %d",
            common::Encode::HexEncode(tx_ptr->tx.gid()).c_str(), tx_ptr->tx.call_contract_step(), tx_ptr->tx.type());
        return kBftError;
    }

    return tx_pool_.AddTx(tx_ptr);
}

TxItemPtr DispatchPool::GetRootTx() {
    // Check this pool height if behind
    return tx_pool_.GetRootTx();
}

void DispatchPool::GetTx(
        uint32_t& pool_index,
        int32_t pool_mod_idx,
        std::vector<TxItemPtr>& res_vec) {
    // Check this pool height if behind
    tx_pool_.GetTx(pool_index, pool_mod_idx, res_vec);
}

TxItemPtr DispatchPool::GetTx(
         uint32_t pool_index,
         bool add_to,
         uint32_t tx_type,
         uint32_t call_contract_step,
         const std::string& gid) {
     return tx_pool_.GetTx(pool_index, add_to, tx_type, call_contract_step, gid);
}

TxItemPtr DispatchPool::GetTx(
        uint32_t pool_index,
        const std::string& uni_gid) {
    return tx_pool_.GetTx(pool_index, uni_gid);
}

void DispatchPool::RemoveTx(
        uint32_t pool_index,
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid) {
    tx_pool_.RemoveTx(pool_index, add_to, tx_type, call_contract_step, gid);
}

void DispatchPool::BftOver(BftInterfacePtr& bft_ptr) {
    tx_pool_.BftOver(bft_ptr);
}

void DispatchPool::CheckTimeoutTx() {
    tx_pool_.CheckTimeoutTx();
}

}  // namespace bft

}  // namespace tenon
