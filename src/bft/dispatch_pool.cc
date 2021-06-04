#include "stdafx.h"
#include "bft/dispatch_pool.h"

#include "transport/transport_utils.h"
#include "bft/bft_utils.h"
#include "bft/proto/bft.pb.h"
#include "bft/gid_manager.h"
#include "block/account_manager.h"
#include "contract/contract_utils.h"
#include "security/secp256k1.h"
#include "election/member_manager.h"
#include "root/root_utils.h"

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

int DispatchPool::Dispatch(const bft::protobuf::BftMessage& bft_msg, const std::string& tx_hash) {
    return AddTx(bft_msg, tx_hash);
}

int DispatchPool::Dispatch(const protobuf::TxInfo& tx_info) {
    BFT_ERROR("Dispatch tx [to: %d] [pool idx: %d] type: %d,"
        "call_contract_step: %d not has tx[%s]to[%s][%s]!",
        tx_info.to_add(),
        0,
        tx_info.type(),
        tx_info.call_contract_step(),
        common::Encode::HexEncode(tx_info.from()).c_str(),
        common::Encode::HexEncode(tx_info.to()).c_str(),
        common::Encode::HexEncode(tx_info.gid()).c_str());
    auto tx_ptr = std::make_shared<TxItem>(tx_info);
    if (!GidManager::Instance()->NewGidTxValid(tx_ptr->tx.gid(), tx_ptr)) {
        BFT_ERROR("global check gid exists: %s",
            common::Encode::HexEncode(tx_ptr->tx.gid()).c_str());
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
            if (new_tx.from() != root::kRootChainSingleBlockTxAddress) {
                return kBftError;
            }

            auto id = security::Secp256k1::Instance()->ToAddressWithPublicKey(bft_msg.pubkey());
            if (id.empty() || !elect::MemberManager::Instance()->IsLeader(
                    network::kRootCongressNetworkId,
                    id,
                    vss::VssManager::Instance()->EpochRandom())) {
                return kBftError;
            }
        } else {
            auto from_account = block::AccountManager::Instance()->GetAcountInfo(new_tx.from());
            if (from_account == nullptr) {
                return kBftError;
            }

            uint64_t balance = 0;
            if (from_account->GetBalance(&balance) != block::kBlockSuccess) {
                return kBftError;
            }

            if (balance >= common::kTenonMaxAmount) {
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
    if (!CheckFromAddressValid(bft_msg, tx_bft.new_tx())) {
        return kBftError;
    }

    auto tx_ptr = std::make_shared<TxItem>(tx_bft.new_tx());
    if (!GidManager::Instance()->NewGidTxValid(tx_ptr->tx.gid(), tx_ptr)) {
        BFT_ERROR("gid invalid.[%s]", common::Encode::HexEncode(tx_ptr->tx.gid()).c_str());
        return kBftError;
    }

    return tx_pool_.AddTx(tx_ptr);
}

 void DispatchPool::GetTx(uint32_t& pool_index, std::vector<TxItemPtr>& res_vec) {
    tx_pool_.GetTx(pool_index, res_vec);
    BFT_ERROR("DispatchPool::GetTx size: %u", res_vec.size());
}

 TxItemPtr DispatchPool::GetTx(
         uint32_t pool_index,
         bool add_to,
         uint32_t tx_type,
         uint32_t call_contract_step,
         const std::string& gid) {
     return tx_pool_.GetTx(pool_index, add_to, tx_type, call_contract_step, gid);
}

void DispatchPool::BftOver(BftInterfacePtr& bft_ptr) {
    tx_pool_.BftOver(bft_ptr);
}

}  // namespace bft

}  // namespace tenon
