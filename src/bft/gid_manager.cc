#include "gid_manager.h"

#include "db/db.h"
#include "bft/dispatch_pool.h"
#include "sync/key_value_sync.h"

namespace tenon {

namespace bft {

GidManager* GidManager::Instance() {
    static GidManager ins;
    return &ins;
}

std::string GidManager::GetUniversalGid(
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid) {
    if (tx_type != common::kConsensusCallContract && tx_type != common::kConsensusCreateContract) {
        return std::to_string(common::GlobalInfo::Instance()->network_id()) +
            (add_to ? std::string("_t_") : std::string("_")) +
            gid;
    } else {
        return std::to_string(common::GlobalInfo::Instance()->network_id()) +
            (add_to ? std::string("_t_") : std::string("_")) +
            std::to_string(call_contract_step) + "_" +
            gid;
    }
}

bool GidManager::NewGidTxValid(const std::string& gid, TxItemPtr& tx_ptr) {
    std::string tx_gid = GetUniversalGid(
        tx_ptr->tx.to_add(),
        tx_ptr->tx.type(),
        tx_ptr->tx.call_contract_step(),
        tx_ptr->tx.gid());
    BFT_DEBUG("NewGidTxValid get tx gid: %s", common::Encode::HexEncode(tx_gid).c_str());
    {
        std::lock_guard<std::mutex> guard(tx_map_mutex_);
        auto iter = tx_map_.find(tx_gid);
        if (iter != tx_map_.end()) {
            return false;
        }

        tx_map_[tx_gid] = tx_ptr;
    }

    std::string db_for_gid = "db_for_gid_" + tx_gid;
    if (db::Db::Instance()->Exist(db_for_gid)) {
        return false;
    }

    db::Db::Instance()->Put(db_for_gid, CreateTxInfo(tx_ptr));
    return true;
}

TxItemPtr GidManager::GetTx(
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid) {
    TxItemPtr bft_msg_ptr = nullptr;
    std::string tx_gid = GetUniversalGid(add_to, tx_type, call_contract_step, gid);
    {
        std::lock_guard<std::mutex> guard(tx_map_mutex_);
        auto iter = tx_map_.find(tx_gid);
        if (iter != tx_map_.end()) {
            return iter->second;
        }
    }

    std::string db_for_gid = "db_for_gid_" + tx_gid;
    std::string bft_msg;
    auto st = db::Db::Instance()->Get(db_for_gid, &bft_msg);
    if (!st.ok()) {
        // get from brother nodes
        sync::KeyValueSync::Instance()->AddSync(4, db_for_gid, sync::kSyncHighest);
        return nullptr;
    }

    protobuf::TxInfo tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("protobuf::TxBft ParseFromString failed!");
        return nullptr;
    }

    auto tx_ptr = std::make_shared<TxItem>(tx_bft);
    {
        std::lock_guard<std::mutex> guard(tx_map_mutex_);
        tx_map_[tx_gid] = tx_ptr;
    }

    return tx_ptr;
}

std::string GidManager::CreateTxInfo(TxItemPtr& tx_ptr) {
    protobuf::TxInfo tx = tx_ptr->tx;
    tx.set_gas_limit(0);
    tx.set_gas_price(0);
    tx.set_gas_used(0);
    tx.set_status(kBftSuccess);
    return tx.SerializeAsString();
}

}  // namespace bft

}  // namespace tenon
