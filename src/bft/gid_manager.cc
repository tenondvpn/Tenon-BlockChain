#include "gid_manager.h"

#include "db/db.h"
#include "bft/dispatch_pool.h"
#include "sync/key_value_sync.h"

namespace lego {

namespace bft {

GidManager* GidManager::Instance() {
    static GidManager ins;
    return &ins;
}

bool GidManager::NewGidTxValid(const std::string& gid, TxItemPtr& tx_ptr) {
    std::string tx_gid = GetUniversalGid(tx_ptr->add_to_acc_addr, gid);
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

TxItemPtr GidManager::GetTx(bool add_to, const std::string& gid) {
    TxItemPtr bft_msg_ptr = nullptr;
    std::string tx_gid = GetUniversalGid(add_to, gid);
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

    auto tx_ptr = std::make_shared<TxItem>(
        tx_bft.version(),
        tx_bft.gid(),
        tx_bft.from(),
        tx_bft.from_pubkey(),
        tx_bft.from_sign(),
        tx_bft.to(),
        tx_bft.amount(),
        tx_bft.type(),
        tx_bft.gas_limit(),
        tx_bft.call_contract_step(),
        tx_bft.tx_hash());
    tx_ptr->add_to_acc_addr = tx_bft.to_add();
    for (int32_t attr_idx = 0; attr_idx < tx_bft.attr_size(); ++attr_idx) {
        tx_ptr->add_attr(
            tx_bft.attr(attr_idx).key(),
            tx_bft.attr(attr_idx).value());
    }

    {
        std::lock_guard<std::mutex> guard(tx_map_mutex_);
        tx_map_[tx_gid] = tx_ptr;
    }

    return tx_ptr;
}

std::string GidManager::CreateTxInfo(TxItemPtr& tx_ptr) {
    protobuf::TxInfo tx;
    tx.set_version(tx_ptr->tx_version);
    tx.set_gid(tx_ptr->gid);
    tx.set_from(tx_ptr->from_acc_addr);
    tx.set_from_pubkey(tx_ptr->from_pubkey);
    tx.set_from_sign(tx_ptr->from_sign);
    tx.set_to(tx_ptr->to_acc_addr);
    tx.set_amount(tx_ptr->lego_count);
    tx.set_to_add(tx_ptr->add_to_acc_addr);
    tx.set_type(tx_ptr->bft_type);
    tx.set_gas_limit(0);
    tx.set_gas_price(0);
    tx.set_gas_used(0);
    tx.set_status(kBftSuccess);
    if (!tx_ptr->attr_map.empty()) {
        for (auto iter = tx_ptr->attr_map.begin(); iter != tx_ptr->attr_map.end(); ++iter) {
            auto tx_attr = tx.add_attr();
            tx_attr->set_key(iter->first);
            tx_attr->set_value(iter->second);
        }
    }

    return tx.SerializeAsString();
}

}  // namespace bft

}  // namespace lego
