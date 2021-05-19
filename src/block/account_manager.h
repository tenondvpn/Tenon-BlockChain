#pragma once

#include <unordered_map>
#include <queue>

#include "common/config.h"
#include "db/db.h"
#include "block/block_utils.h"
#include "block/db_account_info.h"
#include "bft/proto/bft.pb.h"
#include "block/db_pool_info.h"

namespace tenon {

namespace block {

class AccountManager {
public:
    static AccountManager* Instance();
    int AddBlockItem(
        const bft::protobuf::Block& block_item,
        db::DbWriteBach& db_batch);
    DbAccountInfo* GetAcountInfo(const std::string& acc_id);
    bool AccountExists(const std::string& acc_id);
    int GetBlockInfo(uint32_t pool_idx, uint64_t* height, std::string* hash);
    int AddNewAccount(
        const bft::protobuf::TxInfo& tx_info,
        uint64_t tmp_now_height,
        const std::string& create_hash,
        db::DbWriteBach& db_batch);
    int GetAddressConsensusNetworkId(const std::string& address, uint32_t* network_id);
    DbAccountInfo* GetContractInfoByAddress(const std::string& address);

private:
    AccountManager();
    ~AccountManager();
    int UpdateAccountInfo(
        const bft::protobuf::TxInfo& tx_info,
        uint64_t now_height,
        uint64_t timestamp,
        const std::string& hash,
        db::DbWriteBach& db_batch);
    void SetPool(
        uint32_t pool_index,
        uint64_t now_height,
        const std::string& hash,
        db::DbWriteBach& db_batch);
    int GenesisAddAccountInfo(
        const std::string& account_id,
        db::DbWriteBach& db_batch,
        block::DbAccountInfo* account_info);
    int SetAccountAttrs(
        const std::string& account_id,
        const bft::protobuf::TxInfo& tx_info,
        uint64_t exist_height,
        uint64_t tmp_now_height,
        block::DbAccountInfo* account_info,
        db::DbWriteBach& db_batch);

    std::unordered_map<std::string, block::DbAccountInfo*> acc_map_;
    std::mutex acc_map_mutex_;
    DbPoolInfo* network_block_[common::kImmutablePoolSize];
    std::mutex network_block_mutex_;

    DISALLOW_COPY_AND_ASSIGN(AccountManager);
};

}  // namespace block

}  //namespace tenon
