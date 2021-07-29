#pragma once

#include <unordered_map>
#include <queue>
#include <memory>

#include "common/config.h"
#include "common/tick.h"
#include "common/limit_heap.h"
#include "bft/proto/bft.pb.h"
#include "block/block_utils.h"
#include "block/db_account_info.h"
#include "block/db_pool_info.h"
#include "block/proto/block.pb.h"
#include "db/db.h"
#include "db/db_queue.h"

namespace tenon {

namespace block {

class AccountManager {
public:
    static AccountManager* Instance();
    int AddBlockItemToDb(
        const std::shared_ptr<bft::protobuf::Block>& block_item,
        db::DbWriteBach& db_batch);
    int AddBlockItemToCache(
        const std::shared_ptr<bft::protobuf::Block>& block_item,
        db::DbWriteBach& db_batch);
    DbAccountInfoPtr GetAcountInfo(const std::string& acc_id);
    bool AccountExists(const std::string& acc_id);
    int GetBlockInfo(
        uint32_t pool_idx,
        uint64_t* height,
        std::string* hash,
        uint64_t* tm_height,
        uint64_t* tm_with_block_height);
    int AddNewAccount(
        const bft::protobuf::TxInfo& tx_info,
        uint64_t tmp_now_height,
        const std::string& create_hash,
        db::DbWriteBach& db_batch);
    int GetAddressConsensusNetworkId(const std::string& address, uint32_t* network_id);
    DbAccountInfoPtr GetContractInfoByAddress(const std::string& address);
    std::string GetPoolBaseAddr(uint32_t pool_index);

private:
    AccountManager();
    ~AccountManager();
    int UpdateAccountInfo(
        const std::string& account_id,
        const bft::protobuf::TxInfo& tx_info,
        const std::shared_ptr<bft::protobuf::Block>& block_item,
        db::DbWriteBach& db_batch);
    void SetPool(
        uint32_t pool_index,
        const std::shared_ptr<bft::protobuf::Block>& block_item,
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
    bool IsInvalidKey(const std::string& key);
    int HandleRootSingleBlockTx(uint64_t height, const bft::protobuf::TxInfo& tx_info);
    int HandleElectBlock(uint64_t height, const bft::protobuf::TxInfo& tx_info);
    int HandleTimeBlock(uint64_t height, const bft::protobuf::TxInfo& tx_info);
    int HandleFinalStatisticBlock(uint64_t height, const bft::protobuf::TxInfo& tx_info);

    static const uint64_t kStatisticPeriod = 3000000llu;
    static const uint32_t kMaxCacheAccountCount = 10240u;

    std::unordered_map<std::string, block::DbAccountInfoPtr> acc_map_;
    common::LimitHeap<block::DbAccountInfoPtr> acc_limit_heap_{ false, kMaxCacheAccountCount };
    std::mutex acc_map_mutex_;
    DbPoolInfo* network_block_[common::kImmutablePoolSize + 1];

    DISALLOW_COPY_AND_ASSIGN(AccountManager);
};

}  // namespace block

}  //namespace tenon
