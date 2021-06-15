#pragma once

#include <unordered_map>
#include <queue>
#include <memory>

#include "common/config.h"
#include "common/tick.h"
#include "bft/proto/bft.pb.h"
#include "db/db.h"
#include "block/block_utils.h"
#include "block/db_account_info.h"
#include "block/db_pool_info.h"
#include "block/proto/block.pb.h"

namespace tenon {

namespace block {

class AccountManager {
public:
    static AccountManager* Instance();
    int AddBlockItem(
        const std::shared_ptr<bft::protobuf::Block>& block_item,
        db::DbWriteBach& db_batch);
    DbAccountInfo* GetAcountInfo(const std::string& acc_id);
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
    DbAccountInfo* GetContractInfoByAddress(const std::string& address);
    std::string GetPoolBaseAddr(uint32_t pool_index);
    int GetPoolStatistic(uint32_t pool_index, block::protobuf::StatisticInfo* statistic_info);

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
    void StatisticDpPool();

    static const uint64_t kStatisticPeriod = 3000000llu;

    std::unordered_map<std::string, block::DbAccountInfo*> acc_map_;
    std::mutex acc_map_mutex_;
    DbPoolInfo* network_block_[common::kImmutablePoolSize + 1];
    std::mutex network_block_mutex_;
    common::Tick pool_statistci_tick_;

    DISALLOW_COPY_AND_ASSIGN(AccountManager);
};

}  // namespace block

}  //namespace tenon
