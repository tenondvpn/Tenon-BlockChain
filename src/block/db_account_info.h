#pragma once

#include <unordered_set>
#include <queue>

#include "common/utils.h"
#include "common/string_utils.h"
#include "common/user_property_key_define.h"
#include "db/dict.h"
#include "db/db.h"
#include "db/db_pri_queue.h"
#include "bft/proto/bft.pb.h"
#include "block/block_utils.h"

namespace tenon {

namespace block {

class DbAccountInfo {
public:
    static bool AccountExists(const std::string& account_id);
    static bool AddNewAccountToDb(const std::string& account_id, db::DbWriteBach& db_batch);
    DbAccountInfo(const std::string& account_id);
    ~DbAccountInfo();
    int SetBalance(uint64_t balance, db::DbWriteBach& db_batch);
    int GetBalance(uint64_t* balance);
    void NewHeight(uint64_t height, db::DbWriteBach& db_batch);
    void GetHeights(std::vector<uint64_t>* res);
    void NewTxHeight(
        uint64_t height,
        uint64_t timestamp,
        const std::string& hash,
        const bft::protobuf::TxInfo& tx_info,
        db::DbWriteBach& db_batch);
    void GetTxHeights(std::vector<uint64_t>* res);
    int SetCreateAccountHeight(uint64_t create_account_height, db::DbWriteBach& db_batch);
    int GetCreateAccountHeight(uint64_t* create_account_height);
    int SetMaxHeightHash(uint64_t tmp_height, const std::string& hash, db::DbWriteBach& db_batch);
    int GetMaxHeight(uint64_t* max_height);
    int GetMaxHash(std::string* max_hash);
    int SetAttrWithHeight(const std::string& attr_key, uint64_t height, db::DbWriteBach& db_batch);
    int GetAttrWithHeight(const std::string& attr_key, uint64_t* height);
    int SetConsensuseNetid(uint32_t network_id, db::DbWriteBach& db_batch);
    int GetConsensuseNetId(uint32_t* network_id);
    int GetBlockHashWithHeight(uint64_t height, std::string* hash);
    int GetBlockWithHeight(uint64_t height, std::string* block_str);
    common::BlockItemPtr* GetHeightBlockInfos(uint32_t* count);
    int GetAttrValue(const std::string& key, std::string* value);
    int SetAttrValue(const std::string& key, const std::string& value, db::DbWriteBach& db_batch);
    int SetBytesCode(const std::string& bytes_code, db::DbWriteBach& db_batch);
    int GetBytesCode(std::string* bytes_code);
    int SetAddressType(uint32_t address_type, db::DbWriteBach& db_batch);
    int GetAddressType(uint32_t* address_type);
    int AddNewElectBlock(
        uint32_t network_id,
        uint64_t height,
        const std::string& elect_block_str,
        db::DbWriteBach& db_batch);
    int GetLatestElectBlock(
        uint32_t network_id,
        uint64_t* height,
        std::string* elect_block_str);
    int AddNewTimeBlock(uint64_t height, uint64_t block_tm, uint64_t vss_random, db::DbWriteBach& db_batch);
    int GetLatestTimeBlock(uint64_t* height, uint64_t* block_tm, uint64_t* vss_random);
    size_t VmCodeSize();
    std::string VmCodeHash();
    std::string GetCode();

    std::string& account_id() {
        return account_id_;
    }

    bool locked() {
        return locked_;
    }

    void LockAccount() {
        locked_ = true;
    }

    void UnLockAccount() {
        locked_ = false;
    }

    uint64_t added_timeout() {
        return added_timeout_;
    }

    void set_added_timeout(uint64_t added_time) {
        added_timeout_ = added_time;
    }

private:
    static const uint32_t kTopTxHeightBlocksCount = 128;

    std::string account_id_;
    std::string dict_key_;
    std::atomic<int64_t> balance_{ common::kInvalidInt64 };
    std::atomic<uint32_t> out_count_{ common::kInvalidUint32 };
    std::atomic<uint32_t> in_count_{ common::kInvalidUint32 };
    std::atomic<uint64_t> out_lego_{ common::kInvalidUint64 };
    std::atomic<uint64_t> in_lego_{ common::kInvalidUint64 };
    std::atomic<uint64_t> create_account_height_{ common::kInvalidUint64 };
    std::atomic<uint32_t> consensuse_net_id_{ common::kInvalidUint32 };
    std::atomic<uint32_t> type_{ common::kInvalidUint32 };
    std::unordered_map<std::string, uint64_t> attrs_with_height_map_;
    std::mutex attrs_with_height_map_mutex_;
    std::atomic<uint64_t> max_height_{ common::kInvalidUint64 };
    std::string max_hash_;
    std::mutex max_hash_mutex_;
    static std::unordered_set<std::string> account_id_set_;
    static std::mutex account_id_set_mutex_;
    uint32_t pool_index_{ common::kInvalidUint32 };
    db::DbPriQueue<uint64_t, kTopTxHeightBlocksCount> tx_height_queue_;
    std::mutex tx_height_queue_mutex_;
    common::LimitHeap<common::BlockItemPtr> top_height_blocks_{ false, kTopTxHeightBlocksCount };
    std::mutex top_height_blocks_mutex_;
    std::string bytes_code_;
    std::mutex bytes_code_mutex_;
    std::mutex owner_mutex_;
    std::string owner_;
    std::string full_account_id_;
    std::mutex full_account_id_mutex_;
    std::atomic<bool> locked_{ false };
    std::unordered_map<uint32_t, std::pair<uint64_t, std::string>> elect_blocks_map_;
    std::mutex elect_blocks_map_mutex_;
    std::atomic<uint64_t> latest_time_block_heigth_{ common::kInvalidUint64 };
    std::atomic<uint64_t> latest_time_block_tm_{ common::kInvalidUint64 };
    std::atomic<uint64_t> latest_time_block_vss_random_{ common::kInvalidUint64 };
    uint64_t added_timeout_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(DbAccountInfo);
};

typedef std::shared_ptr<DbAccountInfo> DbAccountInfoPtr;
}  // namespace block

}  // namespace tenon
