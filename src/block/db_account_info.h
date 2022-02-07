#pragma once

#include <unordered_set>
#include <queue>

#include "common/utils.h"
#include "common/string_utils.h"
#include "common/user_property_key_define.h"
#include "db/dict.h"
#include "db/db.h"
#include "db/db_pri_queue.h"
#include "db/db_queue.h"
#include "bft/proto/bft.pb.h"
#include "block/block_utils.h"

namespace tenon {

namespace block {

class DbAccountInfo {
public:
    static bool AccountExists(const std::string& account_id);
    static bool AddNewAccountToDb(const std::string& account_id, db::DbWriteBach& db_batch);
    DbAccountInfo(const std::string& account_id, uint32_t net_id);
    ~DbAccountInfo();
    int SetBalance(uint64_t balance, db::DbWriteBach& db_batch);
    int GetBalance(uint64_t* balance);
    void NewHeight(uint64_t height, db::DbWriteBach& db_batch);
    void GetHeights(uint64_t index, int32_t count, std::vector<uint64_t>* res);
    void GetLatestHeights(uint64_t min_height, uint32_t count, std::vector<uint64_t>* res);
    int SetMaxHeightHash(uint64_t tmp_height, const std::string& hash, db::DbWriteBach& db_batch);
    int GetMaxHeight(uint64_t* max_height);
    int SetConsensuseNetid(uint32_t network_id, db::DbWriteBach& db_batch);
    int GetConsensuseNetId(uint32_t* network_id);
    int GetBlockHashWithHeight(uint64_t height, std::string* hash);
    int GetBlockWithHeight(uint64_t height, std::string* block_str);
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
    int AddNewTimeBlock(
        uint64_t height,
        uint64_t block_tm,
        uint64_t vss_random,
        db::DbWriteBach& db_batch);
    int GetLatestTimeBlock(uint64_t* height, uint64_t* block_tm, uint64_t* vss_random);
    size_t VmCodeSize();
    std::string VmCodeHash();
    std::string GetCode();
    void ClearAttr(const std::string& attr_key);

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

    int32_t heap_index() {
        return heap_index_;
    }

    void set_heap_index(int32_t heap_index) {
        heap_index_ = heap_index;
    }

    uint64_t max_index() {
        return tx_queue_.size();
    }

private:
    static std::unordered_set<std::string> account_id_set_;
    static std::mutex account_id_set_mutex_;

    std::string account_id_;
    std::string dict_key_;
    std::atomic<int64_t> balance_{ common::kInvalidInt64 };
    std::atomic<uint32_t> consensuse_net_id_{ common::kInvalidUint32 };
    std::atomic<uint32_t> type_{ common::kInvalidUint32 };
    std::atomic<uint64_t> max_height_{ common::kInvalidUint64 };
    uint32_t pool_index_{ common::kInvalidUint32 };
    std::string bytes_code_;
    std::mutex bytes_code_mutex_;
    std::string owner_;
    std::mutex owner_mutex_;
    std::atomic<bool> locked_{ false };
    std::unordered_map<uint32_t, std::pair<uint64_t, std::string>> elect_blocks_map_;
    std::mutex elect_blocks_map_mutex_;
    std::atomic<uint64_t> latest_time_block_heigth_{ common::kInvalidUint64 };
    std::atomic<uint64_t> latest_time_block_tm_{ common::kInvalidUint64 };
    std::atomic<uint64_t> latest_time_block_vss_random_{ common::kInvalidUint64 };
    std::unordered_map<std::string, std::string> attr_map_;
    std::mutex attr_map_mutex_;
    uint64_t added_timeout_{ 0 };
    int32_t heap_index_{ -1 };
    db::Queue tx_queue_;

    DISALLOW_COPY_AND_ASSIGN(DbAccountInfo);
};

typedef std::shared_ptr<DbAccountInfo> DbAccountInfoPtr;
}  // namespace block

}  // namespace tenon
