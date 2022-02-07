#include "stdafx.h"
#include "block/db_account_info.h"

#include "common/encode.h"
#include "common/bitmap.h"
#include "db/db.h"
#include "network/network_utils.h"

namespace tenon {

namespace block {

static const std::string kFieldBalance("balance");
static const std::string kFieldNetworkId("net_id");
static const std::string kFieldHeight("height");
static const std::string kFieldOutCount("out_count");
static const std::string kFieldInCount("in_count");
static const std::string kFieldOutLego("out_lego");
static const std::string kFieldInLego("in_lego");
static const std::string kFieldNewHeight("create_account_height");
static const std::string kFieldAttrsWithHeight("attrs_with_height");
static const std::string kFieldMaxHeight("max_height");
static const std::string kFieldMaxHash("max_hash");
static const std::string kFieldBytesCode("bytes_code");
static const std::string kFieldAddressType("addr_type");
static const std::string kFieldElectBlock("elect_block");
static const std::string kFieldElectHeight("elect_height");
static const std::string kFieldTimeBlock("time_block");
static const std::string kFieldTimeHeight("time_height");
static const std::string kFieldTimeVssRandom("time_vss_random");

bool operator<(DbAccountInfoPtr& lhs, DbAccountInfoPtr& rhs) {
    return lhs->added_timeout() < rhs->added_timeout();
}

std::unordered_set<std::string> DbAccountInfo::account_id_set_;
std::mutex DbAccountInfo::account_id_set_mutex_;

bool DbAccountInfo::AccountExists(const std::string& uni_account_id) {
    {
        std::lock_guard<std::mutex> guard(account_id_set_mutex_);
        auto iter = account_id_set_.find(uni_account_id);
        if (iter != account_id_set_.end()) {
            return true;
        }
    }

    std::string key = db::kGlobalDickKeyAccountIdExists + "_" + uni_account_id;
    std::string tmp_val;
    auto res = db::Db::Instance()->Get(key, &tmp_val);
    if (res.ok()) {
        std::lock_guard<std::mutex> guard(account_id_set_mutex_);
        account_id_set_.insert(uni_account_id);
        return true;
    }

    return false;
}

bool DbAccountInfo::AddNewAccountToDb(
        const std::string& uni_account_id,
        db::DbWriteBach& db_batch) {
    {
        std::string key = db::kGlobalDickKeyAccountIdExists + "_" + uni_account_id;
        std::string tmp_val("1");
        db_batch.Put(key, tmp_val);
    }

    std::lock_guard<std::mutex> guard(account_id_set_mutex_);
    account_id_set_.insert(uni_account_id);
    return true;
}

DbAccountInfo::DbAccountInfo(const std::string& account_id)
        : account_id_(account_id), tx_queue_(account_id, (std::numeric_limits<uint64_t>::max)()) {
    dict_key_ = db::kGlobalDickKeyAccountInfo + account_id_;
    pool_index_ = common::GetPoolIndex(account_id_);
}

DbAccountInfo::~DbAccountInfo() {
    std::lock_guard<std::mutex> guard(elect_blocks_map_mutex_);
    elect_blocks_map_.clear();
}

int DbAccountInfo::GetBlockWithHeight(uint64_t height, std::string* block_str) {
    std::string hash;
    if (GetBlockHashWithHeight(height, &hash) != kBlockSuccess) {
        return kBlockError;
    }

    auto st = db::Db::Instance()->Get(hash, block_str);
    if (!st.ok()) {
        return kBlockError;
    }

    return kBlockSuccess;
}

int DbAccountInfo::GetBlockHashWithHeight(uint64_t height, std::string* hash) {
    std::string height_db_key = common::GetHeightDbKey(
            consensuse_net_id_,
            pool_index_,
            height);
    auto st = db::Db::Instance()->Get(height_db_key, hash);
    if (!st.ok()) {
        return kBlockError;
    }

    return kBlockSuccess;
}

int DbAccountInfo::SetConsensuseNetid(uint32_t network_id, db::DbWriteBach& db_batch) {
    if (!db::Dict::Instance()->Hset(
            dict_key_,
            kFieldNetworkId,
            std::to_string(network_id),
            db_batch)) {
        return kBlockError;
    }

    consensuse_net_id_ = network_id;
    return kBlockSuccess;

}

int DbAccountInfo::GetConsensuseNetId(uint32_t* network_id) {
    if (consensuse_net_id_ != common::kInvalidUint32) {
        *network_id = consensuse_net_id_;
        return kBlockSuccess;
    }

    std::string str_net_id;
    if (!db::Dict::Instance()->Hget(
            dict_key_,
            kFieldNetworkId,
            &str_net_id)) {
        return kBlockError;
    }
        
    if (!common::StringUtil::ToUint32(str_net_id, network_id)) {
        return kBlockError;
    }

    consensuse_net_id_ = *network_id;
    return kBlockSuccess;
}

int DbAccountInfo::SetBalance(uint64_t balance, db::DbWriteBach& db_batch) {
    if (!db::Dict::Instance()->Hset(
            dict_key_,
            kFieldBalance,
            std::to_string(balance),
            db_batch)) {
        return kBlockError;
    }

    balance_ = balance;
    return kBlockSuccess;
}

int DbAccountInfo::GetBalance(uint64_t* balance) {
    if (balance_ != common::kInvalidInt64) {
        *balance = balance_;
        return kBlockSuccess;
    }

    std::string str_balance;
    if (!db::Dict::Instance()->Hget(
            dict_key_,
            kFieldBalance,
            &str_balance)) {
        return kBlockError;
    } 

    if (!common::StringUtil::ToUint64(str_balance, balance)) {
        return kBlockError;
    }

    balance_ = *balance;
    return kBlockSuccess;
}

void DbAccountInfo::NewHeight(uint64_t height, db::DbWriteBach& db_batch) {
    tx_queue_.push(std::to_string(height), db_batch);
}

// get from end to begin, count's heights, one time max: 1024
void DbAccountInfo::GetHeights(uint64_t index, int32_t count, std::vector<uint64_t>* res) {
    if (index >= (uint64_t)tx_queue_.size()) {
        return;
    }

    static const int32_t kMaxCount = 64;
    if (count > kMaxCount) {
        count = kMaxCount;
    }

    for (uint64_t i = index; i < index + count; ++i) {
        std::string value;
        if (tx_queue_.get(i, &value)) {
            uint64_t height = 0;
            if (common::StringUtil::ToUint64(value, &height)) {
                res->push_back(height);
            }
        }
    }
}

void DbAccountInfo::GetLatestHeights(
        uint64_t min_height,
        uint32_t count,
        std::vector<uint64_t>* res) {
    static const int32_t kMaxCount = 64;
    if (count > kMaxCount) {
        count = kMaxCount;
    }

    uint32_t got_count = 0;
    for (int64_t i = tx_queue_.size() - 1; i >= 0; --i) {
        if (got_count >= count) {
            break;
        }

        std::string value;
        if (!tx_queue_.get(i, &value)) {
            break;
        }

        uint64_t height = 0;
        if (!common::StringUtil::ToUint64(value, &height)) {
            break;
        }
        
        if (min_height != common::kInvalidUint64 && height <= min_height) {
            break;
        }

        res->push_back(height);
        ++got_count;
    }
}

int DbAccountInfo::SetMaxHeightHash(
        uint64_t tmp_height,
        const std::string& hash,
        db::DbWriteBach& db_batch) {
    if (!db::Dict::Instance()->Hset(
            dict_key_,
            kFieldMaxHeight,
            std::to_string(tmp_height),
            db_batch)) {
        return kBlockError;
    }

    if (!db::Dict::Instance()->Hset(
            dict_key_,
            kFieldMaxHash,
            hash,
            db_batch)) {
        return kBlockError;
    }

    max_height_ = tmp_height;
    return kBlockSuccess;
}

int DbAccountInfo::GetMaxHeight(uint64_t* max_height) {
    if (max_height_ != common::kInvalidUint64) {
        *max_height = max_height_;
        return kBlockSuccess;
    }

    std::string tmp_str;
    if (!db::Dict::Instance()->Hget(
            dict_key_,
            kFieldMaxHeight,
            &tmp_str)) {
        return kBlockError;
    }

    if (!common::StringUtil::ToUint64(tmp_str, max_height)) {
        return kBlockError;
    }

    max_height_ = *max_height;
    return kBlockSuccess;
}

void DbAccountInfo::ClearAttr(const std::string& attr_key) {
    std::lock_guard<std::mutex> guard(attr_map_mutex_);
    auto iter = attr_map_.find(attr_key);
    if (iter != attr_map_.end()) {
        attr_map_.erase(iter);
    }
}

int DbAccountInfo::GetAttrValue(const std::string& key, std::string* value) {
    {
        std::lock_guard<std::mutex> guard(attr_map_mutex_);
        auto iter = attr_map_.find(key);
        if (iter != attr_map_.end()) {
            *value = iter->second;
//             if (account_id_ == common::Encode::HexDecode("6bbd8b7912ac3bf7ed00963f5ddfbbfa911db54f") ||
//                 account_id_ == common::Encode::HexDecode("544064949151817a1185e931ea43a71493f9f33c") ||
//                 account_id_ == common::Encode::HexDecode("15518b7643b094a6b1faba3a91fc16c20a9041da") ||
//                 account_id_ == common::Encode::HexDecode("7c4fd7e97e3cdd18dbe56e1256fbd60d4129af66") ||
//                 account_id_ == common::Encode::HexDecode("7027d87b3b251eac11933b5c2e4bd2ff1f7dd666") ||
//                 account_id_ == common::Encode::HexDecode("a2234d38e7073639156ee1cfc323e8d6cdadc604") ||
//                 account_id_ == common::Encode::HexDecode("2935aeb958731e29b8297d7250903b86c22b40be") ||
//                 account_id_ == common::Encode::HexDecode("14f87c1026d307937b6160ca69b24e891467749b") ||
//                 account_id_ == common::Encode::HexDecode("4dca4186ec80fe5bbce7531186fc8966d8dd58a9") ||
//                 account_id_ == common::Encode::HexDecode("a45c90f01155cd8615d2db4267b6ee0e8e3d6528") ||
//                 account_id_ == common::Encode::HexDecode("cc686eefa301ec1a781a77a915a742cc5f562613")) {
//                 std::cout << "get storage key: " << common::Encode::HexEncode(key)
//                     << ", " << common::Encode::HexEncode(*value) << std::endl;
//             }

            return kBlockSuccess;
        }
    }

    auto st = db::Db::Instance()->Get(StorageDbKey(account_id_, key), value);
    if (st.ok()) {
//         if (account_id_ == common::Encode::HexDecode("6bbd8b7912ac3bf7ed00963f5ddfbbfa911db54f") ||
//             account_id_ == common::Encode::HexDecode("544064949151817a1185e931ea43a71493f9f33c") ||
//             account_id_ == common::Encode::HexDecode("15518b7643b094a6b1faba3a91fc16c20a9041da") ||
//             account_id_ == common::Encode::HexDecode("7c4fd7e97e3cdd18dbe56e1256fbd60d4129af66") ||
//             account_id_ == common::Encode::HexDecode("7027d87b3b251eac11933b5c2e4bd2ff1f7dd666") ||
//             account_id_ == common::Encode::HexDecode("a2234d38e7073639156ee1cfc323e8d6cdadc604") ||
//             account_id_ == common::Encode::HexDecode("2935aeb958731e29b8297d7250903b86c22b40be") ||
//             account_id_ == common::Encode::HexDecode("14f87c1026d307937b6160ca69b24e891467749b") ||
//             account_id_ == common::Encode::HexDecode("4dca4186ec80fe5bbce7531186fc8966d8dd58a9") ||
//             account_id_ == common::Encode::HexDecode("a45c90f01155cd8615d2db4267b6ee0e8e3d6528") ||
//             account_id_ == common::Encode::HexDecode("cc686eefa301ec1a781a77a915a742cc5f562613")) {
//             std::cout << "get storage key: " << common::Encode::HexEncode(key)
//                 << ", " << common::Encode::HexEncode(*value) << std::endl;
//         }

        return kBlockSuccess;
    }

    return kBlockError;
}

int DbAccountInfo::SetAttrValue(
        const std::string& key,
        const std::string& value,
        db::DbWriteBach& db_batch) {
    {
        std::lock_guard<std::mutex> guard(attr_map_mutex_);
        attr_map_[key] = value;
    }

//     if (account_id_ == common::Encode::HexDecode("6bbd8b7912ac3bf7ed00963f5ddfbbfa911db54f") ||
//         account_id_ == common::Encode::HexDecode("544064949151817a1185e931ea43a71493f9f33c") ||
//         account_id_ == common::Encode::HexDecode("15518b7643b094a6b1faba3a91fc16c20a9041da") ||
//         account_id_ == common::Encode::HexDecode("7c4fd7e97e3cdd18dbe56e1256fbd60d4129af66") ||
//         account_id_ == common::Encode::HexDecode("7027d87b3b251eac11933b5c2e4bd2ff1f7dd666") ||
//         account_id_ == common::Encode::HexDecode("a2234d38e7073639156ee1cfc323e8d6cdadc604") ||
//         account_id_ == common::Encode::HexDecode("2935aeb958731e29b8297d7250903b86c22b40be") ||
//         account_id_ == common::Encode::HexDecode("14f87c1026d307937b6160ca69b24e891467749b") ||
//         account_id_ == common::Encode::HexDecode("4dca4186ec80fe5bbce7531186fc8966d8dd58a9") ||
//         account_id_ == common::Encode::HexDecode("a45c90f01155cd8615d2db4267b6ee0e8e3d6528") ||
//         account_id_ == common::Encode::HexDecode("cc686eefa301ec1a781a77a915a742cc5f562613")) {
//         std::cout << "set storage key: " << common::Encode::HexEncode(key)
//             << ", " << common::Encode::HexEncode(value) << std::endl;
//         BLOCK_DEBUG("set storage key: %s, value: %s",
//             common::Encode::HexEncode(key).c_str(),
//             common::Encode::HexEncode(value).c_str());
//     }

    db_batch.Put(StorageDbKey(account_id_, key), value);
    return kBlockSuccess;
}

int DbAccountInfo::SetBytesCode(const std::string& bytes_code, db::DbWriteBach& db_batch) {
    if (!db::Dict::Instance()->Hset(
            dict_key_,
            kFieldBytesCode,
            bytes_code,
            db_batch)) {
        return kBlockError;
    }

    {
        std::lock_guard<std::mutex> guard(bytes_code_mutex_);
        bytes_code_ = bytes_code;
    }

//     BLOCK_DEBUG("set bytes code addr: %s, bytescode: %s", common::Encode::HexEncode(account_id_).c_str(), common::Encode::HexEncode(bytes_code));
    return kBlockSuccess;
}

int DbAccountInfo::GetBytesCode(std::string* bytes_code) {
//     BLOCK_DEBUG("get bytes code addr: %s", common::Encode::HexEncode(account_id_).c_str());
    {
        std::lock_guard<std::mutex> guard(bytes_code_mutex_);
        if (!bytes_code_.empty()) {
            *bytes_code = bytes_code_;
            return kBlockSuccess;
        }
    }

    std::string tmp_str;
    if (!db::Dict::Instance()->Hget(
            dict_key_,
            kFieldBytesCode,
            &tmp_str)) {
        return kBlockError;
    }

    *bytes_code = tmp_str;
    {
        std::lock_guard<std::mutex> guard(bytes_code_mutex_);
        bytes_code_ = tmp_str;
    }

    return kBlockSuccess;
}

int DbAccountInfo::SetAddressType(uint32_t address_type, db::DbWriteBach& db_batch) {
    if (!db::Dict::Instance()->Hset(
            dict_key_,
            kFieldAddressType,
            std::to_string(address_type),
            db_batch)) {
        return kBlockError;
    }

    type_ = address_type;
    return kBlockSuccess;

}

int DbAccountInfo::GetAddressType(uint32_t* address_type) {
    if (type_ != common::kInvalidUint32) {
        *address_type = type_;
        return kBlockSuccess;
    }

    std::string str_address_type;
    if (!db::Dict::Instance()->Hget(
            dict_key_,
            kFieldAddressType,
            &str_address_type)) {
        return kBlockError;
    }

    if (!common::StringUtil::ToUint32(str_address_type, address_type)) {
        return kBlockError;
    }

    type_ = *address_type;
    return kBlockSuccess;
}

size_t DbAccountInfo::VmCodeSize() {
    std::string bytes_code;
    if (GetBytesCode(&bytes_code) != kBlockSuccess) {
        return 0;
    }

    return bytes_code.size();
}

std::string DbAccountInfo::VmCodeHash() {
    std::string bytes_code;
    if (GetBytesCode(&bytes_code) != kBlockSuccess) {
        return "";
    }

    return common::Hash::Sha256(bytes_code);
}

std::string DbAccountInfo::GetCode() {
    std::string bytes_code;
    if (GetBytesCode(&bytes_code) != kBlockSuccess) {
        return "";
    }

    return bytes_code;
}

int DbAccountInfo::AddNewElectBlock(
        uint32_t network_id,
        uint64_t height,
        const std::string& elect_block_str,
        db::DbWriteBach& db_batch) {
    std::lock_guard<std::mutex> guard(elect_blocks_map_mutex_);
    auto iter = elect_blocks_map_.find(network_id);
    if (iter == elect_blocks_map_.end()) {
        std::string tmp_key = dict_key_ + "_" + std::to_string(network_id) + "_" + kFieldElectHeight;
        std::string tmp_str;
        auto st = db::Db::Instance()->Get(tmp_key, &tmp_str);
        if (st.ok()) {
            uint64_t db_height = 0;
            if (!common::StringUtil::ToUint64(tmp_str, &db_height)) {
                return kBlockError;
            }

            if (db_height > height) {
                tmp_key = dict_key_ + "_" + std::to_string(network_id) + "_" + kFieldElectBlock;
                st = db::Db::Instance()->Get(tmp_key, &tmp_str);
                if (!st.ok()) {
                    return kBlockError;
                }

                elect_blocks_map_[network_id] = std::make_pair(db_height, tmp_str);
                return kBlockSuccess;
            }
        }
    } else {
        if (iter->second.first > height) {
            return kBlockSuccess;
        }
    }

    std::string tmp_key = dict_key_ + "_" + std::to_string(network_id) + "_" + kFieldElectBlock;
    db_batch.Put(tmp_key, elect_block_str);
    tmp_key = dict_key_ + "_" + std::to_string(network_id) + "_" + kFieldElectHeight;
    db_batch.Put(tmp_key, std::to_string(height));
    elect_blocks_map_[network_id] = std::make_pair(height, elect_block_str);
    return kBlockSuccess;
}

int DbAccountInfo::GetLatestElectBlock(
        uint32_t network_id,
        uint64_t* height,
        std::string* elect_block_str) {
    {
        std::lock_guard<std::mutex> guard(elect_blocks_map_mutex_);
        auto iter = elect_blocks_map_.find(network_id);
        if (iter != elect_blocks_map_.end()) {
            *height = iter->second.first;
            *elect_block_str = iter->second.second;
            return kBlockSuccess;
        }
    }

    std::string tmp_key = dict_key_ + "_" + std::to_string(network_id) + "_" + kFieldElectHeight;
    std::string tmp_str;
    auto st = db::Db::Instance()->Get(tmp_key, &tmp_str);
    if (!st.ok()) {
        return kBlockError;
    }
        
    if (!common::StringUtil::ToUint64(tmp_str, height)) {
        return kBlockError;
    }

    tmp_key = dict_key_ + "_" + std::to_string(network_id) + "_" + kFieldElectBlock;
    st = db::Db::Instance()->Get(tmp_key, elect_block_str);
    if (!st.ok()) {
        return kBlockError;
    }

    elect_blocks_map_[network_id] = std::make_pair(*height, *elect_block_str);
    return kBlockSuccess;
}

int DbAccountInfo::AddNewTimeBlock(
        uint64_t height,
        uint64_t block_tm,
        uint64_t vss_random,
        db::DbWriteBach& db_batch) {
    if (latest_time_block_heigth_ == common::kInvalidUint64) {
        std::string tmp_key = dict_key_ + "_" + kFieldTimeHeight;
        std::string tmp_str;
        auto st = db::Db::Instance()->Get(tmp_key, &tmp_str);
        if (st.ok()) {
            uint64_t tmp_tm_height = 0;
            if (!common::StringUtil::ToUint64(tmp_str, &tmp_tm_height)) {
                return kBlockError;
            }

            latest_time_block_heigth_ = tmp_tm_height;
            tmp_key = dict_key_ + "_" + kFieldTimeBlock;
            auto st = db::Db::Instance()->Get(tmp_key, &tmp_str);
            if (!st.ok()) {
                return kBlockError;
            }

            uint64_t tmp_tm = 0;
            if (!common::StringUtil::ToUint64(tmp_str, &tmp_tm)) {
                return kBlockError;
            }

            latest_time_block_tm_ = tmp_tm;
            std::string tmp_vss_key = dict_key_ + "_" + kFieldTimeVssRandom;
            st = db::Db::Instance()->Get(tmp_vss_key, &tmp_str);
            if (!st.ok()) {
                return kBlockError;
            }

            uint64_t tmp_vss_random = 0;
            if (!common::StringUtil::ToUint64(tmp_str, &tmp_vss_random)) {
                return kBlockError;
            }
             
            latest_time_block_vss_random_ = tmp_vss_random;
        }
    }

    if (latest_time_block_heigth_ != common::kInvalidUint64 && latest_time_block_heigth_ > height) {
        return kBlockSuccess;
    }

    std::string tmp_h_key = dict_key_ + "_" + kFieldTimeHeight;
    db_batch.Put(tmp_h_key, std::to_string(height));
    std::string tmp_b_key = dict_key_ + "_" + kFieldTimeBlock;
    db_batch.Put(tmp_b_key, std::to_string(block_tm));
    std::string tmp_vss_key = dict_key_ + "_" + kFieldTimeVssRandom;
    db_batch.Put(tmp_vss_key, std::to_string(vss_random));
    latest_time_block_heigth_ = height;
    latest_time_block_tm_ = block_tm;
    latest_time_block_vss_random_ = vss_random;
    return kBlockSuccess;
}

int DbAccountInfo::GetLatestTimeBlock(uint64_t* height, uint64_t* block_tm, uint64_t* vss_random) {
    if (latest_time_block_heigth_ != common::kInvalidUint64 &&
            latest_time_block_tm_ != common::kInvalidUint64) {
        *height = latest_time_block_heigth_;
        *block_tm = latest_time_block_tm_;
        *vss_random = latest_time_block_vss_random_;
        return kBlockSuccess;
    }

    std::string tmp_h_key = dict_key_ + "_" + kFieldTimeHeight;
    std::string tmp_str;
    auto st = db::Db::Instance()->Get(tmp_h_key, &tmp_str);
    if (!st.ok()) {
        return kBlockError;
    }

    uint64_t tmp_val = 0;
    if (!common::StringUtil::ToUint64(tmp_str, &tmp_val)) {
        return kBlockError;
    }

    latest_time_block_heigth_ = tmp_val;
    std::string tmp_b_key = dict_key_ + "_" + kFieldTimeBlock;
    st = db::Db::Instance()->Get(tmp_b_key, &tmp_str);
    if (!st.ok()) {
        return kBlockError;
    }

    if (!common::StringUtil::ToUint64(tmp_str, &tmp_val)) {
        return kBlockError;
    }

    latest_time_block_tm_ = tmp_val;
    std::string tmp_vss_key = dict_key_ + "_" + kFieldTimeVssRandom;
    st = db::Db::Instance()->Get(tmp_vss_key, &tmp_str);
    if (!st.ok()) {
        return kBlockError;
    }

    if (!common::StringUtil::ToUint64(tmp_str, &tmp_val)) {
        return kBlockError;
    }

    latest_time_block_vss_random_ = tmp_val;
    *height = latest_time_block_heigth_;
    *block_tm = latest_time_block_tm_;
    *vss_random = latest_time_block_vss_random_;
    return kBlockSuccess;
}

}  // namespace block

}  // namespace tenon
