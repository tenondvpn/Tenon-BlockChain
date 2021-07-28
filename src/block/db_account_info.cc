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

bool DbAccountInfo::AddNewAccountToDb(const std::string& uni_account_id, db::DbWriteBach& db_batch) {
    {
        std::string key = db::kGlobalDickKeyAccountIdExists + "_" + uni_account_id;
        std::string tmp_val("1");
        db_batch.Put(key, tmp_val);
    }

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
        : account_id_(account_id) {
    dict_key_ = db::kGlobalDickKeyAccountInfo + account_id_;
    pool_index_ = common::GetPoolIndex(account_id_);
//     uint64_t* height_data = tx_height_queue_.mem_data();
//     for (uint32_t hight_idx = 0; hight_idx < tx_height_queue_.size(); ++hight_idx) {
//         std::string block_str;
//         if (GetBlockWithHeight(height_data[hight_idx], &block_str) != kBlockSuccess) {
//             continue;
//         }
// 
//         bft::protobuf::Block block;
//         if (!block.ParseFromString(block_str)) {
//             continue;
//         }
// 
//         for (int32_t i = 0; i < block.tx_list_size(); ++i) {
//             if (block.tx_list(i).amount() <= 0) {
//                 continue;
//             }
// 
//             if (block.tx_list(i).from() == account_id_ ||
//                     block.tx_list(i).to() == account_id_) {
//                 common::BlockItemPtr block_item;
//                 block_item.item = new common::BlockItem();
//                 block_item.item->height = height_data[hight_idx];
//                 block_item.item->block_hash = block.hash();
//                 block_item.item->gid = block.tx_list(i).gid();
//                 block_item.item->from = block.tx_list(i).from();
//                 block_item.item->to = block.tx_list(i).to();
//                 block_item.item->amount = block.tx_list(i).amount();
//                 block_item.item->balance = block.tx_list(i).balance();
//                 block_item.item->type = block.tx_list(i).type();
//                 block_item.item->status = block.tx_list(i).status();
//                 block_item.item->timestamp = block.timestamp();
//                 block_item.item->version = block.tx_list(i).version();
//                 if (top_height_blocks_.size() >= kTopTxHeightBlocksCount) {
//                     auto item_ptr = top_height_blocks_.top().item;
//                     top_height_blocks_.pop();
//                     delete item_ptr;
//                 }
// 
//                 auto res = top_height_blocks_.push(block_item);
//             }
//         }
//     }
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
//     height_queue_.push(height, db_batch);
}

void DbAccountInfo::GetHeights(std::vector<uint64_t>* res) {
//     uint64_t* height_data = height_queue_.mem_data();
//     for (uint32_t i = 0; i < height_queue_.size(); ++i) {
//         res->push_back(height_data[i]);
//     }
}

// void DbAccountInfo::NewTxHeight(
//         uint64_t height,
//         uint64_t timestamp,
//         const std::string& hash,
//         const bft::protobuf::TxInfo& tx_info,
//         db::DbWriteBach& db_batch) {
//     if (tx_info.amount() <= 0) {
//         return;
//     }
// 
//     {
//         if (tx_info.from() == account_id_ || tx_info.to() == account_id_) {
//             common::BlockItemPtr block_item;
//             block_item.item = new common::BlockItem();
//             block_item.item->height = height;
//             block_item.item->timestamp = timestamp;
//             block_item.item->block_hash = hash;
//             block_item.item->gid = tx_info.gid();
//             block_item.item->from = tx_info.from();
//             block_item.item->to = tx_info.to();
//             block_item.item->amount = tx_info.amount();
//             block_item.item->balance = tx_info.balance();
//             block_item.item->type = tx_info.type();
//             block_item.item->status = tx_info.status();
//             block_item.item->version = tx_info.version();
//             std::lock_guard<std::mutex> guard(top_height_blocks_mutex_);
//             if (top_height_blocks_.size() >= kTopTxHeightBlocksCount) {
//                 auto item_ptr = top_height_blocks_.top().item;
//                 top_height_blocks_.pop();
//                 delete item_ptr;
//             }
// 
//             top_height_blocks_.push(block_item);
//         }
//     }
// 
//     BLOCK_ERROR("acount new tx height, account id: %s, amount: %llu, balance: %llu",
//             common::Encode::HexEncode(account_id_).c_str(),
//             tx_info.amount(),
//             tx_info.balance());
//     {
//         std::lock_guard<std::mutex> guard(tx_height_queue_mutex_);
//         tx_height_queue_.push(height, db_batch);
//     }
// }

// common::BlockItemPtr* DbAccountInfo::GetHeightBlockInfos(uint32_t* count) {
//     *count = top_height_blocks_.size();
//     return top_height_blocks_.data();
// }

// void DbAccountInfo::GetTxHeights(std::vector<uint64_t>* res) {
//     uint64_t* height_data = tx_height_queue_.mem_data();
//     for (uint32_t i = 0; i < tx_height_queue_.size(); ++i) {
//         res->push_back(height_data[i]);
//     }
// }

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
//     {
//         std::lock_guard<std::mutex> guard(max_hash_mutex_);
//         max_hash_ = hash;
//     }

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

int DbAccountInfo::SetAttrWithHeight(
        const std::string& attr_key,
        uint64_t height,
        db::DbWriteBach& db_batch) {
    std::string tmp_key = dict_key_ + "_" + kFieldAttrsWithHeight;
    if (!db::Dict::Instance()->Hset(
            tmp_key,
            attr_key,
            std::to_string(height),
            db_batch)) {
        return kBlockError;
    }

    {
        std::lock_guard<std::mutex> guard(attrs_with_height_map_mutex_);
        attrs_with_height_map_[attr_key] = height;
    }

    return kBlockSuccess;

}

int DbAccountInfo::GetAttrWithHeight(const std::string& attr_key, uint64_t* height) {
    {
        std::lock_guard<std::mutex> guard(attrs_with_height_map_mutex_);
        auto iter = attrs_with_height_map_.find(attr_key);
        if (iter != attrs_with_height_map_.end()) {
            *height = iter->second;
            return kBlockSuccess;
        }
    }

    std::string tmp_key = dict_key_ + "_" + kFieldAttrsWithHeight;
    std::string tmp_str;
    if (!db::Dict::Instance()->Hget(
            tmp_key,
            attr_key,
            &tmp_str)) {
        return kBlockError;
    }

    if (!common::StringUtil::ToUint64(tmp_str, height)) {
        return kBlockError;
    }

    {
        std::lock_guard<std::mutex> guard(attrs_with_height_map_mutex_);
        attrs_with_height_map_[attr_key] = *height;
    }

    return kBlockSuccess;
}

int DbAccountInfo::GetAttrValue(const std::string& key, std::string* value) {
    auto st = db::Db::Instance()->Get(StorageDbKey(account_id_, key), value);
    if (st.ok()) {
        return kBlockSuccess;
    }

    return kBlockError;
}

int DbAccountInfo::SetAttrValue(
        const std::string& key,
        const std::string& value,
        db::DbWriteBach& db_batch) {
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

    return kBlockSuccess;
}

int DbAccountInfo::GetBytesCode(std::string* bytes_code) {
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
