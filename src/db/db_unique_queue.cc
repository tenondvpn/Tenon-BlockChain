#include "stdafx.h"
#include "db/db_unique_queue.h"

#include <iostream>

#include "common/utils.h"
#include "common/string_utils.h"
#include "db/db_utils.h"
#include "db/dict.h"

namespace tenon {

namespace db {

UniqueQueue::UniqueQueue(const std::string& name, uint64_t max_size) {
    std::lock_guard<std::mutex> guard(push_mutex_);
    db_name_ = db::kGlobalDbQueueKeyPrefix + "_" + name;
    db_bindex_name_ = db::kGlobalDbQueueKeyPrefix + "_bi_" + name;
    db_eindex_name_ = db::kGlobalDbQueueKeyPrefix + "_ei_" + name;
    max_size_ = max_size;
    db_uni_dict_name_ = db_name_ + "_uni";

    std::string begin_index_str;
    if (Db::Instance()->Get(db_bindex_name_, &begin_index_str).ok()) {
        uint64_t tmp_index = 0;
        common::StringUtil::ToUint64(begin_index_str, &tmp_index);
        begin_index_ = tmp_index;
    }

    std::string end_index_str;
    if (Db::Instance()->Get(db_eindex_name_, &end_index_str).ok()) {
        uint64_t tmp_index = 0;
        common::StringUtil::ToUint64(end_index_str, &tmp_index);
        end_index_ = tmp_index;
        ++end_index_;
    }

    DB_ERROR("load unique queue period: %u, %u", begin_index_, end_index_);
    for (uint64_t i = begin_index_; i < end_index_; ++i) {
        std::string key = db_name_ + "_" + std::to_string(i);
        std::string val;
        auto st = db::Db::Instance()->Get(key, &val);
        if (!st.ok()) {
            DB_ERROR("db unique get data failed![%s]", key.c_str());
            exit(0);
        }

        unique_id_set_.insert(val);
    }
}

UniqueQueue::~UniqueQueue() {}

bool UniqueQueue::push(const std::string& value, db::DbWriteBach& db_batch) {
    std::lock_guard<std::mutex> guard(push_mutex_);
    auto iter = unique_id_set_.find(value);
    if (iter != unique_id_set_.end()) {
        return false;
    }

    unique_id_set_.insert(value);
    uint64_t end_index = end_index_;
    db_batch.Put(db_eindex_name_, std::to_string(end_index));
    std::string queue_name = db_name_ + "_" + std::to_string(end_index);
    db_batch.Put(queue_name, value);
    while (end_index_ - begin_index_ > max_size_) {
        std::string value;
        pop(&value, db_batch);
    }

    ++end_index_;
    return true;
}

uint64_t UniqueQueue::size() {
    return end_index_ - begin_index_;
}

bool UniqueQueue::begin(std::string* value) {
    std::string queue_name = db_name_ + "_" + std::to_string(begin_index_);
    auto res = Db::Instance()->Get(queue_name, value);
    if (!res.ok()) {
        return false;
    }

    return true;
}

bool UniqueQueue::pop(std::string* value, db::DbWriteBach& db_batch) {
    uint64_t begin_index = begin_index_;
    db_batch.Put(db_bindex_name_, std::to_string(begin_index + 1));
    ++begin_index_;
    std::string queue_name = db_name_ + "_" + std::to_string(begin_index);
    db_batch.Delete(queue_name);
    return true;
}

bool UniqueQueue::get(uint64_t index, std::string* value) {
    uint64_t begin_index = index;
    std::string queue_name = db_name_ + "_" + std::to_string(begin_index);
    auto res = Db::Instance()->Get(queue_name, value);
    if (!res.ok()) {
        return false;
    }

    return true;
}

}  // db

}  // tenon
