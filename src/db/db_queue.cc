#include "stdafx.h"
#include "db/db_queue.h"

#include "common/utils.h"
#include "common/string_utils.h"
#include "db/db_utils.h"

namespace tenon {

namespace db {

Queue::Queue(const std::string& name, uint32_t max_size) {
    db_name_ = db::kGlobalDbQueueKeyPrefix + "_" + name;
    db_bindex_name_ = db::kGlobalDbQueueKeyPrefix + "_bi_" + name;
    db_eindex_name_ = db::kGlobalDbQueueKeyPrefix + "_ei_" + name;
    max_size_ = max_size;

    std::string begin_index_str;
    if (Db::Instance()->Get(db_bindex_name_, &begin_index_str).ok()) {
        uint32_t tmp_height = 0;
        common::StringUtil::ToUint32(begin_index_str, &tmp_height);
        begin_index_ = tmp_height;
    }

    std::string end_index_str;
    if (Db::Instance()->Get(db_eindex_name_, &end_index_str).ok()) {
        uint32_t tmp_index = 0;
        common::StringUtil::ToUint32(end_index_str, &tmp_index);
        end_index_ = tmp_index;
        ++end_index_;
    }
}

Queue::~Queue() {}

bool Queue::push(const std::string& value) {
    uint32_t end_index = end_index_;
    auto res = Db::Instance()->Put(db_eindex_name_, std::to_string(end_index));
    if (!res.ok()) {
        return false;
    }

    std::string queue_name = db_name_ + "_" + std::to_string(end_index);
    res = Db::Instance()->Put(queue_name, value);
    if (!res.ok()) {
        return false;
    }

    while (end_index_ - begin_index_ > max_size_) {
        std::string value;
        pop(&value);
    }

    ++end_index_;
    return true;
}

uint32_t Queue::size() {
    return end_index_ - begin_index_;
}

bool Queue::pop(std::string* value) {
    uint32_t begin_index = begin_index_;
    auto res = Db::Instance()->Put(db_bindex_name_, std::to_string(begin_index + 1));
    if (!res.ok()) {
        return false;
    }

    std::string queue_name = db_name_ + "_" + std::to_string(begin_index);
    res = Db::Instance()->Delete(queue_name);
    if (!res.ok()) {
        return false;
    }

    ++begin_index_;
    return true;
}

bool Queue::get(uint32_t index, std::string* value) {
    uint32_t begin_index = begin_index_ + index;
    std::string queue_name = db_name_ + "_" + std::to_string(begin_index);
    auto res = Db::Instance()->Get(queue_name, value);
    if (!res.ok()) {
        return false;
    }

    return true;
}

}  // db

}  // tenon
