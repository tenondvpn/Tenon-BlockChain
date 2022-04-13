#pragma once

#include <atomic>
#include <unordered_set>

#include "db.h"

namespace tenon {

namespace db {

class UniqueQueue {
public:
    UniqueQueue(const std::string& name, uint64_t max_size);
    ~UniqueQueue();
    bool push(const std::string& value, db::DbWriteBach& db_batch);
    bool get(uint64_t index, std::string* value);
    uint64_t size();
    bool pop(std::string* value, db::DbWriteBach& db_batch);
    bool begin(std::string* value);

    uint64_t begin_index() {
        return begin_index_;
    }

    uint64_t end_index() {
        return end_index_;
    }

private:

    std::string db_bindex_name_;
    std::string db_eindex_name_;
    std::string db_name_;
    std::string db_uni_dict_name_;
    uint64_t begin_index_{ 0 };
    uint64_t end_index_{ 0 };
    uint64_t max_size_{ 0 };
    std::unordered_set<std::string> unique_id_set_;
    std::mutex push_mutex_;
    DISALLOW_COPY_AND_ASSIGN(UniqueQueue);

};

}  // db

}  // tenon
