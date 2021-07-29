#pragma once

#include <atomic>

#include "db.h"

namespace tenon {

namespace db {

class Queue {
public:
    Queue(const std::string& name, uint64_t max_size);
    ~Queue();
    bool push(const std::string& value, db::DbWriteBach& db_batch);
    bool pop(std::string* value, db::DbWriteBach& db_batch);
    bool get(uint64_t index, std::string* value);
    uint64_t size();
    uint64_t begin_index() {
        return begin_index_;
    }

    uint64_t end_index() {
        return end_index_;
    }

private:
    std::string db_name_;
    uint64_t begin_index_{ 0 };
    uint64_t end_index_{ 0 };
    uint64_t max_size_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(Queue);

};

}  // db

}  // tenon
