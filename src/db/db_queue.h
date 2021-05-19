#pragma once

#include <atomic>

#include "db.h"

namespace tenon {

namespace db {

class Queue {
public:
    Queue(const std::string& name, uint32_t max_size);
    ~Queue();
    bool push(const std::string& value);
    bool pop(std::string* value);
    bool get(uint32_t index, std::string* value);
    uint32_t size();

private:
    std::string db_bindex_name_;
    std::string db_eindex_name_;
    std::string db_name_;
    std::atomic<uint32_t> begin_index_{ 0 };
    std::atomic<uint32_t> end_index_{ 0 };
    uint32_t max_size_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(Queue);

};

}  // db

}  // tenon
