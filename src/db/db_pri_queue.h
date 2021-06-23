#pragma once

#include "db/db.h"
#include "db/dict.h"
#include "common/string_utils.h"
#include "common/min_heap.h"
#include "db/db_utils.h"

namespace tenon {

namespace db {

static const std::string kFieldSize = "kFieldSize";

template <class Type, uint32_t kMaxSize>
class DbPriQueue {
public:
    DbPriQueue(const std::string& name) {
        dict_name_ = db::kGlobalDbPriQueuePrefix + "_" + name;
        std::string tmp_val;
        if (db::Dict::Instance()->Hget(dict_name_, kFieldSize, &tmp_val)) {
            size_ = common::StringUtil::ToUint32(tmp_val);
        }

        for (uint32_t i = 0; i < size_; ++i) {
            std::string key = dict_name_ + "_" + std::to_string(i);
            std::string val;
            auto res = db::Db::Instance()->Get(key, &val);
            if (!res.ok()) {
                DB_ERROR("db get data failed![%s]", key.c_str());
                assert(false);
                exit(0);
            }

            data_[i] = *((Type*)val.c_str());
            mem_min_heap_.push(data_[i]);
            unique_set_.insert(data_[i]);
        }
    }

    ~DbPriQueue() {}
    
    inline common::LimitHeap<Type> GetMemData() {
        return mem_min_heap_;
    }

    inline void push(Type val, db::DbWriteBach& db_batch) {
        if (size_ > 0 && val < data_[0]) {
            return;
        }

        if (unique_set_.find(val) != unique_set_.end()) {
            return;
        }

        unique_set_.insert(val);
        if (size_ >= kMaxSize) {
            PopByPush(db_batch);
        }

        data_[size_] = val;
        ++size_;

        {
            std::string key = dict_name_ + "_" + std::to_string(size_ - 1);
            std::string tmp_val((char*)&val, sizeof(Type));
            db_batch.Put(key, tmp_val);
        }

        db::Dict::Instance()->Hset(dict_name_, kFieldSize, std::to_string(size_), db_batch);
        AdjustUp(size_ - 1, db_batch);
        mem_min_heap_.push(val);
    }

    inline void pop(db::DbWriteBach& db_batch) {
        PopByPush(db_batch);
        mem_min_heap_.pop();
    }

    inline Type top() {
        return data_[0];
    }

    inline bool empty() {
        return size_ == 0;
    }

    inline Type* mem_data() {
        return mem_min_heap_.data();
    }

    inline uint32_t size() {
        return size_;
    }

private:
    void AdjustDown(int index, db::DbWriteBach& db_batch) {
        while (true) {
            int l_child = LeftChild(index);
            if (l_child >= size_) {
                break;
            }

            int r_child = RightChild(index);
            if (r_child >= size_) {
                if (!(data_[l_child] < data_[index])) {
                    break;
                }

                Swap(l_child, index, db_batch);
                index = l_child;
                continue;
            }

            if (data_[index] < data_[r_child] &&
                    data_[index] < data_[l_child]) {
                break;
            }

            if (data_[l_child] < data_[r_child]) {
                Swap(l_child, index, db_batch);
                index = l_child;
            } else {
                Swap(r_child, index, db_batch);
                index = r_child;
            }
        }
    }

    void AdjustUp(int index, db::DbWriteBach& db_batch) {
        while (index > 0) {
            int parent_idx = ParentIndex(index);
            if (parent_idx > index) {
                break;
            }

            if (!(data_[index] < data_[parent_idx])) {
                break;
            }

            Swap(index, parent_idx, db_batch);
            index = parent_idx;
        }
    }

    inline void PopByPush(db::DbWriteBach& db_batch) {
        unique_set_.erase(data_[0]);
        Swap(0, size_ - 1, db_batch);
        --size_;
        db::Dict::Instance()->Hset(dict_name_, kFieldSize, std::to_string(size_), db_batch);
        AdjustDown(0, db_batch);
    }

    inline int LeftChild(int index) {
        return 2 * index + 1;
    }

    inline int RightChild(int index) {
        return 2 * index + 2;
    }

    inline int ParentIndex(int index) {
        if (index % 2 == 0) {
            return index / 2 - 1;
        }

        return index / 2;
    }

    inline void Swap(int l, int r, db::DbWriteBach& db_batch) {
        Type tmp_val = data_[l];
        data_[l] = data_[r];
        {
            std::string key = dict_name_ + "_" + std::to_string(l);
            std::string val((char*)&(data_[l]), sizeof(Type));
            db_batch.Put(key, val);
        }

        data_[r] = tmp_val;
        {
            std::string key = dict_name_ + "_" + std::to_string(r);
            std::string val((char*)&(data_[r]), sizeof(Type));
            db_batch.Put(key, val);
        }
    }

    Type data_[kMaxSize];
    int32_t size_{ 0 };
    std::string dict_name_;
    common::LimitHeap<Type> mem_min_heap_{ true, kMaxSize };
    std::unordered_set<Type> unique_set_;

    DISALLOW_COPY_AND_ASSIGN(DbPriQueue);
};

}  // db

}  // tenon
