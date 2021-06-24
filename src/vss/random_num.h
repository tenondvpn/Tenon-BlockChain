#pragma once

#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <memory>

#include "common/random.h"
#include "common/hash.h"
#include "common/limit_heap.h"
#include "vss/vss_utils.h"

namespace tenon {

namespace vss {

class RandomNum {
public:
    explicit RandomNum(bool is_local = false) : is_local_(is_local) {}

    ~RandomNum() {}

    void ResetStatus() {
        std::lock_guard<std::mutex> guard(mutex_);
        Clear();
    }

    void OnTimeBlock(uint64_t tm_block_tm) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (tm_block_tm_ >= tm_block_tm) {
            return;
        }

        Clear();
        if (!is_local_) {
            return;
        }

        srand(time(NULL));
        std::string hash_str;
        for (uint32_t i = 0; i < kVssRandomSplitCount; ++i) {
            random_nums_[i] = common::Random::RandomUint64();
            final_random_num_ ^= random_nums_[i];
        }

        random_num_hash_ = common::Hash::Hash64(std::to_string(final_random_num_));
        tm_block_tm_ = tm_block_tm;
        valid_ = true;
    }

    void SetHash(uint64_t hash_num) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (valid_ || is_local_) {
            return;
        }

        random_num_hash_ = hash_num;
    }

    uint64_t GetHash() {
        std::lock_guard<std::mutex> guard(mutex_);
        return random_num_hash_;
    }

    void GetRandomNum(uint64_t* out_data) {
        std::lock_guard<std::mutex> guard(mutex_);
        memcpy(out_data, random_nums_, sizeof(random_nums_));
    }

    uint64_t GetFinalRandomNum() {
        std::lock_guard<std::mutex> guard(mutex_);
        return final_random_num_;
    }
    
    void SetFinalRandomNum(uint64_t final_random_num) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (valid_ || is_local_) {
            return;
        }

        auto rand_hash = common::Hash::Hash64(std::to_string(final_random_num));
        if (rand_hash == random_num_hash_) {
            final_random_num_ = final_random_num;
            valid_ = true;
        }
    }

    void SetRandomNum(
            uint64_t tm_block_tm,
            const std::string& from_id,
            uint32_t index,
            uint64_t rand_num) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (valid_ || is_local_) {
            return;
        }

        if (index >= kVssRandomSplitCount) {
            return;
        }

        auto iter = added_id_set_.find(from_id);
        if (iter != added_id_set_.end()) {
            return;
        }

        auto num_iter = split_num_map_[index].find(rand_num);
        if (num_iter == split_num_map_[index].end()) {
            split_num_map_[index][rand_num] = 1;
            max_random_count_[index] = std::make_pair(rand_num, 1);
        } else {
            ++num_iter->second;
            if (max_random_count_[index].second < num_iter->second) {
                max_random_count_[index] = std::make_pair(rand_num, num_iter->second);
            }
        }

        auto final_num = 0;
        for (uint32_t i = 0; i < kVssRandomSplitCount; ++i) {
            final_num ^= max_random_count_[i].first;
        }

        auto random_num_hash = common::Hash::Hash64(std::to_string(final_num));
        if (random_num_hash == random_num_hash_) {
            final_random_num_ = final_num;
            valid_ = true;
        }
    }

private:
    void Clear() {
        for (uint32_t i = 0; i < kVssRandomSplitCount; ++i) {
            split_num_map_[i].clear();
        }

        memset(random_nums_, 0, sizeof(random_nums_));
        memset(max_random_count_, 0, sizeof(max_random_count_));
        final_random_num_ = 0;
        tm_block_tm_ = 0;
        random_num_hash_ = 0;
        added_id_set_.clear();
        valid_ = false;
    }

    std::mutex mutex_;
    uint64_t random_nums_[kVssRandomSplitCount] = { 0 };
    uint64_t final_random_num_{ 0 };
    uint64_t tm_block_tm_{ 0 };
    uint64_t random_num_hash_{ 0 };
    std::unordered_map<uint64_t, uint32_t> split_num_map_[kVssRandomSplitCount];
    std::pair<uint64_t, uint32_t> max_random_count_[kVssRandomSplitCount];
    std::unordered_set<std::string> added_id_set_;
    bool valid_{ false };
    bool is_local_{ false };

    DISALLOW_COPY_AND_ASSIGN(RandomNum);
};

typedef std::shared_ptr<RandomNum> RandomNumPtr;

}  // namespace vss

}  // namespace tenon
