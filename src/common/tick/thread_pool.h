#pragma once

#include <functional>
#include <chrono>
#include <memory>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>

#include "common/utils.h"

namespace tenon {

namespace common {

typedef std::function<void(void)> TickCallbackFunction;
struct Item {
    Item(
            const std::chrono::steady_clock::time_point& cut,
            TickCallbackFunction cb,
            uint32_t tmp_idx)
            : cutoff_time(cut), callback(cb), idx(tmp_idx), hold(false) {}
    ~Item() {}
    std::chrono::steady_clock::time_point cutoff_time;
    TickCallbackFunction callback;
    uint32_t idx;
    bool hold;
};

typedef std::shared_ptr<Item> TickItemPtr;

class TickThreadPool {
public:
    static TickThreadPool* Instance();
    void Destroy();
    void RemoveTick(uint32_t tick_idx);
    void AddTick(uint32_t idx, int64_t cutoff_us, TickCallbackFunction call);
    uint32_t TickIndex() {
        return ++timer_idx_;
    }

private:
    TickThreadPool();
    ~TickThreadPool();

    static const uint32_t kTickThreadPoolCount = 1U;
    static const uint64_t kTickSleepUs = 50000ull;

    void Ticking();
    TickItemPtr Get(uint32_t& idx);

    bool destroy_{ false };
    std::mutex destroy_mutex_;
    std::vector<std::shared_ptr<std::thread>> thread_pool_;
    std::vector<TickItemPtr> tick_items_;
    std::mutex tick_items_mutex_;
    uint32_t tick_handled_index_{ 0 };
    std::atomic<uint32_t> timer_idx_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(TickThreadPool);
};

}  // namespace common

}  // namespace tenon
