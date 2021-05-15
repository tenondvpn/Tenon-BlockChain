#include "stdafx.h"
#include "common/state_lock.h"

namespace lego {

namespace common {

StateLock::StateLock(int32_t cnt) : count_(cnt) {}

void StateLock::Wait() {
    std::unique_lock<std::mutex> lock(mutex_);
    if (count_ <= 0) {
        return;
    }

    con_.wait(lock, [this] { return count_ <= 0; });
}

void StateLock::Signal() {
    std::unique_lock<std::mutex> lock(mutex_);
    --count_;
    con_.notify_one();
}

bool StateLock::WaitFor(int64_t wait_us) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (count_ <= 0) {
        return true;
    }

    bool waited = con_.wait_for(
            lock,
            std::chrono::microseconds(wait_us),
            [this] { return count_ <= 0; });
    if (!waited) {
        return false;
    }

    return true;
}

}  // namespace common

}  // namespace lego
