#pragma once

#include "common/utils.h"

namespace lego {

namespace common {

template<class T, uint32_t kMaxSize>
class MessageWindow {
public:
    MessageWindow() {
        memset(windows_, 0, sizeof(T) * kMaxSize);
    }

    ~MessageWindow() {}

    bool push(T item) {
        if (count_ + 1 - start_msg_no_ >= kMaxSize) {
            return false;
        }

        windows_[count_ % kMaxSize] = item;
        ++count_;
        return true;
    }

    T pop(uint32_t* msg_no) {
        if (count_ - start_msg_no_ == 0) {
            return nullptr;
        }

        T item = windows_[start_msg_no_ % kMaxSize];
        *msg_no = start_msg_no_;
        ++start_msg_no_;
        return item;
    }

private:
    T windows_[kMaxSize];
    uint32_t start_msg_no_{ 0 };
    uint32_t count_{ 0 };
};

}  // namespace common 

}  // namespace lego