#pragma once

#include "readerwriterqueue/readerwriterqueue.h"

namespace tenon {

namespace common {

template<class T>
class ThreadSafeQueue {
public:
    ThreadSafeQueue() {}

    ~ThreadSafeQueue() {}

    void push(T e) {
        rw_queue_.enqueue(e);
    }

    bool pop(T* e) {
        return rw_queue_.try_dequeue(*e);
    }

    size_t size() {
        return rw_queue_.size_approx();
    }

private:
    moodycamel::ReaderWriterQueue<T, 1024> rw_queue_;

    DISALLOW_COPY_AND_ASSIGN(ThreadSafeQueue);
};

}  // namespace common

}  // namespace tenon
