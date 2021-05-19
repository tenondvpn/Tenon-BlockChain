#pragma once

#include "common/utils.h"

namespace tenon {

namespace crand {

class ConsistencyRandom {
public:
    static ConsistencyRandom* Instance();
    uint64_t Random() {
        return random_;
    }

private:
    ConsistencyRandom() {}
    ~ConsistencyRandom() {}

    uint64_t random_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(ConsistencyRandom);
};

}  // namespace crand

}  // namespace tenon
