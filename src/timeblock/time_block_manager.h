#pragma once

#include "common/utils.h"
#include "common/time_utils.h"

namespace tenon {

namespace tmblock {

class TimeBlockManager {
public:
    static TimeBlockManager* Instance();
    uint64_t LatestTimestamp() {
        return common::TimeUtils::TimestampSeconds();
    }

private:
    TimeBlockManager() {}
    ~TimeBlockManager() {}

    DISALLOW_COPY_AND_ASSIGN(TimeBlockManager);
};

}  // namespace tmblock

}  // namespace tenon