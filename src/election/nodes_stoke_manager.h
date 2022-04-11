#pragma once

#include "db/db_unique_queue.h"
#include "election/elect_utils.h"

namespace tenon {

namespace elect {

class NodesStokeManager {
public:
    static NodesStokeManager* Instance();

private:
    NodesStokeManager() {}
    ~NodesStokeManager() {}

    DISALLOW_COPY_AND_ASSIGN(NodesStokeManager);
};

}  // namespace elect

}  // namespace tenon