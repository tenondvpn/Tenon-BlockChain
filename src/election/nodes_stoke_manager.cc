#include "election/nodes_stoke_manager.h"

namespace tenon {

namespace elect {

NodesStokeManager* NodesStokeManager::Instance() {
    static NodesStokeManager ins;
    return &ins;
}

}  // namespace elect

}  // namespace tenon