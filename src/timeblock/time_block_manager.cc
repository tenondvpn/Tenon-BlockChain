#include "timeblock/time_block_manager.h"

namespace tenon {

namespace tmblock {

TimeBlockManager* TimeBlockManager::Instance() {
    static TimeBlockManager ins;
    return &ins;
}

}  // namespace tmblock

}  // namespace tenon