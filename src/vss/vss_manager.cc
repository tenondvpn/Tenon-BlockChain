#include "stdafx.h"
#include "vss/vss_manager.h"

namespace tenon {

namespace vss {

VssManager* VssManager::Instance() {
    static VssManager ins;
    return &ins;
}

}  // namespace vss

}  // namespace tenon
