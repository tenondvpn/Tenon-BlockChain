#include "crand/consistency_random.h"

namespace tenon {

namespace crand {

ConsistencyRandom* ConsistencyRandom::Instance() {
    static ConsistencyRandom ins;
    return &ins;
}
    
}  // namespace crand

}  // namespace tenon
