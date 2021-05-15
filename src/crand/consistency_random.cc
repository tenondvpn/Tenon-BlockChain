#include "crand/consistency_random.h"

namespace lego {

namespace crand {

ConsistencyRandom* ConsistencyRandom::Instance() {
    static ConsistencyRandom ins;
    return &ins;
}
    
}  // namespace crand

}  // namespace lego