#include "common/header_type.h"

namespace tenon {

namespace common {

HeaderType* HeaderType::Instance() {
    static HeaderType ins;
    return &ins;
}

}  // namespace common

}  // namespace tenon
