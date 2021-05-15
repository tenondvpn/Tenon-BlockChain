#include "common/header_type.h"

namespace lego {

namespace common {

HeaderType* HeaderType::Instance() {
    static HeaderType ins;
    return &ins;
}

}  // namespace common

}  // namespace lego
