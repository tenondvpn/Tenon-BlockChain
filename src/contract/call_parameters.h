#pragma once

#include <functional>

#include "contract/contract_utils.h"

namespace lego {

namespace contract {

class VMFace;
class ExtVMFace;
using OnOpFunc = std::function<void(
    uint64_t,
    uint64_t,
    uint8_t,
    uint64_t,
    uint64_t,
    uint64_t,
    VMFace const*,
    ExtVMFace const*)>;

struct CallParameters {
//     CallParameters(
//         const std::string& in_from,
//         const std::string& in_to,
//         const std::string& in_code_address,
//         uint64_t in_value,
//         uint64_t in_apparent_value,
//         uint64_t in_gas,
//         const std::string& in_data,
//         OnOpFunc in_op)
//         : from(in_from),
//           to(in_to),
//           code_address(in_code_address),
//           value(in_value),
//           apparent_value(in_apparent_value),
//           gas(in_gas),
//           data(in_data),
//           on_op(in_op) {}
    std::string from;
    std::string to;
    std::string code_address;
    uint64_t value;
    uint64_t apparent_value;
    uint64_t gas;
    std::string data;
    OnOpFunc on_op;
};

}  // namespace contact

}  // namespace lego
