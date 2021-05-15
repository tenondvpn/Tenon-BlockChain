#pragma once

#include "evmc/evmc.h"

#include "common/utils.h"
#include "common/log.h"

#define TVM_DEBUG(fmt, ...) TENON_DEBUG("[TVM]" fmt, ## __VA_ARGS__)
#define TVM_INFO(fmt, ...) TENON_INFO("[TVM]" fmt, ## __VA_ARGS__)
#define TVM_WARN(fmt, ...) TENON_WARN("[TVM]" fmt, ## __VA_ARGS__)
#define TVM_ERROR(fmt, ...) TENON_ERROR("[TVM]" fmt, ## __VA_ARGS__)

namespace lego {

namespace tvm {

enum TvmErrorCode {
    kTvmSuccess = 0,
    kTvmError = 1,
    kTvmKeyExsits = 2,
    kTvmKeyAdded = 3,
    kTvmBlockReloaded = 4,
    kTvmContractNotExists = 5,
};

inline static void Uint64ToEvmcBytes32(evmc_bytes32& bytes32, uint64_t value) {
    for (std::size_t i = 0; i < sizeof(value); ++i) {
        bytes32.bytes[sizeof(bytes32.bytes) - 1 - i] = static_cast<uint8_t>(value >> (8 * i));
    }
}

inline static uint64_t EvmcBytes32ToUint64(const evmc_bytes32& bytes32) {
    uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(uint64_t); ++i) {
        value += (((uint64_t)(bytes32.bytes[sizeof(bytes32.bytes) - 1 - i])) << (8 * i));
    }

    return value;
}

}  // namespace tvm

}  // namespace lego

#if __cplusplus
extern "C" {
#endif

    const struct evmc_host_interface* tvm_host_get_interface();

    struct evmc_host_context* tvm_host_create_context(struct evmc_tx_context tx_context);

    void tvm_host_destroy_context(struct evmc_host_context* context);

#if __cplusplus
}
#endif
