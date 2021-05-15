#include "contract/contract_utils.h"

#include "common/hash.h"

namespace lego {

namespace contract {

std::string GetContractAddress(
        const std::string& from,
        const std::string& gid,
        const std::string& bytes_code) {
    return common::Hash::Sha256(from + gid + bytes_code);
}

}  // namespace contact

}  // namespace lego
