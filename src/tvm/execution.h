#pragma once

#include "common/utils.h"
#include "evmc/evmc.hpp"
#include "evmc/mocked_host.hpp"

namespace tenon {

namespace tvm {

class TenonHost;
class Execution {
public:
    static Execution* Instance();
    int Init();
    int execute(
        const std::string& contract_address,
        const std::string& input,
        const std::string& from_address,
        const std::string& to_address,
        const std::string& origin_address,
        uint64_t value,
        uint64_t max_gas,
        uint32_t depth,
        uint32_t call_mode,
        tenon::tvm::TenonHost& host,
        evmc::result* res);
    int InitEnvironment(tenon::tvm::TenonHost& tenon_host, evmc_message* msg);

private:
    Execution();
    ~Execution();

    evmc::VM evm_;

    DISALLOW_COPY_AND_ASSIGN(Execution);
};

}  // namespace tvm

}  //namespace tenon

