#include "tvm/execution.h"

#include "common/encode.h"
#include "evmone/evmone.h"
#include "evmc/loader.h"
#include "evmc/hex.hpp"
#include "evmc/evmc.h"
#include "evmc/mocked_host.hpp"
#include "tvm/tvm_utils.h"
#include "tvm/tenon_host.h"
#include "block/account_manager.h"

namespace tenon {

namespace tvm {

Execution::Execution() {}

Execution::~Execution() {}

// create no param: contract bytes_code + 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000
//       has param: contract bytes_code + 000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000 + encode params
int Execution::execute(
        const std::string& bytes_code,
        const std::string& str_input,
        const std::string& from_address,
        const std::string& to_address,
        const std::string& origin_address,
        uint64_t value,
        uint64_t gas_limit,
        uint32_t depth,
        bool is_create,
        tenon::tvm::TenonHost& host,
        evmc::result* out_res) {
    evmc::VM evm;
    evmc_loader_error_code ec;
    evm = evmc::VM{ evmc_load_and_configure("./libevmone.so", &ec) };
    if (ec != EVMC_LOADER_SUCCESS) {
        const auto error = evmc_last_error_msg();
        if (error != nullptr)
            std::cerr << error << "\n";
        else
            std::cerr << "Loading error " << ec << "\n";
        return static_cast<int>(ec);
    }


    if (evm.set_option("O", "0") != EVMC_SET_OPTION_SUCCESS) {
        return kTvmError;
    }

    const size_t code_size = bytes_code.size();
    int64_t gas = gas_limit;
    auto rev = EVMC_ISTANBUL;
    auto create_gas = gas_limit;

    evmc_message msg{};
    msg.gas = gas;
    msg.input_data = (uint8_t*)str_input.c_str();
    msg.input_size = str_input.size();

    memcpy(
        msg.sender.bytes,
        from_address.c_str(),
        sizeof(msg.sender.bytes));
    memcpy(
        msg.destination.bytes,
        to_address.c_str(),
        sizeof(msg.destination.bytes));
    const uint8_t* exec_code_data = nullptr;
    size_t exec_code_size = 0;
    if (is_create) {
        evmc_message create_msg{};
        create_msg.kind = EVMC_CREATE;
        create_msg.destination = msg.destination;        create_msg.gas = create_gas;
        const auto create_result = evm.execute(
            host,
            rev,
            create_msg,
            (uint8_t*)bytes_code.c_str(),
            bytes_code.size());
        if (create_result.status_code != EVMC_SUCCESS) {
            const auto gas_used = create_msg.gas - create_result.gas_left;
            std::cout << "\nResult:   " << create_result.status_code << "\nGas used: " << gas_used << "\n";
            return create_result.status_code;
        }

        auto& created_account = host.accounts_[msg.destination];
        created_account.code = evmc::bytes(create_result.output_data, create_result.output_size);
        exec_code_data = created_account.code.data();
        exec_code_size = created_account.code.size();
        const auto gas_used = create_msg.gas - create_result.gas_left;
        std::cout << "\nResult:   " << create_result.status_code << "\nGas used: " << gas_used << "\n";

        if (create_result.status_code == EVMC_SUCCESS || create_result.status_code == EVMC_REVERT)
            std::cout << "Output:   " << evmc::hex(create_result.output_data, create_result.output_size) << "\n";
        return 0;
    } else {
        exec_code_data = (uint8_t*)bytes_code.c_str();
        exec_code_size = bytes_code.size();
    }

    *out_res = evm.execute(host, rev, msg, exec_code_data, exec_code_size);
    const auto gas_used = msg.gas - out_res->gas_left;
    std::cout << "\nResult:   " << out_res->status_code << "\nGas used: " << gas_used << "\n";

    if (out_res->status_code == EVMC_SUCCESS || out_res->status_code == EVMC_REVERT)
        std::cout << "Output:   " << evmc::hex(out_res->output_data, out_res->output_size) << "\n";

    return 0;
}

}  // namespace tvm

}  //namespace tenon
