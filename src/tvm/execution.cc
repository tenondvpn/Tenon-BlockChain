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

namespace lego {

namespace tvm {

Execution::Execution() {}

Execution::~Execution() {}

static void set_value(evmc_message* msg, uint64_t x) noexcept {
    for (std::size_t i = 0; i < sizeof(x); ++i) {
        msg->value.bytes[sizeof(msg->value) - 1 - i] = static_cast<uint8_t>(x >> (8 * i));
    }
}

int Execution::execute(
        const std::string& contract_address,
        const std::string& str_input,
        const std::string& from_address,
        const std::string& to_address,
        const std::string& origin_address,
        uint64_t value,
        uint64_t gas_limit,
        uint32_t depth,
        bool is_create,
        lego::tvm::TenonHost& host,
        evmc::result* out_res) {
    auto contract_info = block::AccountManager::Instance()->GetAcountInfo(contract_address);
    if (contract_info == nullptr) {
        TVM_ERROR("contract address not exists[%s]",
            common::Encode::HexEncode(contract_address).c_str());
        return kTvmContractNotExists;
    }

    uint32_t address_type = block::kNormalAddress;
    if (contract_info->GetAddressType(&address_type) != block::kBlockSuccess) {
        TVM_ERROR("contract address not exists[%s]",
            common::Encode::HexEncode(contract_address).c_str());
        return kTvmContractNotExists;
    }

    std::string bytes_code;
    if (contract_info->GetBytesCode(&bytes_code) != block::kBlockSuccess) {
        TVM_ERROR("contract address not exists[%s]",
            common::Encode::HexEncode(contract_address).c_str());
        return kTvmContractNotExists;
    }

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
    auto create = false;
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
    set_value(&msg, 0);

    std::cout << "msg.input_size: " << msg.input_size << std::endl;
    const uint8_t* exec_code_data = nullptr;
    size_t exec_code_size = 0;
    if (create) {
//         evmc_message create_msg{};
//         create_msg.kind = EVMC_CREATE;
//         create_msg.destination = create_address;
//         create_msg.gas = create_gas;
// 
//         const auto create_result = evm.execute(
//             host,
//             rev,
//             create_msg,
//             (uint8_t*)contract_address.c_str(),
//             contract_address.size());
//         if (create_result.status_code != EVMC_SUCCESS)
//         {
//             std::cout << "Contract creation failed: " << create_result.status_code << "\n";
//             return create_result.status_code;
//         }
// 
//         auto& created_account = host.accounts[create_address];
//         created_account.code = evmc::bytes(create_result.output_data, create_result.output_size);
// 
//         msg.destination = create_address;
// 
//         exec_code_data = created_account.code.data();
//         exec_code_size = created_account.code.size();
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

}  //namespace lego
