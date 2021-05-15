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

int Execution::InitEnvironment(lego::tvm::TenonHost& tenon_host, evmc_message* msg) {
    memcpy(msg->sender.bytes,
        evmc::from_hex("af5E8eABEd304DfeF8c8effBd7490d6FAfe9bAE3").c_str(),
        sizeof(msg->sender.bytes));
    memcpy(msg->destination.bytes,
        evmc::from_hex("2f6acD655C36FF98398ee8729D3c92f35A1f147E").c_str(),
        sizeof(msg->destination.bytes));
    set_value(msg, 0);
    evmc::bytes32 key;
    memcpy(key.bytes,
        evmc::from_hex("0000000000000000000000000000000000000000000000000000000000000000").c_str(),
        sizeof(key.bytes));
    evmc::bytes32 value;
    memcpy(value.bytes,
        evmc::from_hex("000000000000000000000000b8CE9ab6943e0eCED004cDe8e3bBed6568B2Fa01").c_str(),
        sizeof(value.bytes));
    lego::tvm::MockedAccount sender_account;
    sender_account.set_balance(345624523342345llu);
    tenon_host.accounts[msg->sender] = sender_account;
    lego::tvm::MockedAccount destination_account;
    destination_account.set_balance(3456245233234500llu);
    tenon_host.accounts[msg->destination] = destination_account;
    evmc::address owner_addr;
    memcpy(owner_addr.bytes, evmc::from_hex("b8CE9ab6943e0eCED004cDe8e3bBed6568B2Fa01").c_str(), sizeof(owner_addr.bytes));
    lego::tvm::MockedAccount owner_account;
    owner_account.set_balance(34562452334345llu);
    tenon_host.accounts[owner_addr] = owner_account;
    tenon_host.set_storage(msg->destination, key, value);
    return 0;
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
    if (contract_info->GetAddressType(&address_type) != block::kContractAddress) {
        TVM_ERROR("contract address not exists[%s]",
            common::Encode::HexEncode(contract_address).c_str());
        return kTvmContractNotExists;
    }

    std::string bytes_code;
    if (contract_info->GetBytesCode(&bytes_code) != block::kContractAddress) {
        TVM_ERROR("contract address not exists[%s]",
            common::Encode::HexEncode(contract_address).c_str());
        return kTvmContractNotExists;
    }

//     std::string str_code = common::Encode::HexDecode("60806040523480156100115760006000fd5b50600436106100465760003560e01c806341c0e1b51461004c578063a90ae88714610056578063cfb519281461007257610046565b60006000fd5b6100546100a2565b005b610070600480360381019061006b9190610402565b61011a565b005b61008c600480360381019061008791906103be565b61029c565b604051610099919061048d565b60405180910390f35b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161415156100ff5760006000fd5b3373ffffffffffffffffffffffffffffffffffffffff16ff5b565b6000601b905060007f3d584400dc77e383a2a2860d15fd181b1c36117d7b6c1e5d54e2f21d9491b66e60001b905060007f043a539fab3f2e42ba806da59b30e100077a7dba7439de3fce427eaa75dce5c460001b905060007ff559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d560001b90506000600182868686604051600081526020016040526040516101bd94939291906104a9565b6020604051602081039080840390855afa1580156101e0573d600060003e3d6000fd5b505050602060405103519050600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161415156102495760006000fd5b3373ffffffffffffffffffffffffffffffffffffffff166108fc899081150290604051600060405180830381858888f19350505050158015610290573d600060003e3d6000fd5b5050505050505b505050565b600060008290506000815114156102ba57600060001b9150506102c3565b60208301519150505b9190505661063e565b60006102df6102da84610516565b6104ef565b9050828152602081018484840111156102f85760006000fd5b61030384828561059e565b505b9392505050565b600061031f61031a84610548565b6104ef565b9050828152602081018484840111156103385760006000fd5b61034384828561059e565b505b9392505050565b600082601f83011215156103605760006000fd5b81356103708482602086016102cc565b9150505b92915050565b600082601f830112151561038e5760006000fd5b813561039e84826020860161030c565b9150505b92915050565b6000813590506103b781610623565b5b92915050565b6000602082840312156103d15760006000fd5b600082013567ffffffffffffffff8111156103ec5760006000fd5b6103f88482850161037a565b9150505b92915050565b600060006000606084860312156104195760006000fd5b6000610427868287016103a8565b9350506020610438868287016103a8565b925050604084013567ffffffffffffffff8111156104565760006000fd5b6104628682870161034c565b9150505b9250925092565b6104768161057a565b82525b5050565b61048681610590565b82525b5050565b60006020820190506104a2600083018461046d565b5b92915050565b60006080820190506104be600083018761046d565b6104cb602083018661047d565b6104d8604083018561046d565b6104e5606083018461046d565b5b95945050505050565b60006104f961050b565b905061050582826105ae565b5b919050565b600060405190505b90565b600067ffffffffffffffff821115610531576105306105e0565b5b61053a82610611565b90506020810190505b919050565b600067ffffffffffffffff821115610563576105626105e0565b5b61056c82610611565b90506020810190505b919050565b60008190505b919050565b60008190505b919050565b600060ff821690505b919050565b828183376000838301525b505050565b6105b782610611565b810181811067ffffffffffffffff821117156105d6576105d56105e0565b5b80604052505b5050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b565b6000601f19601f83011690505b919050565b61062c81610585565b8114151561063a5760006000fd5b5b50565bfea26469706673582212205df1f066520c41781aa6e597f682192d353de3fdfe0f68038958a4170a2bf34264736f6c63430008030033");
//     std::string str_input = common::Encode::HexDecode("a90ae887000000000000000000000000000000000000000000000000000855612b7594c00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000413d584400dc77e383a2a2860d15fd181b1c36117d7b6c1e5d54e2f21d9491b66e043a539fab3f2e42ba806da59b30e100077a7dba7439de3fce427eaa75dce5c41b0000000000000000000000000000000000000000000000000000000000000000");

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
    constexpr auto create_address = evmc_address();// "c9ea7ed000000000000000000000000000000001_address";
    auto create_gas = gas_limit;

    evmc_message msg{};
    msg.gas = gas;
    msg.input_data = (uint8_t*)str_input.c_str();
    msg.input_size = str_input.size();

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
