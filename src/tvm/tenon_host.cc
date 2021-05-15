#include "tvm/tenon_host.h"

#include "evmc/hex.hpp"
#include "tvm/tvm_utils.h"
#include "tvm/execution.h"
#include "block/account_manager.h"

namespace lego {

namespace tvm {

bool TenonHost::account_exists(const evmc::address& addr) const noexcept {
    return block::AccountManager::Instance()->AccountExists(
        std::string((char*)addr.bytes, sizeof(addr.bytes)));
}

evmc::bytes32 TenonHost::get_storage(
        const evmc::address& addr,
        const evmc::bytes32& key) const noexcept {
    // first find from temporary map storage
    const auto account_iter = accounts.find(addr);
    if (account_iter != accounts.end()) {
        const auto storage_iter = account_iter->second.storage.find(key);
        if (storage_iter != account_iter->second.storage.end()) {
            return storage_iter->second.value;
        }
    }

    // from db
    auto account_info = block::AccountManager::Instance()->GetAcountInfo(
        std::string((char*)addr.bytes, sizeof(addr.bytes)));
    if (account_info == nullptr) {
        return {};
    }

    std::string val;
    std::string tmp_key((char*)key.bytes, sizeof(key.bytes));
    if (account_info->GetAttrValue(tmp_key, &val) == block::kBlockSuccess) {
        evmc::bytes32 tmp_val{};
        memcpy(tmp_val.bytes, val.c_str(), sizeof(tmp_val.bytes));
        return tmp_val;
    }

    return {};
}

evmc_storage_status TenonHost::set_storage(
        const evmc::address& addr,
        const evmc::bytes32& key,
        const evmc::bytes32& value) noexcept {
    // just set temporary map storage, when commit set to db and block
    const auto it = accounts.find(addr);
    if (it == accounts.end())
        return EVMC_STORAGE_UNCHANGED;

    auto& old = it->second.storage[key];
    if (old.value == value)
        return EVMC_STORAGE_UNCHANGED;

    evmc_storage_status status{};
    if (!old.dirty)
    {
        old.dirty = true;
        if (!old.value)
            status = EVMC_STORAGE_ADDED;
        else if (value)
            status = EVMC_STORAGE_MODIFIED;
        else
            status = EVMC_STORAGE_DELETED;
    }
    else
        status = EVMC_STORAGE_MODIFIED_AGAIN;

    old.value = value;
    return status;
}

evmc::uint256be TenonHost::get_balance(const evmc::address& addr) const noexcept {
    auto account_info = block::AccountManager::Instance()->GetAcountInfo(
        std::string((char*)addr.bytes, sizeof(addr.bytes)));
    if (account_info == nullptr) {
        return {};
    }

    uint64_t balance = 0;
    if (account_info->GetBalance(&balance) == block::kBlockSuccess) {
        evmc::bytes32 tmp_val{};
        Uint64ToEvmcBytes32(tmp_val, balance);
        return tmp_val;
    }

    return {};
// 
//     const auto it = accounts.find(addr);
//     if (it == accounts.end()) {
//         return {};
//     }
// 
//     return it->second.balance;
}

size_t TenonHost::get_code_size(const evmc::address& addr) const noexcept {
    auto account_info = block::AccountManager::Instance()->GetAcountInfo(
        std::string((char*)addr.bytes, sizeof(addr.bytes)));
    if (account_info == nullptr) {
        return 0;
    }

    uint32_t address_type = block::kNormalAddress;
    if (account_info->GetAddressType(&address_type) != block::kBlockSuccess) {
        return 0;
    }

    if (address_type != block::kContractAddress) {
        return 0;
    }

    return account_info->VmCodeSize();

//     const auto it = accounts.find(addr);
//     if (it == accounts.end())
//         return 0;
//     return it->second.code.size();
}

evmc::bytes32 TenonHost::get_code_hash(const evmc::address& addr) const noexcept {
    auto account_info = block::AccountManager::Instance()->GetAcountInfo(
        std::string((char*)addr.bytes, sizeof(addr.bytes)));
    if (account_info == nullptr) {
        return {};
    }

    uint32_t address_type = block::kNormalAddress;
    if (account_info->GetAddressType(&address_type) != block::kBlockSuccess) {
        return {};
    }

    if (address_type != block::kContractAddress) {
        return {};
    }

    std::string code_hash = account_info->VmCodeHash();
    evmc::bytes32 tmp_val{};
    memcpy(tmp_val.bytes, code_hash.c_str(), sizeof(tmp_val.bytes));
    return tmp_val;
// 
//     const auto it = accounts.find(addr);
//     if (it == accounts.end())
//         return {};
//     return it->second.codehash;
}

size_t TenonHost::copy_code(
        const evmc::address& addr,
        size_t code_offset,
        uint8_t* buffer_data,
        size_t buffer_size) const noexcept {
    auto account_info = block::AccountManager::Instance()->GetAcountInfo(
        std::string((char*)addr.bytes, sizeof(addr.bytes)));
    if (account_info == nullptr) {
        return {};
    }

    uint32_t address_type = block::kNormalAddress;
    if (account_info->GetAddressType(&address_type) != block::kBlockSuccess) {
        return {};
    }

    if (address_type != block::kContractAddress) {
        return {};
    }

    std::string code = account_info->GetCode();
    if (code_offset >= code.size()) {
        return 0;
    }

    const auto n = (std::min)(buffer_size, code.size() - code_offset);
    if (n > 0) {
        std::copy_n(&code[code_offset], n, buffer_data);
    }

    return n;
// 
//     const auto it = accounts.find(addr);
//     if (it == accounts.end())
//         return 0;
// 
//     const auto& code = it->second.code;
// 
//     if (code_offset >= code.size())
//         return 0;
// 
//     const auto n = std::min(buffer_size, code.size() - code_offset);
// 
//     if (n > 0)
//         std::copy_n(&code[code_offset], n, buffer_data);
//     return n;
}

void TenonHost::selfdestruct(
        const evmc::address& addr,
        const evmc::address& beneficiary) noexcept {
    recorded_selfdestructs.push_back({addr, beneficiary});
}

evmc::result TenonHost::call(const evmc_message& msg) noexcept {
    contract::CallParameters params;
    params.gas = msg.gas;
    params.apparent_value = tvm::EvmcBytes32ToUint64(msg.value);
    params.value = msg.kind == EVMC_DELEGATECALL ? 0 : params.apparent_value;
    params.from = std::string((char*)msg.sender.bytes, sizeof(msg.sender.bytes));
    params.code_address = std::string(
        (char*)msg.destination.bytes,
        sizeof(msg.destination.bytes));
    params.to = msg.kind == EVMC_CALL ? params.code_address : my_address_;
    params.data = std::string((char*)msg.input_data, msg.input_size);
    params.on_op = {};
    std::cout << "code address is: " << common::Encode::HexEncode(params.code_address) << std::endl;
    std::cout << "sender is: " << common::Encode::HexEncode(params.from) << std::endl;
    std::cout << "receiver is: " << common::Encode::HexEncode(params.to) << std::endl;
    std::cout << "value is: " << params.value << std::endl;
    evmc_result call_result = {};
    evmc::result evmc_res{ call_result };
    evmc_result* raw_result = (evmc_result*)&evmc_res;
    if (contract::ContractManager::Instance()->call(
            params,
            gas_price_,
            origin_address_,
            raw_result) != contract::kContractNotExists) {
    } else {
        auto account_info = block::AccountManager::Instance()->GetAcountInfo(params.code_address);
        if (account_info != nullptr) {
            uint32_t address_type = block::kNormalAddress;
            if (account_info->GetAddressType(&address_type) == block::kBlockSuccess &&
                    address_type == block::kContractAddress) {
                Execution exec;
                ++depth_;
                int res_status = exec.execute(
                    params.code_address,
                    params.data,
                    params.from,
                    params.to,
                    origin_address_,
                    params.apparent_value,
                    params.gas,
                    depth_,
                    false,
                    *this,
                    &evmc_res);
            }
        }
    }

    if (params.value > 0) {
        uint64_t from_balance = EvmcBytes32ToUint64(accounts[msg.sender].balance);
        std::cout << "check can transfer now balance: " << from_balance
            << ", to : " << params.value
            << ", valid: " << (from_balance >= params.value)
            << std::endl;
        if (from_balance < params.value) {
            evmc_res.status_code = EVMC_INSUFFICIENT_BALANCE;
        }
    }
    
    return evmc_res;
}

evmc_tx_context TenonHost::get_tx_context() const noexcept {
    return tx_context;
}

evmc::bytes32 TenonHost::get_block_hash(int64_t block_number) const noexcept {
    return block_hash;
}

void TenonHost::emit_log(const evmc::address& addr,
                const uint8_t* data,
                size_t data_size,
                const evmc::bytes32 topics[],
                size_t topics_count) noexcept {
    recorded_logs.push_back({addr, {data, data_size}, {topics, topics + topics_count}});
}

}  // namespace tvm

}  // namespace lego
