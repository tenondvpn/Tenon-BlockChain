#include "tvm/tenon_host.h"

#include "contract/contract_manager.h"
#include "contract/call_parameters.h"
#include "block/account_manager.h"
#include "evmc/hex.hpp"
#include "tvm/tvm_utils.h"
#include "tvm/execution.h"

namespace tenon {

namespace tvm {

bool TenonHost::account_exists(const evmc::address& addr) const noexcept {
    return block::AccountManager::Instance()->AccountExists(
        std::string((char*)addr.bytes, sizeof(addr.bytes)));
}

evmc::bytes32 TenonHost::get_storage(
        const evmc::address& addr,
        const evmc::bytes32& key) const noexcept {
    // first find from temporary map storage
    std::string id((char*)addr.bytes, sizeof(addr.bytes));
    std::string key_str((char*)key.bytes, sizeof(key.bytes));
    std::cout << "0000 get storage called, id: " << common::Encode::HexEncode(id)
        << ", key: " << common::Encode::HexEncode(key_str)
        << std::endl;


    const auto account_iter = accounts_.find(addr);
    if (account_iter != accounts_.end()) {
        const auto storage_iter = account_iter->second.storage.find(key);
        if (storage_iter != account_iter->second.storage.end()) {
            std::string val_str((char*)storage_iter->second.value.bytes, sizeof(storage_iter->second.value.bytes));
            std::cout << "0 tvm get storage called, id: " << common::Encode::HexEncode(id)
                << ", key: " << common::Encode::HexEncode(key_str)
                << ", value: " << common::Encode::HexEncode(val_str)
                << std::endl;

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
        uint32_t offset = 0;
        uint32_t length = sizeof(tmp_val.bytes);
        if (val.size() < sizeof(tmp_val.bytes)) {
            offset = sizeof(tmp_val.bytes) - val.size();
            length = val.size();
        }

        std::cout << "1 tvm get storage called, id: " << common::Encode::HexEncode(id)
            << ", key: " << common::Encode::HexEncode(key_str)
            << ", value: " << common::Encode::HexEncode(val)
            << std::endl;

        memcpy(tmp_val.bytes + offset, val.c_str(), length);
        return tmp_val;
    }

    return {};
}

evmc_storage_status TenonHost::set_storage(
        const evmc::address& addr,
        const evmc::bytes32& key,
        const evmc::bytes32& value) noexcept {
    // just set temporary map storage, when commit set to db and block
    std::string id((char*)addr.bytes, sizeof(addr.bytes));
    std::string key_str((char*)key.bytes, sizeof(key.bytes));
    std::string val_str((char*)value.bytes, sizeof(value.bytes));

    std::cout << "tvm set storage called, id: " << common::Encode::HexEncode(id)
        << ", key: " << common::Encode::HexEncode(key_str)
        << ", value: " << common::Encode::HexEncode(val_str) << std::endl;
    auto it = accounts_.find(addr);
    if (it == accounts_.end()) {
        accounts_[addr] = MockedAccount();
        it = accounts_.find(addr);
    }

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
    // don't use real balance
    auto iter = account_balance_.find(addr);
    if (iter == account_balance_.end()) {
        return {};
    }

    return iter->second;
//     auto account_info = block::AccountManager::Instance()->GetAcountInfo(
//         std::string((char*)addr.bytes, sizeof(addr.bytes)));
//     if (account_info == nullptr) {
//         return {};
//     }
// 
//     uint64_t balance = 0;
//     if (account_info->GetBalance(&balance) == block::kBlockSuccess) {
//         evmc::bytes32 tmp_val{};
//         Uint64ToEvmcBytes32(tmp_val, balance);
//         return tmp_val;
//     }
// 
//     return {};
// 
//     const auto it = accounts_.find(addr);
//     if (it == accounts_.end()) {
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

//     const auto it = accounts_.find(addr);
//     if (it == accounts_.end())
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
//     const auto it = accounts_.find(addr);
//     if (it == accounts_.end())
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
//     const auto it = accounts_.find(addr);
//     if (it == accounts_.end())
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
    recorded_selfdestructs_.push_back({ addr, beneficiary });
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
    evmc_result call_result = {};
    evmc::result evmc_res{ call_result };
    evmc_result* raw_result = (evmc_result*)&evmc_res;
    raw_result->gas_left = msg.gas;
    std::cout << "host called kind: " << msg.kind << ", from: " << common::Encode::HexEncode(params.from) << ", to: " << common::Encode::HexEncode(params.to) << std::endl;
    if (contract::ContractManager::Instance()->call(
            params,
            gas_price_,
            origin_address_,
            raw_result) != contract::kContractNotExists) {
    } else {
        auto account_info = block::AccountManager::Instance()->GetContractInfoByAddress(params.code_address);
        if (account_info != nullptr) {
            std::string bytes_code;
            if (account_info->GetBytesCode(&bytes_code) != block::kBlockSuccess) {
                evmc_res.status_code = EVMC_REVERT;
                return evmc_res;
            }

            ++depth_;
            int res_status = tvm::Execution::Instance()->execute(
                bytes_code,
                params.data,
                params.from,
                params.to,
                origin_address_,
                params.apparent_value,
                params.gas,
                depth_,
                tvm::kJustCall,
                *this,
                &evmc_res);
        } else {
            // (TODO): sync account info from other shard
        }
    }

    if (params.value > 0) {
        uint64_t from_balance = EvmcBytes32ToUint64(get_balance(msg.sender));
        if (from_balance < params.value) {
            evmc_res.status_code = EVMC_INSUFFICIENT_BALANCE;
        } else {
            std::string from_str = std::string((char*)msg.sender.bytes, sizeof(msg.sender.bytes));
            std::string dest_str = std::string((char*)msg.destination.bytes, sizeof(msg.destination.bytes));
            auto sender_iter = to_account_value_.find(from_str);
            if (sender_iter == to_account_value_.end()) {
                to_account_value_[from_str] = std::unordered_map<std::string, uint64_t>();
                to_account_value_[from_str][dest_str] = params.value;
            } else {
                auto iter = sender_iter->second.find(dest_str);
                if (iter != sender_iter->second.end()) {
                    sender_iter->second[dest_str] += params.value;
                } else {
                    sender_iter->second[dest_str] = params.value;
                }
            }
        }
    }
    
    return evmc_res;
}

evmc_tx_context TenonHost::get_tx_context() const noexcept {
    return tx_context_;
}

evmc::bytes32 TenonHost::get_block_hash(int64_t block_number) const noexcept {
    return block_hash_;
}

void TenonHost::emit_log(const evmc::address& addr,
                const uint8_t* data,
                size_t data_size,
                const evmc::bytes32 topics[],
                size_t topics_count) noexcept {
    std::string id((char*)addr.bytes, sizeof(addr.bytes));
    std::string str_data((char*)data, data_size);
    std::string topics_str;
    for (uint32_t i = 0; i < topics_count; ++i) {
        topics_str += std::string((char*)topics[i].bytes, sizeof(topics[i].bytes)) + ", ";
    }

    std::cout << "log called id: " << common::Encode::HexEncode(id) << ", data: " << common::Encode::HexEncode(str_data) << ", topics: " << common::Encode::HexEncode(topics_str) << std::endl;
    recorded_logs_.push_back({ addr, {data, data_size}, {topics, topics + topics_count} });
}

void TenonHost::AddTmpAccountBalance(const std::string& address, uint64_t balance) {
    evmc::address addr;
    memcpy(
        addr.bytes,
        address.c_str(),
        sizeof(addr.bytes));
    evmc::bytes32 tmp_val{};
    Uint64ToEvmcBytes32(tmp_val, balance);
    account_balance_[addr] = tmp_val;
}

}  // namespace tvm

}  // namespace tenon
