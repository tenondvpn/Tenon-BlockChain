#pragma once

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

#include <evmc/evmc.hpp>

// #include "contract/contract_manager.h"
// #include "contract/call_parameters.h"

namespace tenon {

namespace tvm {

using bytes = std::basic_string<uint8_t>;

struct storage_value {
    evmc::bytes32 value;
    bool dirty{false};
    storage_value() noexcept = default;
    storage_value(const evmc::bytes32& _value, bool _dirty = false) noexcept
      : value{_value}, dirty{_dirty}
    {}
};

struct MockedAccount {
    int nonce = 0;
    bytes code;
    evmc::bytes32 codehash;
    evmc::uint256be balance;
    std::unordered_map<evmc::bytes32, storage_value> storage;
    void set_balance(uint64_t x) noexcept {
        balance = evmc::uint256be{};
        for (std::size_t i = 0; i < sizeof(x); ++i)
            balance.bytes[sizeof(balance) - 1 - i] = static_cast<uint8_t>(x >> (8 * i));
    }
};

class TenonHost : public evmc::Host {
public:
    struct log_record {
        evmc::address creator;
        bytes data;
        std::vector<evmc::bytes32> topics;
        bool operator==(const log_record& other) const noexcept {
            return creator == other.creator && data == other.data && topics == other.topics;
        }
    };

    struct selfdestuct_record {
        evmc::address selfdestructed;
        evmc::address beneficiary;
        bool operator==(const selfdestuct_record& other) const noexcept
        {
            return selfdestructed == other.selfdestructed && beneficiary == other.beneficiary;
        }
    };

    bool account_exists(const evmc::address& addr) const noexcept override;
    evmc::bytes32 get_storage(
        const evmc::address& addr,
        const evmc::bytes32& key) const noexcept override;
    evmc_storage_status set_storage(
        const evmc::address& addr,
        const evmc::bytes32& key,
        const evmc::bytes32& value) noexcept override;
    evmc::uint256be get_balance(const evmc::address& addr) const noexcept override;
    size_t get_code_size(const evmc::address& addr) const noexcept override;
    evmc::bytes32 get_code_hash(const evmc::address& addr) const noexcept override;
    size_t copy_code(
        const evmc::address& addr,
        size_t code_offset,
        uint8_t* buffer_data,
        size_t buffer_size) const noexcept override;
    void selfdestruct(
        const evmc::address& addr,
        const evmc::address& beneficiary) noexcept override;
    evmc::result call(const evmc_message& msg) noexcept override;
    evmc_tx_context get_tx_context() const noexcept override;
    evmc::bytes32 get_block_hash(int64_t block_number) const noexcept override;
    void emit_log(
        const evmc::address& addr,
        const uint8_t* data,
        size_t data_size,
        const evmc::bytes32 topics[],
        size_t topics_count) noexcept override;
    // tmp item
    void AddTmpAccountBalance(const std::string& address, uint64_t balance);

    std::unordered_map<evmc::address, MockedAccount> accounts_;
    evmc_tx_context tx_context_ = {};
    evmc::bytes32 block_hash_ = {};
    std::vector<log_record> recorded_logs_;
    std::vector<selfdestuct_record> recorded_selfdestructs_;

    std::string my_address_;
    uint64_t gas_price_{ 0 };
    std::string origin_address_;
    uint32_t depth_{ 0 };
    std::unordered_map<std::string, std::unordered_map<std::string, uint64_t>> to_account_value_;
    std::unordered_map<evmc::address, evmc::uint256be> account_balance_;
    std::string create_bytes_code_;
};

}  // namespace tvm

}  // namespace tenon
