#include "contract/contract_modexp.h"

#include <cassert>
#include <limits>
#include <boost/multiprecision/integer.hpp>

#include "security/secp256k1.h"
#include "big_num/snark.h"
#include "big_num/bignum_utils.h"

namespace tenon {

namespace contract {

Modexp::Modexp(const std::string& create_address)
        : ContractInterface(create_address) {}

Modexp::~Modexp() {}

int Modexp::InitWithAttr(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info,
        db::DbWriteBach& db_batch) {
    return kContractSuccess;
}

int Modexp::GetAttrWithKey(const std::string& key, std::string& value) {
    return kContractSuccess;
}

int Modexp::Execute(bft::TxItemPtr& tx_item) {
    return kContractSuccess;
}

uint64_t Modexp::GetGasPrice(const std::string& data) {
    bigint const baseLength(ParseBigEndianRightPadded(data, 0, 32));
    bigint const expLength(ParseBigEndianRightPadded(data, 32, 32));
    bigint const modLength(ParseBigEndianRightPadded(data, 64, 32));

    bigint const maxLength((std::max)(modLength, baseLength));
    bigint const adjustedExpLength(ExpLengthAdjust(baseLength + 96, expLength, data));
    std::cout << "modLength: " << modLength << ", baseLength: " << baseLength << ",maxLength: " << maxLength << ", adjustedExpLength: " << adjustedExpLength << std::endl;
    return static_cast<uint64_t>(MultComplexity(maxLength) * (adjustedExpLength > 1 ? adjustedExpLength : 1)) / 20;
}

int Modexp::call(
        const CallParameters& param,
        uint64_t gas,
        const std::string& origin_address,
        evmc_result* res) {
    if (param.data.empty()) {
        std::cout << "param.data.empty()" << std::endl;
        return kContractError;
    }

    uint64_t gas_used = GetGasPrice(param.data);
    if (res->gas_left < gas_used) {
        std::cout << "res->gas_left < gas_used" << res->gas_left << ", " << gas_used << std::endl;
        return kContractError;
    }

    bigint const baseLength(ParseBigEndianRightPadded(param.data, 0, 32));
    bigint const expLength(ParseBigEndianRightPadded(param.data, 32, 32));
    bigint const modLength(ParseBigEndianRightPadded(param.data, 64, 32));
    assert(modLength <= std::numeric_limits<size_t>::max() / 8);
    assert(baseLength <= std::numeric_limits<size_t>::max() / 8);
    if (modLength == 0 && baseLength == 0) {
        std::cout << "modLength == 0 && baseLength == 0" << std::endl;
        return kContractError;
    }

    assert(expLength <= std::numeric_limits<size_t>::max() / 8);
    bigint const base(ParseBigEndianRightPadded(param.data, 96, baseLength));
    bigint const exp(ParseBigEndianRightPadded(param.data, 96 + baseLength, expLength));
    bigint const mod(ParseBigEndianRightPadded(param.data, 96 + baseLength + expLength, modLength));
    bigint const result = mod != 0 ? boost::multiprecision::powm(base, exp, mod) : bigint{ 0 };
    res->output_data = new uint8_t[static_cast<size_t>(modLength)];
    bignum::ToBigEndian(result, (uint8_t*)res->output_data, static_cast<size_t>(modLength));
    res->output_size = static_cast<size_t>(modLength);
    memcpy(res->create_address.bytes,
        create_address_.c_str(),
        sizeof(res->create_address.bytes));
    res->gas_left -= gas_used;
    return kContractSuccess;
}

}  // namespace contract

}  // namespace tenon
