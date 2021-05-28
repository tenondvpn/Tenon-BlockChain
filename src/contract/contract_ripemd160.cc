#include "contract/contract_ripemd160.h"

#include "security/secp256k1.h"

namespace tenon {

namespace contract {

Ripemd160::Ripemd160(const std::string& create_address)
        : ContractInterface(create_address) {}

Ripemd160::~Ripemd160() {}

int Ripemd160::InitWithAttr(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info,
        db::DbWriteBach& db_batch) {
    return kContractSuccess;
}

int Ripemd160::GetAttrWithKey(const std::string& key, std::string& value) {
    return kContractSuccess;
}

int Ripemd160::Execute(bft::TxItemPtr& tx_item) {
    return kContractSuccess;
}

int Ripemd160::call(
        const CallParameters& param,
        uint64_t gas,
        const std::string& origin_address,
        evmc_result* res) {
    if (param.data.empty()) {
        return kContractError;
    }

    uint64_t gas_used = ComputeGasUsed(600, 120, param.data.size());
    if (res->gas_left < gas_used) {
        return kContractError;
    }

    std::string ripemd160 = common::Hash::ripemd160(param.data);
    res->output_data = new uint8_t[32];
    memcpy((void*)res->output_data, ripemd160.c_str(), ripemd160.size());
    res->output_size = 32;
    memcpy(res->create_address.bytes,
        create_address_.c_str(),
        sizeof(res->create_address.bytes));
    res->gas_left -= gas_used;
    return kContractSuccess;
}

}  // namespace contract

}  // namespace tenon
