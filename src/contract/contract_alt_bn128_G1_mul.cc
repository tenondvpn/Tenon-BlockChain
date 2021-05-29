#include "contract/contract_alt_bn128_G1_mul.h"

#include "security/secp256k1.h"
#include "big_num/snark.h"

namespace tenon {

namespace contract {

ContractAltBn128G1Mul::ContractAltBn128G1Mul(const std::string& create_address)
        : ContractInterface(create_address) {}

ContractAltBn128G1Mul::~ContractAltBn128G1Mul() {}

int ContractAltBn128G1Mul::InitWithAttr(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info,
        db::DbWriteBach& db_batch) {
    return kContractSuccess;
}

int ContractAltBn128G1Mul::GetAttrWithKey(const std::string& key, std::string& value) {
    return kContractSuccess;
}

int ContractAltBn128G1Mul::Execute(bft::TxItemPtr& tx_item) {
    return kContractSuccess;
}

int ContractAltBn128G1Mul::call(
        const CallParameters& param,
        uint64_t gas,
        const std::string& origin_address,
        evmc_result* res) {
    if (param.data.empty()) {
        return kContractError;
    }

    if (res->gas_left < gas_cast_) {
        return kContractError;
    }

    std::string out = bignum::Snark::Instance()->AltBn128G1Mul(param.data);
    res->output_data = new uint8_t[out.size()];
    memcpy((void*)res->output_data, out.c_str(), out.size());
    res->output_size = out.size();
    memcpy(res->create_address.bytes,
        create_address_.c_str(),
        sizeof(res->create_address.bytes));
    res->gas_left -= gas_cast_;
    return kContractSuccess;
}

}  // namespace contract

}  // namespace tenon
