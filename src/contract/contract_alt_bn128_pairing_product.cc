#include "contract/contract_alt_bn128_pairing_product.h"

#include "security/secp256k1.h"
#include "big_num/snark.h"

namespace tenon {

namespace contract {

ContractaltBn128PairingProduct::ContractaltBn128PairingProduct(const std::string& create_address)
        : ContractInterface(create_address) {}

ContractaltBn128PairingProduct::~ContractaltBn128PairingProduct() {}

int ContractaltBn128PairingProduct::InitWithAttr(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info,
        db::DbWriteBach& db_batch) {
    return kContractSuccess;
}

int ContractaltBn128PairingProduct::GetAttrWithKey(const std::string& key, std::string& value) {
    return kContractSuccess;
}

int ContractaltBn128PairingProduct::Execute(bft::TxItemPtr& tx_item) {
    return kContractSuccess;
}

int ContractaltBn128PairingProduct::call(
        const CallParameters& param,
        uint64_t gas,
        const std::string& origin_address,
        evmc_result* res) {
    if (param.data.empty()) {
        return kContractError;
    }

    const uint64_t gas_used = (45000 + param.data.size() * 34000);
    if (res->gas_left < gas_used) {
        return kContractError;
    }

    std::string out = bignum::Snark::Instance()->AltBn128PairingProduct(param.data);
    res->output_data = new uint8_t[out.size()];
    memcpy((void*)res->output_data, out.c_str(), out.size());
    res->output_size = out.size();
    memcpy(res->create_address.bytes,
        create_address_.c_str(),
        sizeof(res->create_address.bytes));
    res->gas_left -= gas_used;
    return kContractSuccess;
}

}  // namespace contract

}  // namespace tenon
