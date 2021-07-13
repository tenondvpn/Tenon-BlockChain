#include "contract/contract_alt_bn128_pairing_product.h"

#include "security/secp256k1.h"
#include "big_num/snark.h"
#include "big_num/libsnark.h"

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

int ContractaltBn128PairingProduct::Execute(bft::TxItemPtr tx_item) {
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

    const int64_t gas_used = (45000 + param.data.size() * 34000);
    if (res->gas_left < gas_used) {
        return kContractError;
    }

    bytesConstRef bytes_ref((byte*)param.data.c_str(), param.data.size());
    std::pair<bool, bytes> add_res = alt_bn128_pairing_product(bytes_ref);
    if (!add_res.first) {
        return kContractError;
    }

    res->output_data = new uint8_t[add_res.second.size()];
    memcpy((void*)res->output_data, &add_res.second.at(0), add_res.second.size());
    res->output_size = add_res.second.size();
    memcpy(res->create_address.bytes,
        create_address_.c_str(),
        sizeof(res->create_address.bytes));
    res->gas_left -= gas_used;
    return kContractSuccess;
}

}  // namespace contract

}  // namespace tenon
