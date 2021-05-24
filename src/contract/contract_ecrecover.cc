#include "contract/contract_ecrecover.h"

#include "security/secp256k1.h"

namespace tenon {

namespace contract {

Ecrecover::Ecrecover(const std::string& create_address)
        : ContractInterface(create_address) {}

Ecrecover::~Ecrecover() {}

int Ecrecover::InitWithAttr(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info,
        db::DbWriteBach& db_batch) {
    return kContractSuccess;
}

int Ecrecover::GetAttrWithKey(const std::string& key, std::string& value) {
    return kContractSuccess;
}

int Ecrecover::Execute(bft::TxItemPtr& tx_item) {
    return kContractSuccess;
}

int Ecrecover::call(
        const CallParameters& param,
        uint64_t gas,
        const std::string& origin_address,
        evmc_result* res) {
    if (param.data.size() != 128) {
        return kContractError;
    }

    std::string hash(param.data.c_str(), 32);
    std::string sign(param.data.c_str() + 32, param.data.size() - 32);
    std::string pubkey = security::Secp256k1::Instance()->recover(sign, hash);
    std::string addr_sha3 = security::Secp256k1::Instance()->sha3(pubkey);
    res->output_data = new uint8_t[addr_sha3.size()];
    memcpy((void*)res->output_data, addr_sha3.c_str(), addr_sha3.size());
    res->output_size = addr_sha3.size();
    memcpy(res->create_address.bytes,
        create_address_.c_str(),
        sizeof(res->create_address.bytes));
    std::cout << "ec recover data output: " << common::Encode::HexEncode(addr_sha3) << std::endl;
    return kContractSuccess;
}

}  // namespace contract

}  // namespace tenon
