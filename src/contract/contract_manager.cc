#include "stdafx.h"
#include "contract/contract_manager.h"

#include "network/route.h"
#include "network/universal_manager.h"
#include "contract/contract_vpn_svr_bandwidth.h"
#include "contract/contract_pay_for_vpn.h"
#include "contract/contract_vpn_client_login.h"
#include "contract/proto/contract_proto.h"
#include "contract/contract_vpn_mining.h"
#include "contract/contract_ecrecover.h"
#include "contract/contract_sha256.h"
#include "contract/contract_ripemd160.h"
#include "contract/contract_identity.h"
#include "contract/contract_modexp.h"
#include "contract/contract_alt_bn128_G1_add.h"
#include "contract/contract_alt_bn128_G1_mul.h"
#include "contract/contract_alt_bn128_pairing_product.h"
#include "contract/contract_blake2_compression.h"

namespace tenon {

namespace contract {

ContractManager* ContractManager::Instance() {
    static ContractManager ins;
    return &ins;
}

ContractManager::ContractManager() {
    Init();
    network::Route::Instance()->RegisterMessage(
            common::kContractMessage,
            std::bind(&ContractManager::HandleMessage, this, std::placeholders::_1));
}

ContractManager::~ContractManager() {}

int ContractManager::Init() {
    auto vpn_bandwidth_ins = std::make_shared<VpnSvrBandwidth>("");
    auto vpn_payfor_ins = std::make_shared<PayforVpn>("");
    auto vpn_client_login = std::make_shared<VpnClientLogin>("");
    auto vpn_mining = std::make_shared<VpnMining>("");
    auto ecrecover = std::make_shared<Ecrecover>("");
    auto contract_sha256 = std::make_shared<ContractSha256>("");
    auto contract_rip160 = std::make_shared<Ripemd160>("");
    auto contract_identity = std::make_shared<Identity>("");
    auto modexp = std::make_shared<Modexp>("");
    auto alt_add = std::make_shared<ContractAltBn128G1Add>("");
    auto alt_mul = std::make_shared<ContractAltBn128G1Mul>("");
    auto alt_product = std::make_shared<ContractaltBn128PairingProduct>("");
    auto blake2 = std::make_shared<Blake2Compression>("");
    {
        std::lock_guard<std::mutex> guard(contract_map_mutex_); 
        contract_map_[kContractVpnPayfor] = vpn_payfor_ins;
        contract_map_[kContractVpnBandwidthProveAddr] = vpn_bandwidth_ins;
        contract_map_[kVpnClientLoginManager] = vpn_client_login;
        contract_map_[kVpnMining] = vpn_mining;
        contract_map_[kContractEcrecover] = ecrecover;
        contract_map_[kContractSha256] = contract_sha256;
        contract_map_[kContractRipemd160] = contract_rip160;
        contract_map_[kContractIdentity] = contract_identity;
        contract_map_[kContractModexp] = modexp;
        contract_map_[kContractAlt_bn128_G1_add] = alt_add;
        contract_map_[kContractAlt_bn128_G1_mul] = alt_mul;
        contract_map_[kContractAlt_bn128_pairing_product] = alt_product;
        contract_map_[kContractBlake2_compression] = blake2;
    }

    return kContractSuccess;
}

void ContractManager::HandleMessage(const transport::TransportMessagePtr& header_ptr) {
    auto& header = *header_ptr;
    if (header.type() != common::kContractMessage) {
        return;
    }

    protobuf::ContractMessage contract_msg;
    if (!contract_msg.ParseFromString(header.data())) {
        return;
    }

    if (contract_msg.has_get_attr_req()) {
        return;
    }

    network::Route::Instance()->Send(header);
}

int ContractManager::call(
        const CallParameters& param,
        uint64_t gas,
        const std::string& origin_address,
        evmc_result* res) {
    ContractInterfacePtr contract_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(contract_map_mutex_);
        auto iter = contract_map_.find(param.code_address);
        if (iter != contract_map_.end()) {
            contract_ptr = iter->second;
        }
    }

    if (contract_ptr != nullptr) {
        return contract_ptr->call(param, gas, origin_address, res);
    }

    return kContractNotExists;
}

}  // namespace contract

}  // namespace tenon
