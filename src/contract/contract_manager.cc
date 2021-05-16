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

namespace lego {

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
    {
        std::lock_guard<std::mutex> guard(contract_map_mutex_); 
        contract_map_[kContractVpnPayfor] = vpn_payfor_ins;
        contract_map_[kContractVpnBandwidthProveAddr] = vpn_bandwidth_ins;
        contract_map_[kVpnClientLoginManager] = vpn_client_login;
        contract_map_[kVpnMining] = vpn_mining;
        contract_map_[kContractEcrecover] = ecrecover;
    }
    return kContractSuccess;
}

void ContractManager::HandleMessage(transport::protobuf::Header& header) {
    if (header.type() != common::kContractMessage) {
        return;
    }

    protobuf::ContractMessage contract_msg;
    if (!contract_msg.ParseFromString(header.data())) {
        return;
    }

    if (contract_msg.has_get_attr_req()) {
        HandleGetContractAttrRequest(header, contract_msg);
        return;
    }

    network::Route::Instance()->Send(header);
}

// void ContractManager::HandleGetContractAttrRequest(
//         transport::protobuf::Header& header,
//         protobuf::ContractMessage& contract_msg) {
//     std::string attr_value;
//     if (GetAttrWithKey(
//             contract_msg.get_attr_req().call_addr(),
//             contract_msg.get_attr_req().attr_key(),
//             attr_value) != kContractSuccess) {
//         return;
//     }
// 
//     protobuf::ContractMessage contract_msg_res;
//     auto attr_res = contract_msg_res.mutable_get_attr_res();
//     attr_res->set_call_addr(contract_msg.get_attr_req().call_addr());
//     attr_res->set_attr_key(contract_msg.get_attr_req().attr_key());
//     attr_res->set_attr_value(attr_value);
// 
//     auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
//         network::kUniversalNetworkId);
//     assert(dht_ptr != nullptr);
//     transport::protobuf::Header msg;
//     contract::ContractProto::CreateGetAttrResponse(
//             dht_ptr->local_node(),
//             header,
//             contract_msg_res.SerializeAsString(),
//             msg);
//     network::Route::Instance()->Send(msg);
// //     CONTRACT_ERROR("received contract message request and sent response.[%s]: [%s]",
// //             contract_msg.get_attr_req().attr_key().c_str(), attr_value.c_str());
// }
// 
// int ContractManager::InitWithAttr(
//         const bft::protobuf::Block& block_item,
//         const bft::protobuf::TxInfo& tx_info,
//         db::DbWriteBach& db_batch) {
//     ContractInterfacePtr contract_ptr = nullptr;
//     {
//         std::lock_guard<std::mutex> guard(contract_map_mutex_);
//         auto iter = contract_map_.find(tx_info.call_addr());
//         if (iter != contract_map_.end()) {
//             contract_ptr = iter->second;
//         }
//     }
// 
//     if (contract_ptr != nullptr) {
//         return contract_ptr->InitWithAttr(block_item, tx_info, db_batch);
//     }
//     return kContractError;
// }
// 
// int ContractManager::GetAttrWithKey(
//         const std::string& call_addr,
//         const std::string& key,
//         std::string& value) {
//     ContractInterfacePtr contract_ptr = nullptr;
//     {
//         std::lock_guard<std::mutex> guard(contract_map_mutex_);
//         auto iter = contract_map_.find(call_addr);
//         if (iter != contract_map_.end()) {
//             contract_ptr = iter->second;
//         }
//     }
// 
//     if (contract_ptr != nullptr) {
//         return contract_ptr->GetAttrWithKey(key, value);
//     }
//     return kContractError;
// }
// 
// int ContractManager::Execute(bft::TxItemPtr& tx_item) {
//     ContractInterfacePtr contract_ptr = nullptr;
//     {
//         std::lock_guard<std::mutex> guard(contract_map_mutex_);
//         auto iter = contract_map_.find(tx_item->call_addr);
//         if (iter != contract_map_.end()) {
//             contract_ptr = iter->second;
//         }
//     }
// 
//     if (contract_ptr != nullptr) {
//         return contract_ptr->Execute(tx_item);
//     }
//     return kContractError;
// }

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

}  // namespace lego
