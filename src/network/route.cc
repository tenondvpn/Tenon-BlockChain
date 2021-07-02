#include "stdafx.h"
#include "network/route.h"

#include "transport/processor.h"
#include "dht/dht_key.h"
#include "broadcast/filter_broadcast.h"
#include "network/universal.h"
#include "network/dht_manager.h"
#include "network/universal_manager.h"
#include "network/network_utils.h"

namespace tenon {

namespace network {

Route* Route::Instance() {
    static Route ins;
    return &ins;
}

void Route::Init() {
    RegisterMessage(
            common::kDhtMessage,
            std::bind(&Route::HandleDhtMessage, this, std::placeholders::_1));
    RegisterMessage(
            common::kNatMessage,
            std::bind(&Route::HandleDhtMessage, this, std::placeholders::_1));
    RegisterMessage(
            common::kNetworkMessage,
            std::bind(&Route::HandleDhtMessage, this, std::placeholders::_1));
    RegisterMessage(
            common::kRelayMessage,
            std::bind(&Route::RouteByUniversal, this, std::placeholders::_1));
    broadcast_ = std::make_shared<broadcast::FilterBroadcast>();
}

void Route::Destroy() {
    UnRegisterMessage(common::kDhtMessage);
    UnRegisterMessage(common::kNatMessage);
    UnRegisterMessage(common::kNetworkMessage);
    broadcast_.reset();
}

int Route::SendToLocal(transport::protobuf::Header& message) {
    uint32_t des_net_id = dht::DhtKeyManager::DhtKeyGetNetId(message.des_dht_key());
    dht::BaseDhtPtr dht_ptr{ nullptr };
    if (message.universal()) {
        dht_ptr = UniversalManager::Instance()->GetUniversal(des_net_id);
    } else {
        dht_ptr = DhtManager::Instance()->GetDht(des_net_id);
    }

    if (!dht_ptr) {
        NETWORK_ERROR("get dht failed[%d]", des_net_id);
        return kNetworkError;
    }

    dht_ptr->transport()->SendToLocal(message);
    return kNetworkSuccess;
}

int Route::Send(transport::protobuf::Header& message) {
    uint32_t des_net_id = dht::DhtKeyManager::DhtKeyGetNetId(message.des_dht_key());
    dht::BaseDhtPtr dht_ptr{ nullptr };
    if (message.universal() ||
            des_net_id == network::kUniversalNetworkId ||
            des_net_id == network::kNodeNetworkId) {
        dht_ptr = UniversalManager::Instance()->GetUniversal(des_net_id);
    } else {
        dht_ptr = DhtManager::Instance()->GetDht(des_net_id);
    }

    if (message.version() == 14 || message.version() == 15)
        std::cout << "ddddddddd 0" << std::endl;

    if (dht_ptr != nullptr) {
        if (message.has_broadcast()) {
            if (message.version() == 14 || message.version() == 15)
                std::cout << "ddddddddd 1" << std::endl;

            broadcast_->Broadcasting(dht_ptr, message);
        } else {
            if (message.has_to_ip() && message.has_to_port()) {
                if (message.transport_type() == transport::kTcp) {
                    transport::MultiThreadHandler::Instance()->transport()->Send(
                            message.to_ip(), message.to_port(), 0, message);
                } else {
                    dht_ptr->transport()->Send(message.to_ip(), message.to_port(), 0, message);
                }
            } else {
                dht_ptr->SendToClosestNode(message);
            }
        }
        return kNetworkSuccess;
    }
    // this node not in this network, relay by universal
    RouteByUniversal(message);
    return kNetworkSuccess;
}

void Route::HandleMessage(transport::protobuf::Header& header) {
    if (header.type() >= common::kLegoMaxMessageTypeCount) {
        return;
    }

    if (message_processor_[header.type()] == nullptr) {
        RouteByUniversal(header);
        return;
    }

    if (header.version() == 14 || header.version() == 15) {
        std::cout << "receive message broadcast data 4" << std::endl;
    }
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            kUniversalNetworkId);
    if (!uni_dht) {
        NETWORK_ERROR("get uni dht failed!");
        return;
    }

    if (header.version() == 14 || header.version() == 15) {
        std::cout << "receive message broadcast data 5" << std::endl;
    }

    if (uni_dht->local_node()->client_mode || uni_dht->local_node()->dht_key() == header.des_dht_key()) {
        message_processor_[header.type()](header);
        return;
    }

    if (header.version() == 14 || header.version() == 15) {
        std::cout << "receive message broadcast data 6" << std::endl;
    }

    // every route message must use dht
    auto dht = GetDht(header.des_dht_key(), header.universal());
    uint32_t net_id = dht::DhtKeyManager::DhtKeyGetNetId(header.des_dht_key());
    if (header.version() == 14 || header.version() == 15) {
        std::cout << "receive message broadcast data 6 1: " << header.universal() << ", net_id: " << net_id << std::endl;
    }

    if (!dht) {
        if (header.version() == 14 || header.version() == 15) {
            std::cout << "receive message broadcast data 6 2: " << header.universal() << std::endl;
        }

        RouteByUniversal(header);
        return;
    }

    if (!header.handled()) {
        message_processor_[header.type()](header);
    }
    if (header.version() == 14 || header.version() == 15) {
        std::cout << "receive message broadcast data 7" << std::endl;
    }

    if (header.has_broadcast()) {
        Broadcast(header);
    }
}

void Route::HandleDhtMessage(transport::protobuf::Header& header) {
    auto dht = GetDht(header.des_dht_key(), header.universal());
    if (!dht) {
        return;
    }

    if (!dht) {
        NETWORK_ERROR("get dht failed!");
        return;
    }

    dht->HandleMessage(header);
}

void Route::RegisterMessage(uint32_t type, transport::MessageProcessor proc) {
    if (type >= common::kLegoMaxMessageTypeCount) {
        return;
    }

    if (message_processor_[type] != nullptr) {
        NETWORK_ERROR("message handler exist.[%d]", type);
    }

    message_processor_[type] = proc;
    transport::Processor::Instance()->RegisterProcessor(
            type,
            std::bind(&Route::HandleMessage, this, std::placeholders::_1));
}

void Route::UnRegisterMessage(uint32_t type) {
    if (type >= common::kLegoMaxMessageTypeCount) {
        return;
    }

    message_processor_[type] = nullptr;
}

Route::Route() {
    Init();
}

Route::~Route() {
    Destroy();
}

void Route::Broadcast(transport::protobuf::Header& header) {
    if (!header.has_broadcast() || !header.has_des_dht_key()) {
        return;
    }

    uint32_t des_net_id = dht::DhtKeyManager::DhtKeyGetNetId(header.des_dht_key());
    auto des_dht = GetDht(header.des_dht_key(), header.universal());
    if (!des_dht) {
        return;
    }

    uint32_t src_net_id = kNetworkMaxDhtCount;
    if (header.has_src_dht_key()) {
        src_net_id = dht::DhtKeyManager::DhtKeyGetNetId(header.src_dht_key());
    }

    auto broad_param = header.mutable_broadcast();
    if (src_net_id != des_net_id) {
        if (!broad_param->net_crossed()) {
            broad_param->set_net_crossed(true);
            broad_param->clear_bloomfilter();
            header.set_hop_count(0);
        }
    }
    broadcast_->Broadcasting(des_dht, header);
}

dht::BaseDhtPtr Route::GetDht(const std::string& dht_key, bool universal) {
    uint32_t net_id = dht::DhtKeyManager::DhtKeyGetNetId(dht_key);
    dht::BaseDhtPtr dht = nullptr;
    if (universal) {
        dht = UniversalManager::Instance()->GetUniversal(net_id);
    } else {
        dht = DhtManager::Instance()->GetDht(net_id);
    }

    return dht;
}

void Route::RouteByUniversal(transport::protobuf::Header& header) {
    auto universal_dht = UniversalManager::Instance()->GetUniversal(kUniversalNetworkId);
    if (!universal_dht) {
        return;
    }

    universal_dht->SendToClosestNode(header);
}

}  // namespace network

}  // namespace tenon
