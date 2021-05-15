#include "stdafx.h"
#include "transport/client_relay.h"

#include <functional>

namespace lego {

namespace transport {

ClientRelay::ClientRelay() {
//     tick_.CutOff(
//             kCheckClientTimeoutPeriod,
//             std::bind(&ClientRelay::CheckTimeoutClient, this));
}

ClientRelay::~ClientRelay() {}

ClientRelay* ClientRelay::Instance() {
    static ClientRelay ins;
    return &ins;
}

void ClientRelay::AddClient(
        const std::string& dht_key,
        const std::string& ip,
        uint16_t port,
        int32_t trans_type) {
    auto client_node = std::make_shared<ClientNode>(dht_key, ip, port, trans_type);
    std::string key = ip + "_" + std::to_string(port);
    std::lock_guard<std::mutex> guard(client_node_map_mutex_);
    client_node_map_[key] = client_node;  // just cover
}

ClientNodePtr ClientRelay::GetClient(const std::string& key) {
    std::lock_guard<std::mutex> guard(client_node_map_mutex_);
    auto iter = client_node_map_.find(key);
    if (iter != client_node_map_.end()) {
        auto item_ptr = iter->second;
        return item_ptr;
    }
    return nullptr;
}

void ClientRelay::CheckTimeoutClient() {
    {
        auto now_tm = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> guard(client_node_map_mutex_);
        for (auto iter = client_node_map_.begin(); iter != client_node_map_.end();) {
            if (iter->second->timeout <= now_tm) {
                client_node_map_.erase(iter++);
            } else {
                ++iter;
            }
        }
    }
    tick_.CutOff(
            kCheckClientTimeoutPeriod,
            std::bind(&ClientRelay::CheckTimeoutClient, this));
}

}  // namespace transport

}  // namespace transport