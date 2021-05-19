#pragma once

#include <unordered_map>

#include "common/tick.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace transport {


struct ClientNode {
    ClientNode(const std::string& dht_key, const std::string& in_ip, uint16_t in_port, int32_t trans_type)
            : client_dht_key(dht_key), ip(in_ip), port(in_port), transport_type(trans_type) {
        static const uint32_t kClientTimeout = 30u * 1000u * 1000u;
        timeout = (std::chrono::steady_clock::now() +
                std::chrono::microseconds(kClientTimeout));
    }
    std::string client_dht_key;
    std::string ip;
    uint16_t port;
    int32_t transport_type;
    std::chrono::steady_clock::time_point timeout;
};

typedef std::shared_ptr<ClientNode> ClientNodePtr;

class ClientRelay {
public:
    static ClientRelay* Instance();
    void AddClient(
            const std::string& dht_key,
            const std::string& ip,
            uint16_t port,
            int32_t transport_type);
    ClientNodePtr GetClient(const std::string& key);

private:
    ClientRelay();
    ~ClientRelay();
    void CheckTimeoutClient();

    static const uint32_t kCheckClientTimeoutPeriod = 3u * 1000u * 1000u;

    std::unordered_map<std::string, ClientNodePtr> client_node_map_;
    std::mutex client_node_map_mutex_;
    common::Tick tick_;

    DISALLOW_COPY_AND_ASSIGN(ClientRelay);
};

}  // namespace transport

}  // namespace transport
